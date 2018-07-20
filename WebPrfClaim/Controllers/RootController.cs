using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using WebPrfClaim.Jwt;
using WebPrfClaim.Models;

namespace WebPrfClaim.Controllers
{

    [Route("api/[controller]")]
    public class RootController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<IdentityUser> _signInManager;

        public RootController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
        }

        [Route("GetClaimValue")]
        [HttpGet]
        public IActionResult GetClaimValue()
        {
            //ClaimsIdentity claimsIdentity = User.Identity as ClaimsIdentity;

            //var claims = claimsIdentity.Claims.Select(x => new { type = x.Type, value = x.Value });

            //return Ok(claims);

            return Json(User.Claims.FirstOrDefault(c=>c.ValueType == "SecurityStamp"));
        }

        [Route("GetClaimValue2")]
        [HttpGet]
        public IActionResult GetClaimValue2()
        {
            var identity = (ClaimsIdentity)User.Identity;
            IEnumerable<Claim> claims = identity.Claims;

            return Json(claims);
        }

        [Route("GetClaimValue3")]
        public IActionResult GetClaimValue3()
        {
            return Json(User.Claims.Select(c => new { type = c.Type, value = c.Value }).ToList());       
        }

        [Route("GetClaimValue4")]
        public IActionResult GetClaimValue4()
        {
            var ourToken = Request.HttpContext.Request.Headers["access_token"];

            return Json(ourToken);
        }

        [Route("ChangeUserRole")]
        public async Task<JsonResult> ChangeUserRole(string UserId,string newRole)
        {
            List<IdentityUser> identityUsers = _userManager.Users.ToList();

            IdentityUser user = identityUsers.FirstOrDefault(p => p.Id == UserId);

            List<IdentityRole> identityRoles = _roleManager.Roles.ToList();

            IdentityRole identityRole = identityRoles.FirstOrDefault(p => p.Name == newRole);

            if(identityRole == null)
            {
                var roleUser = new IdentityRole { Name = newRole};

                await _roleManager.CreateAsync(roleUser);
            }

            await _userManager.AddToRoleAsync(user, newRole);

            await _userManager.UpdateSecurityStampAsync(user);

            return Json(HttpStatusCode.Accepted);
        }

        [Route("LoginUser")]
        [HttpPost]
        public async Task<JsonResult> LoginUser(string email, string password)
        {
            var identity = GetIdentityLogin(email, password);

            if (identity != null)
            {
                var now = DateTime.UtcNow;

                var jwt = new JwtSecurityToken(
                        issuer: AuthOptions.ISSUER,
                        audience: AuthOptions.AUDIENCE,
                        notBefore: now,
                        claims: identity.Claims,
                        expires: now.Add(TimeSpan.FromHours(AuthOptions.LIFETIME)),
                        signingCredentials: new SigningCredentials(AuthOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));
                var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

                var response = new
                {
                    access_token = encodedJwt,
                    username = identity.Name
                };

                return Json(new { JsonResponseRes = response, JsonHttpStatusCode = HttpStatusCode.Accepted });
            }

            return Json(HttpStatusCode.BadRequest);
        }

        [Route("RegisterUser")]
        [HttpPost]
        public async Task<JsonResult> RegisterUser(string email, string password)
        {       
                User user = new User { Email = email, UserName = email, Year=2012  };

                var roleUser = new IdentityRole { Name = "User" };

                await _roleManager.CreateAsync(roleUser);
 
                // добавляем пользователя
                var result = await _userManager.CreateAsync(user, password);

                if (result.Succeeded)
                {
                     await _userManager.AddToRoleAsync(user, roleUser.Name);

                        var now = DateTime.UtcNow;

                        var identityClaims = GenerateClaimsIdentity(user.Id);

                        var jwt = new JwtSecurityToken(
                           issuer: AuthOptions.ISSUER,
                           audience: AuthOptions.AUDIENCE,
                           notBefore: now,
                           claims: identityClaims.Claims,
                           expires: now.Add(TimeSpan.FromMinutes(AuthOptions.LIFETIME)),
                           signingCredentials: new SigningCredentials(AuthOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));
                        var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

                        return Json(HttpStatusCode.Accepted);
                    }
                       
            return Json(HttpStatusCode.BadRequest);
        }

        private  ClaimsIdentity GetIdentityLogin(string name, string password)
        {
            List<IdentityUser> identityUsers = _userManager.Users.ToList();

            IdentityUser IdentityUser = identityUsers.FirstOrDefault(p => p.UserName == name);
          
            var checkPassword = _userManager.CheckPasswordAsync(IdentityUser, password);

            if (IdentityUser != null && checkPassword.Result == true)
            {

                var claims = new List<Claim>
                {
                    new Claim("SecurityStamp",IdentityUser.SecurityStamp),
                    new Claim("UserRole","User")
                };

                ClaimsIdentity claimsIdentity = new ClaimsIdentity(claims, "Token", "SecurityStamp", "UserRole");

                return claimsIdentity;
            }

            return null;

        }

        private ClaimsIdentity GenerateClaimsIdentity(string id)
        {
            var identity = _userManager.FindByIdAsync(id);

            var claims = new List<Claim>
                {
                    new Claim("SecurityStamp",identity.Result.SecurityStamp),
                    new Claim("UserRole","User")
                };

            ClaimsIdentity claimsIdentity = new ClaimsIdentity(claims, "Token", "SecurityStamp", "UserRole");

            return claimsIdentity;
        }

        private string GetIdentityRegister(string username, string password)
        {
            List<IdentityUser> identityUsers = _userManager.Users.ToList();

            IdentityUser user = identityUsers.FirstOrDefault(p => p.UserName == username);

            if (user != null)
            {
                return "The user exist";
            }

            return null;
        }

        public async Task<HttpResponseMessage> ChangeRoleUser()
        {
            return new HttpResponseMessage(HttpStatusCode.Accepted);
        }

    }
}