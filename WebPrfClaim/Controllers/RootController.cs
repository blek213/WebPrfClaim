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

        [HttpGet]
        public async Task<HttpResponseMessage> LoginUser()
        {
            return new HttpResponseMessage(HttpStatusCode.Accepted);
        }

        [Route("LoginUser")]
        [HttpPost]
        public async Task<JsonResult> LoginUser(string email, string password)
        {
            var result = GetIdentityLogin(email, password);


            return Json(HttpStatusCode.Accepted);
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

            IdentityUser user = identityUsers.FirstOrDefault(p => p.UserName == name);

            var checkPassword = _userManager.CheckPasswordAsync(user, password);

            if (user != null && checkPassword.Result == true)
            {

                var claims = new List<Claim>
                {
                    new Claim(ClaimsIdentity.DefaultIssuer,user.SecurityStamp),
                };

                ClaimsIdentity claimsIdentity = new ClaimsIdentity(claims, "Token", ClaimsIdentity.DefaultIssuer, ClaimsIdentity.DefaultRoleClaimType);

                return claimsIdentity;
            }

            return null;

        }

        private ClaimsIdentity GenerateClaimsIdentity(string id)
        {
            var identity = _userManager.FindByIdAsync(id);

            var claims = new List<Claim>
                {
                    new Claim(ClaimsIdentity.DefaultIssuer,identity.Result.SecurityStamp),
                };

            ClaimsIdentity claimsIdentity = new ClaimsIdentity(claims, "Token", ClaimsIdentity.DefaultIssuer, ClaimsIdentity.DefaultRoleClaimType);

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