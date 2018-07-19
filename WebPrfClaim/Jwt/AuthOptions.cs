using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WebPrfClaim.Jwt
{
    public class AuthOptions
    {
        public const string ISSUER = "http://localhost:54904/";
        public const string AUDIENCE = "http://localhost:54904/";
        const string KEY = "mysupersecret_secretkey!123";   // key for decryption
        public const int LIFETIME = 45;
        public static SymmetricSecurityKey GetSymmetricSecurityKey()
        {
            return new SymmetricSecurityKey(Encoding.ASCII.GetBytes(KEY));
        }

    }
}
