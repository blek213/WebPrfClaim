using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WebPrfClaim.Models
{
    public class User : IdentityUser
    {
        public int TempCheckVal { get; set; }
        public int Year { get; set; }
    }
}
