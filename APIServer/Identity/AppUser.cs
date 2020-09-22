using Microsoft.AspNetCore.Identity;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace APIServer.Identity
{
    public class AppUser : IdentityUser
    {
        public int EmployeeId { get; set; }
        public string JwtToken { get; set; }
        public string RefreshToken { get; set; }
    }
}
