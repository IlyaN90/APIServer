using APIServer.Models;
using Microsoft.AspNetCore.Identity;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace APIServer.Identity
{
    public class AppUser : IdentityUser
    {
        public int EmployeeId { get; set; }
        public JwtTokens JToken { get; set; }
        public RefreshTokens RefreshToken { get; set; }
    }
}
