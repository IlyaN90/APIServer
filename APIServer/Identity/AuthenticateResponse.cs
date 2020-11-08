using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace APIServer.Identity
{
    public class AuthenticateResponse
    {
        public string UserName { get; set; }
        public SecurityToken JwtToken { get; set; }
        public string RefreshToken { get; set; }
        public DateTime RefExpiresAt { get; set; }
        public int employeeId { get; set; }
    }
}
