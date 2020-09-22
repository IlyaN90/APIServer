using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace APIServer.Models
{
    public class CustomUser
    {
        public int CustomUserId { get; set; }
        public int EmployeeId { get; set; }
        public string Username { get; set; }
        public string JWToken { get; set; }
        public string RefresherToken { get; set; }
    }
}
