using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace APIServer.Authorization
{
    public class Policies
    {
        public const string Admin = "Admin";
        public const string VD = "VD";
        public const string Employee = "Employee";

        public static AuthorizationPolicy AdminPolicy()
        {
            return new AuthorizationPolicyBuilder().RequireAuthenticatedUser().RequireRole(Admin).Build();
            //admin-roll skall kunna göra allt, 
        }
        public static AuthorizationPolicy VDPolicy()
        {
            //VD skall kunna läsa samtliga användare men inte uppdatera/radera.
            return new AuthorizationPolicyBuilder().RequireAuthenticatedUser().RequireRole(VD).Build();
        }
        public static AuthorizationPolicy EmployeePolicy()
        {
            //vanlig user skall ha employee - roll och kunna uppdatera sin egen användarpost
            return new AuthorizationPolicyBuilder().RequireAuthenticatedUser().RequireRole(Employee).Build();
        }
    }
}
