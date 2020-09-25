using APIServer.Authorization;
using APIServer.Identity;
using APIServer.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace APIServer.Services
{
    public interface IAccountService
    {
        public void AddNewNWEmployee(RegisterModel model);
        public Task<AppUser> FindByNameAsync(string userName);
        public int FindEmployeeId(string firstName, string lastName);
        public AppUser AddIdeUser(RegisterModel model);
        public Task<IdentityResult>CreateAsync(AppUser user, string password);
        public Task<IdentityResult> AddUserToRoleEmployee(AppUser user);
        public Task<IdentityResult> AddUserToRoleVD(AppUser user);
        public Task<IdentityResult> AddUserToRoleAdmin(AppUser user);
        public Task<bool> CheckPasswordAsync(AppUser user, string password);
        public Task<IList<string>> GetRolesAsync(AppUser user);
        public Task<Employees> DeleteEmployees(int id);
        public Task<CustomUser> FindUserById(int id);
        public Task<ActionResult<IEnumerable<AppUser>>> GetEmployees();

        public Task<IdentityResult> UpdateUserTokens(AppUser user);
        public Task<SecurityToken> CreateJWTToken(AppUser user);
        public RefreshTokens CreateRefToken(AppUser user);
        public string GenerateRefreshTokenNum();
        public Task<JwtTokens> GetJWTToken(AppUser user);
        public Task<RefreshTokens> GetRefreshToken(AppUser user);

        public AppUser GetUserFromToken(string token);

        public Task<AuthenticateResponse> RefreshToken(RefreshTokenRequest refTokenString);

        public bool CheckJwtTokenExpired(JwtTokens jwtToken);
        public bool CheckRefreshTokenExpired(RefreshTokens refreshToken);
        //public Task<bool> ClearJWT(AppUser user);
        //public Task<bool> ClearRefresh(AppUser user);
    }

    public class AccountService : IAccountService
    {
        private readonly NorthwindContext _nwContext;
        private readonly IConfiguration _configuration;
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        public AccountService(NorthwindContext nwContext, UserManager<AppUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration)
        {
            _nwContext = nwContext;
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }
        //register new Employee in Northwind
        public void AddNewNWEmployee(RegisterModel model)
        {
            Employees employee = new Employees()
            {
                FirstName = model.FirstName,
                LastName = model.LastName,
            };
            _nwContext.Employees.Add(employee);
            _nwContext.SaveChanges();
        }

        public AppUser AddIdeUser(RegisterModel model)
        {
            AppUser appUser=new AppUser()
            {
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.UserName,
                EmployeeId = model.EmployeeID
            };
            return appUser;
        }

        public async Task<AppUser> FindByNameAsync(string userName)
        {
            var user = await _userManager.FindByNameAsync(userName);
            return user;
        }

        public int FindEmployeeId(string firstName, string lastName)
        {
            int nwId=_nwContext.Employees.Where(e => e.FirstName == firstName && e.LastName == lastName).Select(e => e.EmployeeId).First();
            return nwId;
        }

        public async Task<IdentityResult> CreateAsync(AppUser user, string password)
        {
            var result = await _userManager.CreateAsync(user, password);
            return result;
        }

        public async Task<IdentityResult> AddUserToRoleEmployee(AppUser user)
        {
               return await _userManager.AddToRoleAsync(user, UserRoles.Employee);
        }

        public async Task<IdentityResult> AddUserToRoleVD(AppUser user)
        {
            List<string> rolesList = new List<string>();
            rolesList.Add(UserRoles.VD);
            rolesList.Add(UserRoles.Employee);

            return await _userManager.AddToRolesAsync(user, rolesList);
        }

        public async Task<IdentityResult> AddUserToRoleAdmin(AppUser user)
        {
            List<string> rolesList = new List<string>();
            rolesList.Add(UserRoles.Admin);
            rolesList.Add(UserRoles.Employee);

            bool admin = await _roleManager.RoleExistsAsync(UserRoles.Admin);
            bool VD = await _roleManager.RoleExistsAsync(UserRoles.VD);
            bool employee = await _roleManager.RoleExistsAsync(UserRoles.Employee);

            if (!admin||!VD||!employee)
            {
                if (!await _roleManager.RoleExistsAsync(UserRoles.Admin))
                    await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));
                if (!await _roleManager.RoleExistsAsync(UserRoles.VD))
                    await _roleManager.CreateAsync(new IdentityRole(UserRoles.VD));
                if (!await _roleManager.RoleExistsAsync(UserRoles.Employee))
                    await _roleManager.CreateAsync(new IdentityRole(UserRoles.Employee));
            }
            return await _userManager.AddToRolesAsync(user, rolesList);
        }

        public async Task<bool> CheckPasswordAsync(AppUser user, string password)
        {
            return await _userManager.CheckPasswordAsync(user, password);
        }

        public async Task<IList<string>> GetRolesAsync(AppUser user)
        {
            return await _userManager.GetRolesAsync(user);
        }

        public async Task<SecurityToken> CreateJWTToken(AppUser user)
        {
            var userRoles = await _userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, user.UserName),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    };

            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetSection("Jwt:SecretKey").Value));//["JWT:Secret"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:Issuer"],
                audience: _configuration["JWT:Audience"],
                expires: DateTime.Now.AddMinutes(5),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            /*
            user.JToken.EmployeeId = user.EmployeeId;
            user.JToken.Token = token.ToString();
            user.JToken.ExpirationDate = token.ValidTo;
            */
            return token;
        }

        public RefreshTokens CreateRefToken(AppUser user)
        {
            RefreshTokens newRefreshToken = new RefreshTokens();
          //  newRefreshToken.EmployeeId = user.EmployeeId;
            newRefreshToken.Expires = DateTime.Now.AddMinutes(15);
            newRefreshToken.Token = GenerateRefreshTokenNum();
            return newRefreshToken;
        }

        public async Task<Employees> DeleteEmployees(int id)
        {
            AppUser deleteMe = _userManager.Users.Where(u => u.EmployeeId == id).First();
            var result = await _userManager.DeleteAsync(deleteMe);
            var employees = await _nwContext.Employees.FindAsync(id);
            if (employees == null)
            {
                return null;
            }
            _nwContext.Employees.Remove(employees);
            await _nwContext.SaveChangesAsync();
            return employees;
        }

        public async Task<CustomUser> FindUserById(int id)
        {
            Employees employee = await _nwContext.Employees.FindAsync(id);
            var appUser = _userManager.Users.Where(u => u.EmployeeId == id).FirstOrDefault();
            _userManager.Users.Where(u => u.EmployeeId == id).FirstOrDefault();
            if (employee == null || appUser == null)
            {
                return null;
            }
            CustomUser customUser = new CustomUser();
            customUser.EmployeeId = appUser.EmployeeId;
            customUser.Username = appUser.UserName;

            return customUser;
        }

        public async Task<ActionResult<IEnumerable<AppUser>>> GetEmployees()
        {
            return await _userManager.Users.ToListAsync();
        }



        public string GenerateRefreshTokenNum()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

        public async Task<JwtTokens> GetJWTToken(AppUser user)
        {
            JwtTokens jtoken = await _userManager.Users.Select(u => u.JToken).Where(t=>t.appUser.Id== user.Id).FirstOrDefaultAsync();
            if (jtoken == null)
            {
                jtoken = new JwtTokens();
            }
            return jtoken;
        }

        public async Task<RefreshTokens> GetRefreshToken(AppUser user)
        {
            RefreshTokens refToken = await _userManager.Users.Select(u => u.RefreshToken).Where(t => t.appUser.Id == user.Id).FirstOrDefaultAsync();
            if (refToken == null)
            {
                refToken = new RefreshTokens();
            }
            return refToken;
        }

        public bool CheckJwtTokenExpired(JwtTokens jwtToken)
        {
            bool expired = false;
            DateTime currentTime = DateTime.Now;
            if (jwtToken.ExpirationDate.CompareTo(currentTime) <= 0)
            {
                expired = true;
            }
            return expired;
        }

       public bool CheckRefreshTokenExpired(RefreshTokens refreshToken)
        {
            bool expired = false;
            DateTime currentTime = DateTime.Now;
            if(refreshToken.Expires.CompareTo(currentTime)<=0)
            {
                expired= true;
            }
            return expired;
        }

        public async Task<IdentityResult> UpdateUserTokens(AppUser user)
        {
            return await _userManager.UpdateAsync(user);
        }

        public async Task<AuthenticateResponse> RefreshToken(RefreshTokenRequest refTokenString)
        {
            var user =  GetUserFromToken(refTokenString.RefreshToken);

            RefreshTokens refreshToken = new RefreshTokens();
            refreshToken = CreateRefToken(user);
            RefreshTokens usersRefToken = await GetRefreshToken(user);
            user.RefreshToken = new RefreshTokens();
            user.RefreshToken.Token = refreshToken.Token;
            user.RefreshToken.Expires = refreshToken.Expires;

            SecurityToken token = await CreateJWTToken(user);
            JwtTokens newToken = new JwtTokens();
            JwtTokens usersJwt = await GetJWTToken(user);

            //RefreshTokens usersRefresh = await GetRefreshToken(user);
            user.JToken = new JwtTokens();
            user.JToken.Token = token.ToString();
            user.JToken.ExpirationDate = token.ValidTo;

            var res = await UpdateUserTokens(user);
            AuthenticateResponse response = new AuthenticateResponse();
            response.RefExpires = DateTime.Now;
            response.UserName = user.UserName;
            response.JwtToken = token;
            response.RefreshToken = refreshToken.Token;
 
            return response;
        }

        public AppUser GetUserFromToken(string token)
        {
            var account = _userManager.Users.Where(u => u.RefreshToken.Token.Equals(token)).FirstOrDefault();
            return account;
        }
        /*
public async Task<bool> ClearRefresh(AppUser user)
{
RefreshTokens refToken = await _userManager.Users.Select(u => u.RefreshToken).Where(t => t.EmployeeId == user.EmployeeId).FirstAsync();
if(user.RefreshToken == null)
{
return true;
}
user.RefreshToken = null;
var res = await _userManager.UpdateAsync(user);
return true;

}*/
    }
}
