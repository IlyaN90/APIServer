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
        //kollar om användaren har giltig JWT
        public Task<bool> CheckForValidJWT(AppUser User, string jwtToken);
        #region Create new accounts
        public void AddNewNWEmployee(RegisterModel model);
        public AppUser AddIdeUser(RegisterModel model);
        public Task<IdentityResult> CreateAsync(AppUser user, string password);
        #endregion
        #region Find accounts
        public Task<AppUser> FindByNameAsync(string userName);
        public Task<CustomUser> FindUserById(int id);
        public Task<Employees> FindEmployeeId(string firstName, string lastName); 
        public Task<Employees> FindEmployeeByEmployeeId(int id);
        public AppUser FindUserFromToken(string token);
        public Task<AppUser> FindUserByJWT(string jwtToken);
        #endregion
        #region Update accounts
        public Task<Employees> UpdateNVUser(Employees employee);
        public Task<IdentityResult> UpdateAppUser(AppUser appUser);
        #endregion
        #region AppUser to role
        public Task<IdentityResult> AddUserToRole(AppUser user, string role);
        #endregion
        #region Tokens
        public Task<IdentityResult> UpdateUserTokens(AppUser user);
        public Task<SecurityToken> CreateJWTToken(AppUser user);
        public RefreshTokens CreateRefToken();
        public string GenerateRefreshTokenNum();
        public Task<JwtTokens> GetJWTToken(AppUser user);
        public Task<RefreshTokens> GetRefreshToken(AppUser user);
        public Task<AuthenticateResponse> RefreshTokens(AppUser user);
        #endregion
        public Task<bool> CheckPasswordAsync(AppUser user, string password);
        public Task<Employees> DeleteEmployees(int id);
        public Task<bool> ClearUserTokens(AppUser user);
        public Task<ActionResult<IEnumerable<AppUser>>> GetEmployees();
        public Task<List<Employees>> SyncEmployees();
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
        
        #region Create new accounts
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
        //creates new Identity User object
        public AppUser AddIdeUser(RegisterModel model)
        {
            AppUser appUser=new AppUser()
            {
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.UserName,
                EmployeeId = model.EmployeeID,
                Country=model.Country
            };
            return appUser;
        }
        public async Task<IdentityResult> CreateAsync(AppUser user, string password)
        {
            var result = await _userManager.CreateAsync(user, password);
            return result;
        }
        #endregion
        public async Task<bool> CheckForValidJWT(AppUser user, string jwtToken)
        {
            if (user == null || jwtToken==null)
            {
                return false;
            }
            JwtTokens jwt = await _userManager.Users.Select(u => u.JToken).Where(t => t.appUser.Id == user.Id).FirstAsync();
            if (jwt != null && user.JToken.Token.Contains(jwtToken))
            {
                return true;
            }
            return false;
        }
        #region Find accounts
        public async Task<AppUser> FindByNameAsync(string userName)
        {
            var user = await _userManager.FindByNameAsync(userName);
            return user;
        }
        public async Task<Employees> FindEmployeeId(string firstName, string lastName)
        {
            Employees employee= await _nwContext.Employees.Where(e => e.FirstName == firstName && e.LastName == lastName).FirstOrDefaultAsync();
            return employee;
        }
        public async Task<Employees> FindEmployeeByEmployeeId(int id)
        {
            Employees employee = await _nwContext.Employees.FindAsync(id);
            return employee;
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
        public async Task<AppUser> FindUserByJWT(string jwtToken)
        {
            AppUser user = new AppUser();
            user = null;
            if (jwtToken != null)
            {
                user = await _userManager.Users.Where(t => t.JToken.Token.Contains(jwtToken)).FirstOrDefaultAsync();
                return user;
            }
            return user;
        }
        public AppUser FindUserFromToken(string token)
        {
            var account = _userManager.Users.Where(u => u.RefreshToken.Token.Equals(token)).FirstOrDefault();
            return account;
        }
        #endregion
        #region update accounts
        public async Task<Employees> UpdateNVUser(Employees employee)
        {
            Employees oldEmployee = await _nwContext.Employees.FindAsync(employee.EmployeeId);
            oldEmployee = employee;
            _nwContext.Update(oldEmployee);
            await _nwContext.SaveChangesAsync();
            return employee;
        }
        public async Task<IdentityResult> UpdateAppUser(AppUser appUser)
        {
            return await _userManager.UpdateAsync(appUser);
        }
        #endregion

        #region AppUser to role
        public async Task<IdentityResult> AddUserToRole(AppUser user, string role)
        {
            bool admin = await _roleManager.RoleExistsAsync(UserRoles.Admin);
            bool VD = await _roleManager.RoleExistsAsync(UserRoles.VD);
            bool employee = await _roleManager.RoleExistsAsync(UserRoles.Employee);
            bool countryManager = await _roleManager.RoleExistsAsync(UserRoles.CountryManager);

            if (!admin || !VD || !employee || !countryManager)
            {
                if (!await _roleManager.RoleExistsAsync(UserRoles.Admin))
                    await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));
                if (!await _roleManager.RoleExistsAsync(UserRoles.VD))
                    await _roleManager.CreateAsync(new IdentityRole(UserRoles.VD));
                if (!await _roleManager.RoleExistsAsync(UserRoles.Employee))
                    await _roleManager.CreateAsync(new IdentityRole(UserRoles.Employee));
                if (!await _roleManager.RoleExistsAsync(UserRoles.CountryManager))
                    await _roleManager.CreateAsync(new IdentityRole(UserRoles.CountryManager));
            }
            List<string> rolesList = new List<string>();
            if (role == UserRoles.Admin)
            {
                rolesList.Add(UserRoles.Admin);   
            }
            else if (role == UserRoles.CountryManager)
            {
                rolesList.Add(UserRoles.CountryManager);
            }
            else if (role == UserRoles.VD)
            {
                rolesList.Add(UserRoles.VD);
            }
            rolesList.Add(UserRoles.Employee);
            return await _userManager.AddToRolesAsync(user, rolesList);
        }
        #endregion

        #region Tokens
        public async Task<SecurityToken> CreateJWTToken(AppUser user)
        {
            var userRoles = await _userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, user.UserName),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                        new Claim("Country", user.Country),
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
            return token;
        }
        public RefreshTokens CreateRefToken()
        {
            RefreshTokens newRefreshToken = new RefreshTokens();
            newRefreshToken.Expires = DateTime.Now.AddMinutes(15);
            newRefreshToken.Token = GenerateRefreshTokenNum();
            return newRefreshToken;
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
            JwtTokens jtoken = await _userManager.Users.Select(u => u.JToken).Where(t => t.appUser.Id == user.Id).FirstOrDefaultAsync();
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
                refToken.Token = null;
            }
            return refToken;
        }
        public async Task<IdentityResult> UpdateUserTokens(AppUser user)
        {
            var res = await _userManager.UpdateAsync(user);
            return res;
        }
        public async Task<AuthenticateResponse> RefreshTokens(AppUser user)
        {
            AuthenticateResponse response = new AuthenticateResponse();
            JwtTokens usersJwt = await GetJWTToken(user);
            RefreshTokens refreshToken = new RefreshTokens();
            RefreshTokens usersRefresh = await GetRefreshToken(user);
            if (usersRefresh.Expires >= DateTime.Now)
            {
                refreshToken = CreateRefToken();
                user.RefreshToken = new RefreshTokens();
                user.RefreshToken.Token = refreshToken.Token;
                user.RefreshToken.Expires = refreshToken.Expires;

                SecurityToken token = await CreateJWTToken(user);
                user.JToken = new JwtTokens();
                user.JToken.Token = token.ToString();
                user.JToken.ExpirationDate = token.ValidTo;
                response.RefExpiresAt = DateTime.Now;
                response.UserName = user.UserName;
                response.JwtToken = token;
                response.RefreshToken = refreshToken.Token;
                response.UserName = user.UserName;
                response.employeeId = user.EmployeeId;
                return response;
            }
            else
            {
                return null;
            }
        }
        #endregion

        public async Task<bool> CheckPasswordAsync(AppUser user, string password)
        {
            return await _userManager.CheckPasswordAsync(user, password);
        }

        public async Task<Employees> DeleteEmployees(int id)
        {
            AppUser deleteMe = _userManager.Users.Where(u => u.EmployeeId == id).FirstOrDefault();
            if (deleteMe != null)
            {
                await ClearUserTokens(deleteMe);
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
            return null;
        }

        public async Task<bool> ClearUserTokens(AppUser user)
            {
            RefreshTokens refToken = await _userManager.Users.Select(u => u.RefreshToken).Where(t => t.appUser.Id == user.Id).FirstAsync();
            if(user.RefreshToken == null)
            {
                return true;
            }
            user.RefreshToken = null;
            JwtTokens jwt = await _userManager.Users.Select(u => u.JToken).Where(t => t.appUser.Id == user.Id).FirstAsync();
            if (user.JToken == null)
            {
                return true;
            }
            user.JToken = null;
            var res = await _userManager.UpdateAsync(user);
            return true;
        }

        public async Task<ActionResult<IEnumerable<AppUser>>> GetEmployees()
        {
            return await _userManager.Users.ToListAsync();
        }
        //Gets three Employees from NW
        public async Task<List<Employees>> SyncEmployees()
        {
            List<Employees> employees = new List<Employees>();
            Employees one = await _nwContext.Employees.FindAsync(4);
            Employees two = await _nwContext.Employees.FindAsync(5);
            Employees three = await _nwContext.Employees.FindAsync(6);
            employees.Add(one);
            employees.Add(two);
            employees.Add(three);
            return employees;
        }
    }
}
