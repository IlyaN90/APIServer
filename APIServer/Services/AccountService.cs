using APIServer.Authorization;
using APIServer.Identity;
using APIServer.Models;
using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
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
        public void AddUserToRoleEmployee(AppUser user);
        public void AddUserToRoleVD(AppUser user);
        public void AddUserToRoleAdmin(AppUser user);
        public Task<bool> CheckPasswordAsync(AppUser user, string password);
        public void CreateRoles();
        public Task<IList<string>> GetRolesAsync(AppUser user);
        public Task<JwtSecurityToken> CreateTokens(AppUser user);
    }

    public class AccountService : IAccountService
    {
        private readonly NorthwindContext _nwContext;
        private readonly IConfiguration _configuration;
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        public AccountService(NorthwindContext nwContext, UserManager<AppUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IMapper mapper,
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

        public async void AddUserToRoleEmployee(AppUser user)
        {
            if (await _roleManager.RoleExistsAsync(UserRoles.Employee))
            {
                await _userManager.AddToRoleAsync(user, UserRoles.Employee);
            }
        }

        public async void AddUserToRoleVD(AppUser user)
        {
            if (await _roleManager.RoleExistsAsync(UserRoles.VD))
            {
                await _userManager.AddToRoleAsync(user, UserRoles.VD);
            }
        }

        public async void AddUserToRoleAdmin(AppUser user)
        {
            if (await _roleManager.RoleExistsAsync(UserRoles.Admin))
            {
                await _userManager.AddToRoleAsync(user, UserRoles.Admin);
            }
            else
            {
                CreateRoles();
                await _userManager.AddToRoleAsync(user, UserRoles.Admin);
            }
        }

        public async Task<bool> CheckPasswordAsync(AppUser user, string password)
        {
            return await _userManager.CheckPasswordAsync(user, password);
        }

        public async void CreateRoles()
        {
            if (!await _roleManager.RoleExistsAsync(UserRoles.Admin))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));
            if (!await _roleManager.RoleExistsAsync(UserRoles.VD))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.VD));
            if (!await _roleManager.RoleExistsAsync(UserRoles.Employee))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.Employee));
        }

        public async Task<IList<string>> GetRolesAsync(AppUser user)
        {
            return await _userManager.GetRolesAsync(user);
        }

        public async Task<JwtSecurityToken> CreateTokens(AppUser user)
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
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddMinutes(5),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );
            user.JwtToken = token.ToString();
            if (user.RefreshToken != null)
            {
                //https://code-maze.com/using-refresh-tokens-in-asp-net-core-authentication/#:~:text=With%20refresh%20token%2Dbased%20flow,identify%20the%20app%20using%20it.
                //user.RefreshToken = refreshToken.ToString();
            }
            // var res = await _userManager.UpdateAsync(user);

            return token;
        }
    }
}
