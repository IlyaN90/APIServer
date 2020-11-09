using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using APIServer.Models;
using APIServer.Identity;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using APIServer.Authorization;
using Microsoft.AspNetCore.Authorization;
using APIServer.Services;
using System;
using APIServer.Migrations.Northwind;

namespace APIServer.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class EmployeesController : ControllerBase
    {
        private readonly IAccountService _accountService;

        public EmployeesController(IAccountService account)
        {
            _accountService = account;
        }
       
        #region register appUsers
        [AllowAnonymous]
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register(RegisterModel model)
        {
            var userExists = await _accountService.FindByNameAsync(model.UserName);
            if (userExists != null)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User already exists!" });
            }
            //create an employee and get its EmployeeID
            _accountService.AddNewNWEmployee(model);
            Employees employee= await _accountService.FindEmployeeId(model.FirstName, model.LastName);
            model.EmployeeID = employee.EmployeeId;
            AppUser user = _accountService.AddIdeUser(model);

            var result = await _accountService.CreateAsync(user, model.Password);
            string role = model.Role;
            if (!result.Succeeded) 
            { 
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });
            }
            else if (role == "Admin")
            {
                await _accountService.AddUserToRole(user, UserRoles.Admin);
            }
            else if (role == "CountryManager")
            {
                await _accountService.AddUserToRole(user, UserRoles.CountryManager);
            }
            else if (role == "VD")
            {
                await _accountService.AddUserToRole(user, UserRoles.VD);
            }
            else if (role == "Employee")
            {
                await _accountService.AddUserToRole(user, UserRoles.Employee);
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Please provide an accepted role with the user!" });
            }
            return Ok(new
            {
                Status = "Success",
                Message = "User created successfully!",
                employeeId = user.EmployeeId,
                role=model.Role
            }); 
        }

        #endregion
        [HttpPost("refresh-token")]
        public async Task<ActionResult<AuthenticateResponse>> RefreshToken(RefreshTokenRequest refreshToken)
        {
            string refTokenString = refreshToken.RefreshToken;
            if (refreshToken != null)
            {
                AppUser user = _accountService.FindUserFromToken(refreshToken.RefreshToken);
                if (user != null)
                {
                    var response = await _accountService.RefreshTokens(user);
                    if (response == null)
                    {
                        return Unauthorized();
                    }
                    var res = await _accountService.UpdateUserTokens(user);
                    return Ok(new
                    {
                        UserName = response.UserName,
                        JwtToken = new JwtSecurityTokenHandler().WriteToken(response.JwtToken),
                        JwtExpiresAt = response.JwtToken.ValidTo,
                        RefreshToken = response.RefreshToken,
                        RefExpiresAt = response.RefExpiresAt,
                        Country = "",
                        EmployeeId = ""
                    });
                }
            }
            return StatusCode(StatusCodes.Status401Unauthorized, new Response { Status = "Error", Message = "Ogiltig token" }); 
        }
        
        [AllowAnonymous]
        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login(LoginModel model)
        {
            AppUser user = await _accountService.FindByNameAsync(model.UserName);
            if (await _accountService.CheckPasswordAsync(user, model.Password))
            {
                SecurityToken token = await _accountService.CreateJWTToken(user);
                JwtTokens newToken = await _accountService.GetJWTToken(user);
                user.JToken = newToken;
                user.JToken.Token = token.ToString();
                user.JToken.ExpirationDate = token.ValidTo;
                RefreshTokens dbRefToken = await _accountService.GetRefreshToken(user);
                if (dbRefToken == null || dbRefToken.Expires<DateTime.Now)
                {
                    user.RefreshToken = _accountService.CreateRefToken();
                    var res = await _accountService.UpdateUserTokens(user);
                    return Ok(new
                    {
                        Status = "New tokens provided",
                        JwtToken = new JwtSecurityTokenHandler().WriteToken(token),
                        UserName = user.UserName,
                        EmployeeId = user.EmployeeId,
                        JwtExpiresAt = token.ValidTo,
                        RefreshToken = user.RefreshToken.Token,
                        RefExpiresAt = user.RefreshToken.Expires
                    });
                }
                else 
                {
                    var res = await _accountService.UpdateUserTokens(user);
                    return Ok(new
                    {
                        Status = "New JWT token provided",
                        JwtToken = new JwtSecurityTokenHandler().WriteToken(token),
                        UserName = user.UserName,
                        EmployeeId = user.EmployeeId,
                        JwtExpiresAt = token.ValidTo,
                        RefreshToken = user.RefreshToken.Token,
                        RefExpiresAt = user.RefreshToken.Expires
                    });
                }
            }
            return Unauthorized();
        }

        [Authorize]
        [HttpGet("{id:int}")]
        public async Task<ActionResult<CustomUser>> GetEmployee(int id)
        {
            var claimJTI = ((ClaimsIdentity)User.Identity).Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti);
            var claim = ((ClaimsIdentity)User.Identity).Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name);
            AppUser employee = await _accountService.FindByNameAsync(claim.Value);
            bool validJWT = await _accountService.CheckForValidJWT(employee, claimJTI.Value);
            if (!validJWT)
            {
                return StatusCode(StatusCodes.Status401Unauthorized, new Response { Status = "Error", Message = "invalid JWT for !" + employee.UserName });
            }
            int employeeId = employee.EmployeeId;
            CustomUser customUser = await _accountService.FindUserById(id);
            if (customUser == null)
            {
                return NotFound();
            }
            List<Claim> claims = ((ClaimsIdentity)User.Identity).Claims.Where(c => c.Type == ClaimTypes.Role).ToList();
            bool admin = false;
            bool vd = false;
            foreach (Claim c in claims)
            {
                if (c.Value == "Admin")
                {
                    admin = true;
                }
                if (c.Value == "VD")
                {
                    vd = true;
                }
            }
            if (employeeId == id || admin == true || vd == true)
            {
                return customUser;
            }
            return Unauthorized();
        }

        [Authorize(Roles ="VD, Admin")]
        [HttpGet]
        public async Task<ActionResult<IEnumerable<AppUser>>> GetEmployees()
        {
            var claimJTI = ((ClaimsIdentity)User.Identity).Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti);
            var claim = ((ClaimsIdentity)User.Identity).Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name);
            AppUser employee = await _accountService.FindByNameAsync(claim.Value);
            bool validJWT = await _accountService.CheckForValidJWT(employee, claimJTI.Value);
            if (validJWT)
            {
                return await _accountService.GetEmployees();
            }
            return Unauthorized();
        }

        [Authorize(Roles=UserRoles.Admin)]
        [HttpDelete("{id}")]
        public async Task<ActionResult<Employees>> DeleteEmployee(int id)
        {
            var claimJTI = ((ClaimsIdentity)User.Identity).Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti);
            var claim = ((ClaimsIdentity)User.Identity).Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name);
            AppUser employee = await _accountService.FindByNameAsync(claim.Value);
            bool validJWT = await _accountService.CheckForValidJWT(employee, claimJTI.Value);
            if (validJWT)
            {
                Employees employees = await _accountService.DeleteEmployees(id);
                if (employees == null)
                {
                    return NotFound();
                }
                return employees;
            }
            return Unauthorized();
        }

        [Authorize]
        [HttpPut("{id}")]
        public async Task<IActionResult> PutEmployees(int id, ClientUser cliEmployee)
         {
            int employeeId = int.Parse(cliEmployee.EmployeeId);

            var claimJTI = ((ClaimsIdentity)User.Identity).Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti);
            var claim = ((ClaimsIdentity)User.Identity).Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name);
            AppUser employee = await _accountService.FindByNameAsync(claim.Value);
            bool validJWT = await _accountService.CheckForValidJWT(employee, claimJTI.Value);
            if (validJWT)
            { 
                AppUser appUser = await _accountService.FindByNameAsync(claim.Value);
                CustomUser customUser = await _accountService.FindUserById(id);
                if (customUser == null)
                {
                    return NotFound();
                }
                List<Claim> claims = ((ClaimsIdentity)User.Identity).Claims.Where(c => c.Type == ClaimTypes.Role).ToList();
                bool admin = false;
                foreach (Claim c in claims)
                {
                    if (c.Value == "Admin")
                    {
                        admin = true;
                    }
                }
                if (appUser.EmployeeId == id || admin == true)
                {
                    Employees employees = await _accountService.FindEmployeeByEmployeeId(id);
                    AppUser userToUpdate = await _accountService.FindByNameAsync(employee.UserName);
                    var result = await _accountService.UpdateAppUser(userToUpdate);
                    return Ok(new
                    {
                        Status = "Success",
                        Message = "User updated successfully!",
                        target = cliEmployee.UserName,
                        by = appUser.UserName
                    });
                }
                return Unauthorized();
            }
            return Unauthorized();
        }

        [HttpPost("sync")]
        public async Task<IActionResult> SyncEmployees()
        {
            List<Employees> employees = await _accountService.SyncEmployees();
            List<RegisterModel> usersToRegister = new List<RegisterModel>();
            foreach(Employees e in employees)
            {
                RegisterModel user = new RegisterModel();
                user.UserName = e.FirstName + e.LastName;
                user.FirstName = e.FirstName;
                user.LastName = e.LastName;
                user.Password = "Secret1337?!";
                user.Country = e.Country;
                user.EmployeeID = e.EmployeeId;
                usersToRegister.Add(user);
            }
            foreach(RegisterModel u in usersToRegister)
            {
                var userExists = await _accountService.FindByNameAsync(u.UserName);
                if (userExists != null)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User already exists!" });
                }
                AppUser user = _accountService.AddIdeUser(u);

                var result = await _accountService.CreateAsync(user, u.Password);
                if (!result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });
                }

                await _accountService.AddUserToRole(user, "Employee");
            }
            return Ok(new
            {
                employees= usersToRegister,
                Status = "Success",
                Message = "User were synced successfully!",
            });
        }
    }
}
