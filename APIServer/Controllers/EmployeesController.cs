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
            if (!result.Succeeded) 
            { 
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });
            }

            await _accountService.AddUserToRole(user, UserRoles.Employee);

            return Ok(new
            {
                Status = "Success",
                Message = "User created successfully!",
                employeeId = user.EmployeeId
            }); 
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("register-manager")]
        public async Task<IActionResult> RegisterCountryManager(RegisterModel model)
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
            if (!result.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });
            }

            await _accountService.AddUserToRole(user, UserRoles.CountryManager);

            return Ok(new
            {
                Status = "Success",
                Message = "User created successfully!",
                employeeId = user.EmployeeId
            });
        }
        
        [HttpPost]
        [Route("register-admin")]
        public async Task<IActionResult> RegisterAdmin(RegisterModel model)
        {
            var userExists = await _accountService.FindByNameAsync(model.UserName);
            if (userExists != null)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User already exists!" });
            }
            _accountService.AddNewNWEmployee(model);
            Employees employee = await _accountService.FindEmployeeId(model.FirstName, model.LastName);
            int id = employee.EmployeeId;
            model.EmployeeID = id;

            //create an employee and get its EmployeeID
            AppUser user = _accountService.AddIdeUser(model);

            var result = await _accountService.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });

            var res=await _accountService.AddUserToRole(user, UserRoles.Admin);

            return Ok(new
            {
                Status = "Success",
                Message = "User created successfully!",
                employeeId = user.EmployeeId
            });
        }

        [HttpPost]
        [Route("register-vd")]
        public async Task<IActionResult> RegisterVD(RegisterModel model)
        {
            var userExists = await _accountService.FindByNameAsync(model.UserName);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User already exists!" });

            //create an employee and get its EmployeeID
            _accountService.AddNewNWEmployee(model);
            Employees employee = await _accountService.FindEmployeeId(model.FirstName, model.LastName);
            int id = employee.EmployeeId;
            model.EmployeeID = id;

            AppUser user = _accountService.AddIdeUser(model);

            var result = await _accountService.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });
            }

            await _accountService.AddUserToRole(user, UserRoles.VD);

            return Ok(new
            {
                Status = "Success",
                Message = "User created successfully!",
                employeeId = user.EmployeeId
            });
        }
        #endregion
        
        [HttpPost("refresh-token")]
        public async Task<ActionResult<AuthenticateResponse>> RefreshToken (RefreshTokenRequest refreshToken)
        {
            var response = await _accountService.RefreshToken(refreshToken, null);
            if (response.UserName == null)
            {
                return Unauthorized();
            }
            return Ok(new
            {
                JwtToken = new JwtSecurityTokenHandler().WriteToken(response.JwtToken),
                UserName = response.UserName,
                RefreshToken = response.RefreshToken,
                JwtExpiresAt = response.JwtToken.ValidTo,
                RefExpiresAt = response.RefExpires,
             });
        }
        
        [AllowAnonymous]
        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login(LoginModel model)
        {
            AppUser user = await _accountService.FindByNameAsync(model.UserName);
            if (user != null)
            {
                RefreshTokens refToken = await _accountService.GetRefreshToken(user);

                bool correct = await _accountService.CheckPasswordAsync(user, model.Password);
                if (correct)
                {
                    if (refToken.Token == null || refToken.Expires > DateTime.Now)
                    {
                        RefreshTokenRequest refReq = new RefreshTokenRequest();
                        refReq.RefreshToken = refToken.Token;
                        //returnerar och uppdaterar JWT och Ref tokens
                        AuthenticateResponse response=await _accountService.RefreshToken(refReq, user);
                        return Ok(new
                        {
                            JwtToken = new JwtSecurityTokenHandler().WriteToken(response.JwtToken),
                            UserName = user.UserName,
                            EmployeeId = user.EmployeeId,
                            JwtExpiresAt = response.JwtToken.ValidTo,
                            RefreshToken = response.RefreshToken,
                            RefExpiresAt = response.RefExpires
                        }); 
                    }
                    else
                    {
                        SecurityToken token = await _accountService.CreateJWTToken(user);
                        JwtTokens newToken = await _accountService.GetJWTToken(user);
                        user.JToken = newToken;
                        user.JToken.Token = token.ToString();
                        user.JToken.ExpirationDate = token.ValidTo;
                        var res = await _accountService.UpdateUserTokens(user);
                        return Ok(new
                        {
                            JwtToken = new JwtSecurityTokenHandler().WriteToken(token),
                            UserName = user.UserName,
                            EmployeeId = user.EmployeeId,
                            JwtExpiresAt = token.ValidTo
                        });
                    }
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
                return Unauthorized();
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
            return await _accountService.GetEmployees();
        }

        [Authorize(Roles=UserRoles.Admin)]
        [HttpDelete("{id}")]
        public async Task<ActionResult<Employees>> DeleteEmployee(int id)
        {

            Employees employees = await _accountService.DeleteEmployees(id);
            if (employees == null)
            {
                return NotFound();
            }
            return employees;
        }

        [Authorize]
        [HttpPut("{id}")]
        public async Task<IActionResult> PutEmployees(int id, ClientUser employee)
         {
            int employeeId = int.Parse(employee.EmployeeId);
            var claim = ((ClaimsIdentity)User.Identity).Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name);
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
                    target = employee.UserName,
                    by = appUser.UserName
                });
            }
            return Unauthorized();
         }

        //Loads in three Employees from NW
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
