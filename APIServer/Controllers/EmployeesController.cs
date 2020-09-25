using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using APIServer.Models;
using APIServer.Identity;
using Microsoft.AspNetCore.Identity;
using AutoMapper;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.Extensions.Configuration;
using APIServer.Authorization;
using Microsoft.AspNetCore.Authorization;
using System.Net.Http;
using Newtonsoft.Json;
using APIServer.Services;
using APIServer.Migrations.Northwind;

namespace APIServer.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    //[Authorize]
    //[Authorize(Roles ="VD,Employee")]
    public class EmployeesController : ControllerBase
    {
        //private readonly NorthwindContext _nwContext;
        private readonly IAccountService _accountService;

        public EmployeesController(IAccountService account)
        {
            _accountService = account;
        }

        //        [Authorize]
        //        [Authorize(Roles=UserRoles.Admin)]

        //register an employee
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
            model.EmployeeID = _accountService.FindEmployeeId(model.FirstName, model.LastName);
            AppUser user = _accountService.AddIdeUser(model);

            var result = await _accountService.CreateAsync(user, model.Password);
            if (!result.Succeeded) 
            { 
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });
            }

            await _accountService.AddUserToRoleEmployee(user);

            return Ok(new Response { 
                Status = "Success", 
                Message = "User created successfully!",
            });
        }

        //register an Admin and create all Roles
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
            int id = _accountService.FindEmployeeId(model.FirstName, model.LastName);
            model.EmployeeID = id;

            //create an employee and get its EmployeeID
            AppUser user = _accountService.AddIdeUser(model);

            var result = await _accountService.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });

            var res=await _accountService.AddUserToRoleAdmin(user);

            return Ok(new Response { Status = "Success", Message = "User created successfully!" });
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
            int id = _accountService.FindEmployeeId(model.FirstName, model.LastName);
            model.EmployeeID = id;

            AppUser user = _accountService.AddIdeUser(model);

            var result = await _accountService.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });
            }

            await _accountService.AddUserToRoleVD(user);

            return Ok(new Response { Status = "Success", Message = "User created successfully!" });
        }

        [Authorize(Roles=UserRoles.VD)]
        [HttpPost]
        public async Task<IActionResult> Authorize(RefreshTokenRequest refreshToken)
        {
            return null;
        }

  //      [Authorize(Roles = UserRoles.VD)]
      //  [Authorize]
        [HttpPost("refresh-token")]
        public async Task<ActionResult<AuthenticateResponse>> RefreshToken (RefreshTokenRequest refreshToken)
        {
            var response = await _accountService.RefreshToken(refreshToken);
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
                RefExpiresAt = response.RefExpires
            });
        }

        //takes in login and password and generates new bearer and refresh tokens
        [AllowAnonymous]
        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login(LoginModel model)
        {
            AppUser user = await _accountService.FindByNameAsync(model.UserName);

            if (await _accountService.CheckPasswordAsync(user, model.Password))
            {
                if (user != null)
                {
                    SecurityToken token = await _accountService.CreateJWTToken(user);
                    JwtTokens newToken = await _accountService.GetJWTToken(user);
                    RefreshTokens usersRefresh = await _accountService.GetRefreshToken(user);

                    user.JToken = newToken;
                    user.JToken.Token = token.ToString();
                    user.JToken.ExpirationDate = token.ValidTo;

                    RefreshTokens refreshToken = new RefreshTokens();
                    user.RefreshToken = refreshToken;
                    refreshToken = _accountService.CreateRefToken(user);
                    user.RefreshToken.Token = refreshToken.Token;
                    user.RefreshToken.Expires = refreshToken.Expires;
                    var res = await _accountService.UpdateUserTokens(user);

                    return Ok(new
                    {
                        JwtToken = new JwtSecurityTokenHandler().WriteToken(token),
                        UserName=user.UserName,
                        RefreshToken = refreshToken.Token,
                        JwtExpiresAt = token.ValidTo,
                        RefExpiresAt = refreshToken.Expires
                    });
                }
            }
            return Unauthorized();
        }
        //check claims
        public string GetClaim(string token, string claimType)
        {
            //Request.HttpContext.User.Claims
            var tokenHandler = new JwtSecurityTokenHandler();
            var securityToken = tokenHandler.ReadToken(token) as JwtSecurityToken;

             var stringClaimValue = securityToken.Claims.First(claim => claim.Type == claimType).Value;
            //var stringClaimValue = securityToken.Claims.ToList();
            return stringClaimValue;
        }

        // GET: api/Employees
        [Authorize(Roles ="VD, Admin")]
        [HttpGet]
        public async Task<ActionResult<IEnumerable<AppUser>>> GetEmployees()
        {
            return await _accountService.GetEmployees();
        }

        // GET: api/Employees/5
        [HttpGet("{id}")]
        public async Task<ActionResult<CustomUser>> GetEmployees(int id)
        {
            CustomUser customUser = await _accountService.FindUserById(id);
            if (customUser == null)
            {
                return NotFound();
            }
            return customUser;
        }

        // PUT: api/Employees/5
        // To protect from overposting attacks, enable the specific properties you want to bind to, for
        // more details, see https://go.microsoft.com/fwlink/?linkid=2123754.
        [HttpPut("{id}")]
       /* public async Task<IActionResult> PutEmployees(int id, Employees employees)
        {
            if (id != employees.EmployeeId)
            {
                return BadRequest();
            }

            _nwContext.Entry(employees).State = EntityState.Modified;

            try
            {
                await _nwContext.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!_nwContext.Employees.Any(e => e.EmployeeId == id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }*/

            return NoContent();
            throw new NotImplementedException();

        }

        // POST: api/Employees
        // To protect from overposting attacks, enable the specific properties you want to bind to, for
        // more details, see https://go.microsoft.com/fwlink/?linkid=2123754.
        [HttpPost]
        public async Task<ActionResult<Employees>> PostEmployees(Employees employees)
        {
            /*_nwContext.Employees.Add(employees);
            await _nwContext.SaveChangesAsync();

            return CreatedAtAction("GetEmployees", new { id = employees.EmployeeId }, employees);*/
            throw new NotImplementedException();

        }

        // DELETE: api/Employees/5
        //[Authorize(Roles=UserRoles.Admin)]
        [HttpDelete("{id}")]
        public async Task<ActionResult<Employees>> DeleteEmployees(int id)
        {
            Employees employees = await _accountService.DeleteEmployees(id);
            if (employees == null)
            {
                NotFound();
            }
            return employees;
        }
    }
}
