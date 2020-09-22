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
using APIServer.Migrations;
using APIServer.Services;

namespace APIServer.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class EmployeesController : ControllerBase
    {
        private readonly NorthwindContext _nwContext;
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IAccountService _accountService;

        public EmployeesController(NorthwindContext nwContext,UserManager<AppUser> userManager,
            RoleManager<IdentityRole> roleManager, IAccountService account,
            IMapper mapper,
            IConfiguration configuration)
        {
            _nwContext = nwContext;
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _accountService = account;
        }

        //        [Authorize]
        //        [Authorize(Roles=UserRoles.Admin)]

        //register an employee
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromForm] RegisterModel model)
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

            _accountService.AddUserToRoleEmployee(user);

            return Ok(new Response { Status = "Success", Message = "User created successfully!" });
        }

        //register an Admin and create all Roles
        [HttpPost]
        [Route("register-admin")]
        public async Task<IActionResult> RegisterAdmin([FromForm] RegisterModel model)
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

            _accountService.AddUserToRoleAdmin(user);

            return Ok(new Response { Status = "Success", Message = "User created successfully!" });
        }

        [HttpPost]
        [Route("register-vd")]
        public async Task<IActionResult> RegisterVD([FromForm] RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.UserName);
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

            _accountService.AddUserToRoleVD(user);

            return Ok(new Response { Status = "Success", Message = "User created successfully!" });
        }

        [Authorize(Roles=UserRoles.VD)]
        [HttpPost]
        public async Task<IActionResult> Authorize([FromForm] RegisterModel model)
        {
            return null;
        }
        //takes in login and password and generates bearer and refresh tokens
        [AllowAnonymous]
        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromForm] RegisterModel model)
        {
            AppUser user = await _accountService.FindByNameAsync(model.UserName);

            if (await _accountService.CheckPasswordAsync(user, model.Password))
            {
                if (user != null)
                {
                    var token = await _accountService.CreateTokens(user);
                    user.JwtToken = token.ToString();

                    if (user.RefreshToken != null)
                    {
                        //https://code-maze.com/using-refresh-tokens-in-asp-net-core-authentication/#:~:text=With%20refresh%20token%2Dbased%20flow,identify%20the%20app%20using%20it.
                        //user.RefreshToken = refreshToken.ToString();
                    }

                    // var res = await _userManager.UpdateAsync(user);

                    return Ok(new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(token),
                        refToken = new JwtSecurityTokenHandler().WriteToken(token),
                        expiration = token.ValidTo
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
        [HttpGet]
        public async Task<ActionResult<IEnumerable<AppUser>>> GetEmployees()
        {
            return await _userManager.Users.ToListAsync();
        }

        // GET: api/Employees/5
        [HttpGet("{id}")]
        public async Task<ActionResult<CustomUser>> GetEmployees(int id)
        {
            Employees employee = await _nwContext.Employees.FindAsync(id);
            var appUser =  _userManager.Users.Where(u => u.EmployeeId == id).FirstOrDefault();
            if (employee == null || appUser == null)
            {
                return NotFound();
            }
            CustomUser customUser = new CustomUser();
            customUser.EmployeeId = appUser.EmployeeId;
            customUser.Username = appUser.UserName;

            return customUser;
        }

        // PUT: api/Employees/5
        // To protect from overposting attacks, enable the specific properties you want to bind to, for
        // more details, see https://go.microsoft.com/fwlink/?linkid=2123754.
        [HttpPut("{id}")]
        public async Task<IActionResult> PutEmployees(int id, Employees employees)
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
                if (!EmployeesExists(id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            return NoContent();
        }

        // POST: api/Employees
        // To protect from overposting attacks, enable the specific properties you want to bind to, for
        // more details, see https://go.microsoft.com/fwlink/?linkid=2123754.
        [HttpPost]
        public async Task<ActionResult<Employees>> PostEmployees(Employees employees)
        {
            _nwContext.Employees.Add(employees);
            await _nwContext.SaveChangesAsync();

            return CreatedAtAction("GetEmployees", new { id = employees.EmployeeId }, employees);
        }

        // DELETE: api/Employees/5
        //[Authorize(Roles=UserRoles.Admin)]
        [HttpDelete("{id}")]
        public async Task<ActionResult<Employees>> DeleteEmployees(int id)
        {
            AppUser deleteMe = _userManager.Users.Where(u=>u.EmployeeId==id).First();
            var result = await _userManager.DeleteAsync(deleteMe);
            var employees = await _nwContext.Employees.FindAsync(id);
            if (employees == null)
            {
                return NotFound();
            }

            _nwContext.Employees.Remove(employees);
            await _nwContext.SaveChangesAsync();

            return employees;
        }

        private bool EmployeesExists(int id)
        {
            return _nwContext.Employees.Any(e => e.EmployeeId == id);
        }
    }
}
