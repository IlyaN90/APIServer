using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using APIServer.Models;
using APIServer.Services;
using Microsoft.AspNetCore.Authorization;
using APIServer.Identity;
using System.Security.Claims;
using APIServer.Migrations;
using System.IdentityModel.Tokens.Jwt;

namespace APIServer.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class OrdersController : ControllerBase
    {
        private readonly IOrderService _orderService;
        private readonly IAccountService _accountService;

        public OrdersController(IOrderService orders, IAccountService account)
        {
            _orderService = orders;
            _accountService=account;
        }

        [Authorize]
        [HttpGet("{id:int}")]
        public async Task<ActionResult<IEnumerable<Orders>>> GetMyOrders(int id)
        {
            List<Claim> claims = ((ClaimsIdentity)User.Identity).Claims.Where(c => c.Type == ClaimTypes.Role).ToList();
            var claimJTI = ((ClaimsIdentity)User.Identity).Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti);
            AppUser user = await _accountService.FindUserByJWT(claimJTI.Value);
            bool validJWT = await _accountService.CheckForValidJWT(user, claimJTI.Value);
            if (validJWT) 
            {
                bool admin = false;
                bool vd = false;
                bool self = false;
                if (user != null && id == user.EmployeeId)
                {
                    self = true;
                }
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
                if (self == true || vd == true || admin == true)
                {
                    IEnumerable<Orders> usersOreders = await _orderService.GetUsersOrders(id);
                    if (usersOreders.Count() == 0)
                    {
                        return NotFound(new
                        {
                            Status = "Failed",
                            Message = "No orders found!"
                        });
                    }
                    return Ok(new
                    {
                        Status = "Sucess",
                        Message = "Orders found!",
                        orders = usersOreders
                    });
                }
                return Unauthorized();
            }
            return Unauthorized();
        }

        [Authorize(Roles = "VD, Admin, CountryManager")]
        [HttpGet("{country}")]
        public async Task<ActionResult<IEnumerable<AppUser>>> GetCountryOrders(string country)
        {
            var claimJTI = ((ClaimsIdentity)User.Identity).Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti);
            var claim = ((ClaimsIdentity)User.Identity).Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name);
            AppUser employee = await _accountService.FindByNameAsync(claim.Value);
            bool validJWT = await _accountService.CheckForValidJWT(employee, claimJTI.Value);
            if (validJWT)
            {
                var claimType = "Country";
                var claimCountry = ((ClaimsIdentity)User.Identity).Claims.FirstOrDefault(c => c.Type == claimType);
                List<Claim> claims = ((ClaimsIdentity)User.Identity).Claims.Where(c => c.Type == ClaimTypes.Role).ToList();
                bool admin = false;
                bool vd = false;
                bool manager = false;
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
                    if (c.Value == "CountryManager")
                    {
                        manager = true;
                    }
                }
                if (admin == true || vd == true)
                {
                    IEnumerable<Orders> usersOreders = await _orderService.GetUsersOrders(country);
                    return Ok(new {
                        Status = "Sucess",
                        Message = "Orders found!",
                        orders = usersOreders
                    });
                }
                if (manager == true && claimCountry.Value == country)
                {
                    IEnumerable<Orders> usersOreders = await _orderService.GetUsersOrders(country);
                    return Ok(new {
                        Status = "Sucess",
                        Message = "Orders found!",
                        orders = usersOreders
                    });
                }
                return Unauthorized();
            }
            return Unauthorized();
        }

        [Authorize(Roles = "VD, Admin, CountryManager")]
        [HttpGet]
        public async Task<IEnumerable<Orders>> GetAllOrders()
        {
            var claimJTI = ((ClaimsIdentity)User.Identity).Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti);
            var claim = ((ClaimsIdentity)User.Identity).Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name);
            AppUser employee = await _accountService.FindByNameAsync(claim.Value);
            bool validJWT = await _accountService.CheckForValidJWT(employee, claimJTI.Value);
            if (validJWT)
            {
                var claimType = "Country";
                var claimCountry = ((ClaimsIdentity)User.Identity).Claims.FirstOrDefault(c => c.Type == claimType);
                List<Claim> claims = ((ClaimsIdentity)User.Identity).Claims.Where(c => c.Type == ClaimTypes.Role).ToList();
                bool admin = false;
                bool vd = false;
                bool manager = false;
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
                    if (c.Value == "CountryManager")
                    {
                        manager = true;
                    }
                }
                if (admin == true || vd == true)
                {
                    IEnumerable<Orders> usersOreders = await _orderService.GetAllOrders();
                    return usersOreders;
                }
                if (manager == true)
                {
                    IEnumerable<Orders> usersOreders = await _orderService.GetAllOrdersRaw(claimCountry.Value);
                    return usersOreders;
                }
                return null;
            }
            return null;
        }
    }
}
