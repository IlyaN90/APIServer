﻿using System;
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
        [HttpPost("user-orders")]
        public async Task<ActionResult<IEnumerable<Orders>>> GetMyOrders(ClientUser clientUser)
        {
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
            if (vd == true || admin == true)
            {
                int id = int.Parse(clientUser.EmployeeId);
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

            /*
GetMyOrders skall returnera de ordrar för employee som användaren är knuten till då användaren
har rollen Employee, 
27.för rollerna VD och Admin skall dessa kunna skicka in parameter employee och
få dessa ordrar.
*/
        }

        [Authorize]
        [HttpGet("{id:int}")]
        public async Task<ActionResult<IEnumerable<Orders>>> GetMyOrders(int id)
        {
            //var claimUserName = ((ClaimsIdentity)User.Identity).Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name);
            //var claimCountry = ((ClaimsIdentity)User.Identity).Claims.FirstOrDefault(c => c.Type == ClaimTypes.Country);
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

        [Authorize(Roles = "VD, Admin, CountryManager")]
        [HttpGet("{country}")]
        public async Task<ActionResult<IEnumerable<AppUser>>> GetCountryOrders(string country)
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

        [Authorize(Roles = "VD, Admin, CountryManager")]
        [HttpGet]
        public async Task<ActionResult<IEnumerable<AppUser>>> GetAllOrders()
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
                return Ok(new
                {
                    Status = "Sucess",
                    Message = "Orders found!",
                    orders = usersOreders
                });
            }
            if (manager == true)
            {
                IEnumerable<Orders> usersOreders = await _orderService.GetAllOrdersRaw(claimCountry.Value);
                return Ok(new
                {
                    Status = "Sucess",
                    Message = "Orders found!",
                    orders = usersOreders
                });
            }
            return Unauthorized();
        }

    }
}