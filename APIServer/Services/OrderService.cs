using APIServer.Identity;
using APIServer.Models;
using AutoMapper.Configuration;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;

namespace APIServer.Services
{
    public interface IOrderService
    {
        public Task<IEnumerable<Orders>> GetUsersOrders(int id);
        public Task<IEnumerable<Orders>> GetUsersOrders(string country);
        public Task<IEnumerable<Orders>> GetAllOrders();
        public Task<IEnumerable<Orders>> GetAllOrdersRaw(string country);
        public string GetClaim(string token, string claimType);
    }
    public class OrderService : IOrderService
    {
        private readonly NorthwindContext _nwContext;
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        public OrderService(NorthwindContext nwContext, UserManager<AppUser> userManager,
            RoleManager<IdentityRole> roleManager)
        {
            _nwContext = nwContext;
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public string GetClaim(string token, string claimType)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var securityToken = tokenHandler.ReadToken(token) as JwtSecurityToken;

            var stringClaimValue = securityToken.Claims.First(claim => claim.Type == claimType).Value;
            return stringClaimValue;
        }

        public async Task<IEnumerable<Orders>> GetUsersOrders(int id)
        {
            List<Orders> orders = await _nwContext.Orders.Where(o => o.EmployeeId == id).ToListAsync();
            return orders;
        }
        public async Task<IEnumerable<Orders>> GetUsersOrders(string country)
        {
            List<Orders> orders = await _nwContext.Orders.Where(o => o.ShipCountry == country).ToListAsync();
            return orders;
        }
        public async Task<IEnumerable<Orders>> GetAllOrders()
        {
            List<Orders> orders = await _nwContext.Orders.ToListAsync();
            return orders;
        }
        public async Task<IEnumerable<Orders>> GetAllOrdersRaw(string country)
        {
            var orders = await _nwContext.Orders
                    .FromSqlRaw("Select * from Orders where ShipCountry=@Country", new SqlParameter("@Country", country))
                    .ToListAsync();
            return orders;
        }
    }
}
