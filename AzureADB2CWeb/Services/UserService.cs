using AzureADB2CWeb.Data;
using AzureADB2CWeb.Extensions;
using AzureADB2CWeb.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AzureADB2CWeb.Services
{
    public class UserService : IUserService
    {
        private readonly ApplicationDbContext _context;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public UserService(ApplicationDbContext context , IHttpContextAccessor httpContextAccessor )
        {
            _context = context;
            _httpContextAccessor = httpContextAccessor;
        }
        public User Create(User user)
        {
            _context.Users.Add(user);
            _context.SaveChanges();
            return user;
        }

        public async Task<string> GetB2CTokenAsync()
        {
            try
            {
                return await _httpContextAccessor.HttpContext.GetTokenAsync("access_token");
            }
            catch
            {
                return null;
            }
        }

        public User GetUserById(string b2cObjectId)
        {
            User user = new();
            try
            {
                return _context.Users.FirstOrDefault(i=>i.B2CObjectId == b2cObjectId);
            }
            catch
            {
                return user;
            }
        }

        public User GetUserFromSession()
        {
            var user = _httpContextAccessor.HttpContext.Session.GetComplexData<User>("UserSession");
            if(user==null || string.IsNullOrWhiteSpace(user.B2CObjectId))
            {
                var idClaim = ((ClaimsIdentity)_httpContextAccessor.HttpContext.User.Identity)
                    .FindFirst(ClaimTypes.NameIdentifier);
                string userId = idClaim?.Value;
                user = GetUserById(userId);
                this._httpContextAccessor.HttpContext.Session.SetComplexData("UserSession" , user);

            }

            return user;
        }
    }
}
