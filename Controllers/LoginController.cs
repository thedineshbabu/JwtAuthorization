using Microsoft.AspNetCore.Authorization;    
using Microsoft.AspNetCore.Mvc;    
using Microsoft.Extensions.Configuration;    
using Microsoft.IdentityModel.Tokens;    
using System;    
using System.IdentityModel.Tokens.Jwt;    
using System.Security.Claims;    
using System.Text; 


namespace JWTAuthentication 
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : Controller 
    {
        private IConfiguration _config;
        public LoginController(IConfiguration config)
        {
            _config = config;
        }

        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login([FromBody]UserModel login)
        {
            IActionResult response = Unauthorized();

            var user = AuthenticateUser(login);
            if(user != null)
            {
                var tokenString = GenerateJSONToken();
                response = new OkObjectResult(new { token = tokenString});
            }

            return response;
        }

        private UserModel AuthenticateUser(UserModel login) 
        {
            UserModel user = null;
            if(login.UserName == "Dinesh")
            {
                user = new UserModel(){ UserName = "Dinesh", Password = "babu" };
            }
            return user;
        }

        private string GenerateJSONToken()
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("sampleKey"));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken("a.com", "a.com", null, expires: DateTime.Now.AddMinutes(120), signingCredentials: credentials);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

    }
}