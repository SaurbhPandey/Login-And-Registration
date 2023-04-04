using AutoMapper;
using LoginAndRegister.Ef_core;
using LoginAndRegister.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace LoginAndRegister.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthenticationController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration )
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }
        [HttpPost("registration")]
        public async Task<IActionResult> Register([FromBody] RegisterModel registerModel)
        {
            var userExist = await _userManager.FindByEmailAsync(registerModel.Email);
            if (userExist != null)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { status = "Error", message = "User Already exist" });
            }
            ApplicationUser user = new ApplicationUser()
            {
                Email = registerModel.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerModel.UserName,
            };
            var result = await _userManager.CreateAsync(user, registerModel.Password);
            if (!result.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { status = "Error", message = "User creation is failed , Please try again later" });
            }
            else
            {
                return StatusCode(StatusCodes.Status200OK, new Response { status = "Ok", message = "User registered succesfully" });
            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            var user = await _userManager.FindByNameAsync(loginModel.UserName);
            if (user != null && await _userManager.CheckPasswordAsync(user, loginModel.Password))
            {
                var userRoles = await _userManager.GetRolesAsync(user);
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(ClaimTypes.Email , user.Email),
                    new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };
                foreach(var userRole in  userRoles)
                {
                    authClaims.Add(new Claim (ClaimTypes.Role , userRole));
                }
                var authKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Secret"]));
                var token = new JwtSecurityToken(
                    issuer: _configuration["Jwt:ValidIssuer"],
                    audience: _configuration["Jwt:ValidAudience"],
                    expires: DateTime.Now.AddHours(1),
                    claims : authClaims, 
                    signingCredentials: new SigningCredentials(authKey , SecurityAlgorithms.HmacSha256)
                 );
                return Ok(new JwtSecurityTokenHandler().WriteToken(token));
            }
            return Unauthorized();
        }



        [HttpPost("RegisterAdmin")]
        public async Task<IActionResult> RegisterAdmin([FromBody] RegisterModel registerModel)
        {
            var userExist = await _userManager.FindByEmailAsync(registerModel.Email);
            if (userExist != null)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { status = "Error", message = "User Already exist" });
            }
            ApplicationUser user = new ApplicationUser()
            {
                Email = registerModel.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerModel.UserName,
            };
            var result = await _userManager.CreateAsync(user, registerModel.Password);
            if (!result.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { status = "Error", message = "User creation is failed , Please try again later" });
            }
            else
            {
                if (!await _roleManager.RoleExistsAsync(UserRole.Admin))
                    await _roleManager.CreateAsync(new IdentityRole(UserRole.Admin));
                if (!await _roleManager.RoleExistsAsync(UserRole.User))
                    await _roleManager.CreateAsync(new IdentityRole(UserRole.User));
                if(await _roleManager.RoleExistsAsync(UserRole.Admin))
                {
                    await _userManager.AddToRoleAsync(user , UserRole.Admin);
                }
                return StatusCode(StatusCodes.Status200OK, new Response { status = "Ok", message = "User registered succesfully" });
            }
        }

        [HttpPut("{id}")]
        [Authorize]
        public async Task<IActionResult> UpdateUser(RegisterModel registerModel)
        {
            var user = await _userManager.FindByEmailAsync(registerModel.Email);
            var userEmail = User.FindFirst(ClaimTypes.Email).Value;
            if(user != null && user.Email.Equals(userEmail))
            {
                user.UserName = registerModel.UserName;
                user.Email = registerModel.Email;
                var passwordHasher = new PasswordHasher<ApplicationUser>();
                var newPasswordHash = passwordHasher.HashPassword(user, registerModel.Password);
                user.PasswordHash = newPasswordHash;
                await _userManager.UpdateAsync(user);
                return Ok(new Response { status = "Ok", message = "User updated succesfully" });
            }
            else
            {
                return StatusCode(StatusCodes.Status400BadRequest, new Response { status = "user not found" ,message = "user is not updated" });
            }
        }

        [HttpDelete("DeleteUser")]
        [Authorize(Roles = UserRole.Admin)]

        public async Task<IActionResult> DeleteUser(DeleteModel deleteModel)
        {
            var user = await _userManager.FindByEmailAsync(deleteModel.Email);
            if(user == null)
            {
                
                return Ok(new Response { message = "The user that you are trying delete is not exist in our database , Please enter the correct email id", status = "BAD REQUEST" });
            }
            else
            {
                await _userManager.DeleteAsync(user);
                return Ok(new Response { status = "ok", message = "User has beeb delted succesfully." });
            }
             
        }

    }
}
