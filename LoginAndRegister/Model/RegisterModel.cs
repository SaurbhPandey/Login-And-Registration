﻿using System.ComponentModel.DataAnnotations;

namespace LoginAndRegister.Model
{
    public class RegisterModel
    {
        [Required (ErrorMessage = "Username is required")]
        public string UserName { get; set; }
        [Required(ErrorMessage = "Email is required") , EmailAddress]
        public string Email { get; set; }
        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; }    
        
    }
}
