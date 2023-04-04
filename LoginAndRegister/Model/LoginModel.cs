using System.ComponentModel.DataAnnotations;

namespace LoginAndRegister.Model
{
    public class LoginModel
    {
        [Required(ErrorMessage = "UserName is required for login")]
        public string UserName { get; set; }
        [Required(ErrorMessage = "Please enter the password for login")]
        public string Password { get; set; }
    }
}
