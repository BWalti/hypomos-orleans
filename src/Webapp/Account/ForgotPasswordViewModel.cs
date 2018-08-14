namespace Webapp.Account
{
    using System.ComponentModel.DataAnnotations;
    using Newtonsoft.Json;

    [JsonObject]
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}