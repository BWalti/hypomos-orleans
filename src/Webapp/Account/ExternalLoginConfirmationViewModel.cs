namespace Webapp.Account
{
    using System.ComponentModel.DataAnnotations;
    using Newtonsoft.Json;

    [JsonObject]
    public class ExternalLoginConfirmationViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}