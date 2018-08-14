namespace Webapp.Models
{
    using System.ComponentModel.DataAnnotations;
    using Newtonsoft.Json;

    [JsonObject]
    public class SubscribeModel
    {
        [EmailAddress]
        [Required]
        public string Email { get; set; }
    }
}