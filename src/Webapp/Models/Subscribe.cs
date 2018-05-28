using Newtonsoft.Json;
using System.ComponentModel.DataAnnotations;

namespace Webapp.Models
{
    [JsonObject]
    public class SubscribeModel
    {
        [EmailAddress, Required]
        public string Email { get; set; }
    }
}
