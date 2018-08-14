namespace Webapp.Models
{
    using Newtonsoft.Json;

    [JsonObject]
    public class XsrfModel
    {
        public string XsrfToken { get; set; }
    }
}