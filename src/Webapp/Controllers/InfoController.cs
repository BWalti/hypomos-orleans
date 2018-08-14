namespace Webapp.Controllers
{
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Configuration;
    using Orleans;

    // The home controller generates the initial home page, as wel as the aspnet-javascript serverside fallback pages (mostly for seo)
    public class InfoController : Controller
    {
        private readonly IClusterClient clusterClient;
        private readonly IConfiguration config;
        private readonly IHostingEnvironment env;

        public InfoController(IClusterClient clusterClient, IHostingEnvironment env, IConfiguration config)
        {
            this.clusterClient = clusterClient;
            this.env = env;
            this.config = config;
        }

        [HttpGet]
        [Route("~/info")]
        public IActionResult Index()
        {
            return this.Content($"Webapp is alive. Id = {this.config["Id"]}, Version = {this.config["Version"]}");

            // todo connect to orleanshost and get its version and Id
        }
    }
}