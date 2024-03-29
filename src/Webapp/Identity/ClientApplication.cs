namespace Webapp.Identity
{
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.Linq;
    using GrainInterfaces;

    public class ClientApplication
    {
        public ClientApplication()
        {
            this.Tokens = new List<string>();
        }

        public ClientApplication(string clientId, ClientApplicationState appState) : this()
        {
            this.ClientId = clientId;
            this.ClientSecret = appState.Secret;
            this.DisplayName = appState.DisplayName;
            this.LogoutRedirectUri = appState.LogoutRedirectUri;
            this.RedirectUri = appState.RedirectUris.FirstOrDefault();
            this.Type = appState.Type;
        }

        [Required]
        public string ClientId { get; set; }

        [Required]
        public string ClientSecret { get; set; }

        [Required]
        public string DisplayName { get; set; }

        [Required]
        public string RedirectUri { get; set; }

        public string LogoutRedirectUri { get; set; }
        public IList<string> Tokens { get; }
        public string Type { get; set; }
    }
}