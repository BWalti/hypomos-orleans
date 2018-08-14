namespace Webapp.Services
{
    using System;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.Logging;

    public class AcmeSettings
    {
        public AcmeSettings()
        {
            this.AcmeUri = "https://acme-v01.api.letsencrypt.org/directory";
            this.TermsOfServiceUri = "https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf";
        }

        public string EmailAddress { get; set; }
        public string TermsOfServiceUri { get; set; }
        public string PfxPassword { get; set; }
        public string AcmeUri { get; set; }
    }

    public class AcmeOptions
    {
        public AcmeSettings AcmeSettings { get; set; }

        // public IServiceProvider ApplicationServices { get; set; }
        public Func<string, Task<string>> GetChallengeResponse { get; set; } =
            challenge => Task.FromResult<string>(null);

        public Func<string, string, Task> SetChallengeResponse { get; set; } =
            (challenge, response) => Task.FromResult(0);

        public Func<string, byte[], Task> StoreCertificate { get; set; } = (domainName, certData) => Task.FromResult(0);

        public Func<string, Task<byte[]>> RetrieveCertificate { get; set; } =
            domainName => Task.FromResult<byte[]>(null);
    }

    public class AcmeResponseMiddleware
    {
        private static readonly PathString startPath = new PathString("/.well-known/acme-challenge");

        private readonly ICertificateManager certificateManager;

        // private readonly Func<string, Task<string>> challengeResponder;
        private readonly ILogger<AcmeResponseMiddleware> logger;
        private readonly RequestDelegate next;

        public AcmeResponseMiddleware(RequestDelegate next, ICertificateManager certificateManager,
            ILogger<AcmeResponseMiddleware> logger)
        {
            this.next = next;
            this.certificateManager = certificateManager;
            this.logger = logger;
        }

        public async Task Invoke(HttpContext context)
        {
            PathString requestPathId;
            var requestPath = context.Request.PathBase + context.Request.Path;
            if (requestPath.StartsWithSegments(startPath, out requestPathId))
            {
                var challenge = requestPathId.Value.TrimStart('/');
                this.logger.LogWarning($"Acme challenge received on {requestPath}, challenge id = {challenge}");

                var response = await this.certificateManager.GetChallengeResponse(challenge);

                if (!string.IsNullOrEmpty(response))
                {
                    this.logger.LogWarning($"Acme challenge response found: {response}");
                    context.Response.ContentType = "text/plain";
                    context.Response.StatusCode = 200;
                    await context.Response.WriteAsync(response);
                }
                else
                {
                    this.logger.LogError($"Error: Acme challenge response for challenge id {challenge} NOT FOUND!");
                    context.Response.StatusCode = 404;
                }
            }
            else
            {
                await this.next.Invoke(context);
            }
        }
    }
}

namespace Microsoft.AspNetCore.Hosting
{
    using Microsoft.AspNetCore.Builder;
    using Webapp.Services;

    public static class AcmeResponseExtensions
    {
        public static IApplicationBuilder UseAcmeResponse(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<AcmeResponseMiddleware>();
        }
    }
}