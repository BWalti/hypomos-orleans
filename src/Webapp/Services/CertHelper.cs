namespace Webapp.Services
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;

    public class CertHelper
    {
        public static X509Certificate2 BuildTlsSelfSignedServer(string[] domains)
        {
            var sanBuilder = new SubjectAlternativeNameBuilder();
            foreach (var domain in domains)
            {
                sanBuilder.AddDnsName(domain);
            }

            using (var rsa = RSA.Create())
            {
                var request = new CertificateRequest("CN=" + domains.First(), rsa, HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);

                request.CertificateExtensions.Add(
                    new X509EnhancedKeyUsageExtension(
                        new OidCollection {new Oid("1.3.6.1.5.5.7.3.1")}, false));

                request.CertificateExtensions.Add(sanBuilder.Build());

                var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(90));

                // Hack - https://github.com/dotnet/corefx/issues/24454
                var buffer = cert.Export(X509ContentType.Pfx, (string) null);
                return new X509Certificate2(buffer, (string) null);
            }
        }
    }
}