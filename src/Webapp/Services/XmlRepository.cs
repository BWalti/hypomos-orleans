namespace Webapp.Services
{
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using System.Xml.Linq;
    using GrainInterfaces;
    using Microsoft.AspNetCore.DataProtection;
    using Microsoft.AspNetCore.DataProtection.KeyManagement;
    using Microsoft.AspNetCore.DataProtection.Repositories;
    using Microsoft.Extensions.DependencyInjection;
    using Orleans;

    public static class OrleansDataProtectionBuilderExtensions
    {
        public static IDataProtectionBuilder PersistKeysToOrleans(this IDataProtectionBuilder builder,
            IClusterClient clusterClient)
        {
            builder.Services.Configure<KeyManagementOptions>(options =>
            {
                options.XmlRepository = new OrleansXmlRepository(clusterClient);
            });
            return builder;
        }
    }

    public class OrleansXmlRepository : IXmlRepository
    {
        private const string DataProtectionKeysName = "DataProtection-Keys";
        private readonly IClusterClient grainClient;

        public OrleansXmlRepository(IClusterClient grainClient)
        {
            this.grainClient = grainClient;
        }

        public IReadOnlyCollection<XElement> GetAllElements()
        {
            return this.GetAllElementsCore().ToImmutableList();
        }

        public void StoreElement(XElement element, string friendlyName)
        {
            this.grainClient.GetGrain<IStringStoreGrain>(DataProtectionKeysName)
                .StoreString(element.ToString(SaveOptions.DisableFormatting))
                .GetAwaiter()
                .GetResult();
        }

        public IEnumerable<XElement> GetAllElementsCore()
        {
            var data = this.grainClient.GetGrain<IStringStoreGrain>(DataProtectionKeysName).GetAllStrings().GetAwaiter()
                .GetResult();

            if (data == null)
            {
            }
            else
            {
                foreach (var value in data)
                {
                    yield return XElement.Parse(value);
                }
            }
        }
    }
}