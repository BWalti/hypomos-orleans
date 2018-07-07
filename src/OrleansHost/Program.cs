namespace OrleansHost
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Runtime.Loader;
    using System.Threading;
    using System.Threading.Tasks;

    using GrainInterfaces;

    using Grains;
    using Grains.Redux;

    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Logging;

    using Orleans;
    using Orleans.Clustering.Kubernetes;
    using Orleans.Configuration;
    using Orleans.Hosting;
    using Orleans.Runtime;

    internal class Program
    {
        private static readonly ManualResetEvent StopSilo = new ManualResetEvent(false);

        private static async Task Main(string[] args)
        {
            var environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Development";

            ISiloHost silo;
            try
            {
                // string connectionString = config.GetConnectionString("DataConnectionString");
                silo = new SiloHostBuilder().UseEnvironment(environment).ConfigureLogging((context, logging) =>
                {
                    logging.AddConfiguration(context.Configuration.GetSection("Logging"));
                    logging.AddConsole();
                    logging.AddDebug();
                }).ConfigureAppConfiguration((context, builder) =>
                {
                    builder.SetBasePath(Directory.GetCurrentDirectory())
                    .AddInMemoryCollection(new
                                           Dictionary<string, string
                                           > // add default settings, that will be overridden by commandline
                                           {
                                           { "Id", "OrleansHost" },
                                           { "Version", "1.0.0" },
                                           { "ClusterId", "rrod-cluster" },
                                           { "ServiceId", "rrod" }
                                           }).AddCommandLine(args).AddJsonFile("OrleansHost.settings.json", true, true)
                    .AddJsonFile($"OrleansHost.settings.{environment}.json", true, true)
                    .AddJsonFile("/run/config/OrleansHost.settings.json", true, true)
                    .AddDockerSecrets("/run/secrets", true) // we can pas connectionstring as a docker secret
                    .AddUserSecrets<Program>(true) // for development
                    .AddEnvironmentVariables("RROD_"); // can override all settings (i.e. URLS) by passing an environment variable
                }).AddStartupTask<SettingsLogger>()
                .UseKubeMembership(opts => { opts.CanCreateResources = true; })
                
                //.UseAzureStorageClustering(builder => builder.Configure((AzureStorageClusteringOptions options, IConfiguration cfg) => options.ConnectionString = cfg.GetConnectionString("DataConnectionString")))
                .UseAdoNetClustering(builder => builder
                                     .Configure((AdoNetClusteringSiloOptions opts, IConfiguration cfg) =>
                                                {
                                                    opts.ConnectionString = cfg.GetConnectionString("DataConnectionString");
                                                    opts.Invariant = "adoClustering";
                                                }))

                .ConfigureEndpoints(11111, 30000)
                .ConfigureServices((context, services) =>
                {
                    var config = context.Configuration;

                    var dataConnectionString = config.GetConnectionString("DataConnectionString");
                    var reduxConnectionString = config.GetConnectionString("ReduxConnectionString");

                    services.AddOptions();
                    services.Configure<ClusterOptions>(config);
                    //services.UseAzureTableReminderService(options => options.ConnectionString = dataConnectionString);
                    services.UseAdoNetReminderService(options => options.Configure(ropts => ropts.ConnectionString = dataConnectionString));
                    services.AddSingleton(new ReduxTableStorage<CertState>(reduxConnectionString));
                    services.AddSingleton(new ReduxTableStorage<UserState>(reduxConnectionString));
                    services.AddSingleton(new ReduxTableStorage<CounterState>(reduxConnectionString));
                    services.AddSingleton(new ReduxTableStorage<StringStoreState>(reduxConnectionString));
                }).ConfigureApplicationParts(parts =>
                {
                    parts.AddApplicationPart(typeof(CounterGrain).Assembly).WithReferences();
                    //parts.AddApplicationPart(typeof(AzureQueueDataAdapterV2).Assembly).WithReferences();
                })
                .AddMemoryGrainStorage("memoryStorage")
                .AddAdoNetGrainStorageAsDefault(builder => builder.Configure((AdoNetGrainStorageOptions opts, IConfiguration cfg) => opts.ConnectionString = cfg.GetConnectionString("DataConnectionString")))
                .AddAdoNetGrainStorage("PubSubStore", builder => builder.Configure((AdoNetGrainStorageOptions opts, IConfiguration cfg) => opts.ConnectionString = cfg.GetConnectionString("DataConnectionString")))
                //.AddAzureTableGrainStorageAsDefault(builder => builder.Configure((AzureTableStorageOptions options, IConfiguration cfg) => options.ConnectionString = cfg.GetConnectionString("DataConnectionString")))
                //.AddAzureTableGrainStorage("PubSubStore", builder => builder.Configure((AzureTableStorageOptions options, IConfiguration cfg) => options.ConnectionString = cfg.GetConnectionString("DataConnectionString")))
                //.AddAzureQueueStreams<AzureQueueDataAdapterV2>("Default", builder => builder.Configure((AzureQueueOptions options, IConfiguration cfg) => options.ConnectionString = cfg.GetConnectionString("DataConnectionString")))
                .Build();
            }
            catch (Exception e)
            {
                Console.WriteLine("Error building silo host: " + e.Message);
                throw;
            }

            // If our process is stopped, close the silo nicely so active grains get deactivated
            AssemblyLoadContext.Default.Unloading += context => { StopSilo.Set(); };

            // Make Ctrl-C stop our process
            Console.CancelKeyPress += (sender, e) => { Environment.Exit(0); };

            try
            {
                Console.WriteLine("Silo starting...");
                await silo.StartAsync();
                Console.WriteLine("Silo started");

                StopSilo.WaitOne();

                Console.WriteLine("Silo stopping...");
                await silo.StopAsync();
                Console.WriteLine("Silo Stopped");
            }
            catch (OrleansLifecycleCanceledException e)
            {
                Console.WriteLine("Silo could not be started with exception: " + e.InnerException.Message);
            }
            catch (Exception e)
            {
                Console.WriteLine("Silo could not be started with exception: " + e.Message);
            }
        }
    }

    internal class SettingsLogger : IStartupTask
    {
        private readonly IConfigurationRoot config;

        private readonly ILogger logger;

        public SettingsLogger(IConfiguration config, ILogger<SettingsLogger> logger)
        {
            this.config = config as IConfigurationRoot;
            this.logger = logger;
        }

        public Task Execute(CancellationToken cancellationToken)
        {
            foreach (var provider in this.config.Providers)
                this.logger
                .LogInformation($"Config Provider {provider.GetType().Name}: {provider.GetChildKeys(Enumerable.Empty<string>(), null).Count()} settings");
            return Task.CompletedTask;
        }
    }
}