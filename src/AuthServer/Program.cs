using AuthServer.Domain.AggregatesModel.ApplicationUserAggregate;
using AuthServer.Infrastructure;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using dotenv;
using Serilog;

using West94.AuthServer.Endpoints;
using dotenv.net;
using West94.AuthServer;

Log.Logger = new LoggerConfiguration()
    .Enrich.FromLogContext()
    .WriteTo.File("logs/host-.log", 
        rollingInterval:  RollingInterval.Day,
        fileSizeLimitBytes: 1000000,
        rollOnFileSizeLimit: true,
        flushToDiskInterval: TimeSpan.FromSeconds(1),
        shared: true)
    .CreateBootstrapLogger();

DotEnv.Load(new DotEnvOptions(probeForEnv: true, probeLevelsToSearch: 5));
try 
{
    var builder = WebApplication.CreateBuilder(args);

    //
    // Add services to the container.
    builder.Services.AddDbContext<ApplicationDbContext>(options => 
    {
        var connectionString = builder.Configuration.GetConnectionString("AuthServer");

        if (string.IsNullOrWhiteSpace(connectionString)) {
            throw new InvalidOperationException("Connection string is not set");
        }

        var username = builder.Configuration["POSTGRES_USER"];
        var password = builder.Configuration["POSTGRES_PASSWORD"];
        connectionString = connectionString.Replace("{username}", username).Replace("{password}", password);

        options.UseNpgsql(connectionString, dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName));
        options.UseOpenIddict();
    });

    builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
        .AddEntityFrameworkStores<ApplicationDbContext>()
        .AddDefaultTokenProviders();
        
    builder.Services.AddOpenIddict()
    .AddCore((options) => 
    {
        options.UseEntityFrameworkCore()
            .UseDbContext<ApplicationDbContext>();
    })
    .AddServer((options) => {
        options
            .AllowAuthorizationCodeFlow()
            .AllowClientCredentialsFlow()
            .AllowRefreshTokenFlow();

        options
            .SetAuthorizationEndpointUris("connect/authorize")
            .SetTokenEndpointUris("connect/token");

        options
            .AddDevelopmentEncryptionCertificate()
            .AddDevelopmentSigningCertificate();

        options
            .UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableTokenEndpointPassthrough();
    })
    .AddValidation((options) => 
    {
        // Import the configuration from the local OpenIddict server instance.
        options.UseLocalServer();

        // Register the ASP.NET Core host.
        options.UseAspNetCore();
    });

    builder.Services.AddRazorPages();
    builder.Services.AddControllers();

    builder.Services.AddSerilog((ctx, loggerConfiguration) => 
        loggerConfiguration
            .ReadFrom.Configuration(builder.Configuration)
            .Enrich.FromLogContext()
            .WriteTo.File("logs/application-.log",
                rollingInterval: RollingInterval.Day,
                fileSizeLimitBytes: 1_000_000,
                rollOnFileSizeLimit: true,
                flushToDiskInterval: TimeSpan.FromSeconds(1),
                shared: true)
    );

    builder.Services.AddAuthorization()
        .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddCookie(options => 
        {
            options.Cookie.HttpOnly = true;
            options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
            options.SlidingExpiration = true;

            // options.LoginPath = "/Identity/Account/Login";
            // options.AccessDeniedPath = "/Identity/Account/AccessDenied";
        });

    var app = builder.Build();

    // Configure the HTTP request pipeline.
    if (!app.Environment.IsDevelopment())
    {
        app.UseExceptionHandler("/Error");
        // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
        app.UseHsts();
    }


    app.UseStaticFiles();
    app.UseSerilogRequestLogging();
    app.UseHttpsRedirection();
    app.UseRouting();

    app.UseAuthentication();
    app.UseAuthorization();

    app.MapRazorPages();
    
    app.MapGroup("/connect").MapAuthorizationEndpoints();

    if (args.Contains("/seed")) {
        Log.Information("Seeding database...");
        SeedData.EnsureSeedData(app);
        Log.Information("Done seeding database. Exiting...");
    }

    app.Run();
}
catch (Exception ex) when (ex is not HostAbortedException)
{
    Log.Fatal(ex, "Host terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}