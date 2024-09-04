using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;

using Serilog;

using West94.AuthServer.Endpoints;

Log.Logger = new LoggerConfiguration()
    .Enrich.FromLogContext()
    .WriteTo.File("logs/host-.log", 
        rollingInterval:  RollingInterval.Day,
        fileSizeLimitBytes: 1000000,
        rollOnFileSizeLimit: true,
        flushToDiskInterval: TimeSpan.FromSeconds(1),
        shared: true)
    .CreateBootstrapLogger();

try 
{
    var builder = WebApplication.CreateBuilder(args);

    //
    // Add services to the container.

    builder.Services.AddOpenIddict()
    .AddCore((options) => {
        
    })
    .AddServer((options) => {
        options.SetTokenEndpointUris("connect/token");
        options.AllowClientCredentialsFlow();

        options
            .AddDevelopmentEncryptionCertificate()
            .AddDevelopmentSigningCertificate();

        options
            .UseAspNetCore()
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
        .AddCookie();

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