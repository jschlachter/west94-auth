using OpenIddict.Abstractions;

namespace West94.AuthServer.Endpoints;

public class AuthorizationServices
{
    public ILogger<AuthorizationServices> Logger { get; }
    public IHttpContextAccessor HttpContextAccessor { get; }
    public IOpenIddictApplicationManager ApplicationManager { get; }

    public AuthorizationServices(
        ILogger<AuthorizationServices> logger,
        IHttpContextAccessor httpContextAccessor,
        IOpenIddictApplicationManager openIddictApplicationManager)
    {
        Logger = logger;
        HttpContextAccessor = httpContextAccessor;
        ApplicationManager = openIddictApplicationManager;
    }
}