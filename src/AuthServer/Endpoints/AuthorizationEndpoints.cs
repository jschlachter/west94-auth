using System.Security.Claims;
using System.Security.Cryptography;

using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

using static OpenIddict.Abstractions.OpenIddictConstants;

namespace West94.AuthServer.Endpoints;

public static class AuthorizationEndpoints
{
    public static RouteGroupBuilder MapAuthorizationEndpoints(this RouteGroupBuilder app)
    {
        app.MapPost("/token", Exchange);

        return app;
    }

    public static async Task<SignInHttpResult> Exchange([FromServices] AuthorizationServices services)
    {
        HttpContext httpContext = services.HttpContextAccessor.HttpContext ?? throw new InvalidOperationException("Method can only be invoked as part of an HTTP request.");
        var request = httpContext.GetOpenIddictClientRequest() ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (request.IsClientCredentialsGrantType())
        {
            var application = await services.ApplicationManager.FindByClientIdAsync(request.ClientId) ?? throw new InvalidOperationException("The application cannot be found.");

            var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);

            identity.SetClaim(Claims.Subject,await services.ApplicationManager.GetIdAsync(application));
            identity.SetClaim(Claims.Name, await services.ApplicationManager.GetDisplayNameAsync(application));

            identity.SetDestinations(static claim => claim.Type switch
            {
                // Allow the "name" claim to be stored in both the access and identity tokens
                // when the "profile" scope was granted (by calling principal.SetScopes(...)).
                Claims.Name when claim.Subject.HasScope(Scopes.Profile) => [Destinations.AccessToken, Destinations.IdentityToken],

                // Otherwise, only store the claim in the access tokens.
                _ => [Destinations.AccessToken]
            });
            
            return TypedResults.SignIn(new ClaimsPrincipal(identity), authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        throw new InvalidOperationException("The specified grant type is not supported.");
    }
}