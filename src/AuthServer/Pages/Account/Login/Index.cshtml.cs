using System.Collections.Immutable;
using System.Security.Claims;

using AuthServer.Domain.AggregatesModel.ApplicationUserAggregate;

using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Http.Diagnostics;
using Microsoft.Identity.Client.TelemetryCore.TelemetryClient;
using Microsoft.IdentityModel.Tokens;

using OpenIddict.Abstractions;
using OpenIddict.Client.AspNetCore;
using OpenIddict.EntityFrameworkCore.Models;

using static OpenIddict.Abstractions.OpenIddictConstants;

namespace West94.AuthServer.Pages.Login;

[AllowAnonymous]
public class Index : PageModel
{
    readonly UserManager<ApplicationUser> _userManager;
    readonly SignInManager<ApplicationUser> _signInManager;
    readonly IAuthenticationSchemeProvider _schemeProvider;
    readonly IOpenIddictApplicationManager _applicationManager;

    public ViewModel View { get; set; } = default!;

    public InputModel Input { get; set; } = default!;

    public Index (
        UserManager<ApplicationUser> userManager, 
        SignInManager<ApplicationUser> signInManager, 
        IAuthenticationSchemeProvider schemeProvider,
        IOpenIddictApplicationManager applicationManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _schemeProvider = schemeProvider;
        _applicationManager = applicationManager;
    }

    public async Task<IActionResult> OnGet(string? returnUrl)
    {
        await BuildModelAsync(returnUrl);

        if (View.IsExternalLoginOnly)
        {
            return RedirectToPage("/ExternalLogin/Challange", new { scheme = View.ExternalLoginScheme, returnUrl});
        }

        return Page();
    }

    public async Task<IActionResult> OnPost()
    {
        var request = HttpContext.GetOpenIddictClientRequest();

        if (Input.Button != "login") {
            // if the user cancels, send a result back into IdentityServer as if they 
            // denied the consent (even if this client does not require consent).
            // this will send back an access denied OIDC error response to the client.

            return RedirectToPage("~/");
        }

        if (ModelState.IsValid) 
        {
            var result = await _signInManager.PasswordSignInAsync(Input.Username!, Input.Password!, Input.RememberLogin, lockoutOnFailure: true);
            if (result.Succeeded)
            {
                var user = await _userManager.FindByNameAsync(Input.Username!);
                
                var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme);

                identity.SetClaim(ClaimTypes.Email, user!.Email);
                identity.SetClaim(ClaimTypes.Name, user!.UserName);
                identity.SetClaim(ClaimTypes.NameIdentifier, user!.Id);
                
                var properties = new AuthenticationProperties
                {
                    RedirectUri = Input!.ReturnUrl
                };

                await _signInManager.SignInAsync(user, Input.RememberLogin, CookieAuthenticationDefaults.AuthenticationScheme);
                
                return SignIn(new ClaimsPrincipal(identity), properties, CookieAuthenticationDefaults.AuthenticationScheme);
            }

            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
        }

        await BuildModelAsync(Input.ReturnUrl);
        return Page();
    }

    async Task BuildModelAsync(string? returnUrl)
    {
        Input = new InputModel
        {
            ReturnUrl = returnUrl
        };

        var schemes = await _schemeProvider.GetAllSchemesAsync();

        var providers = schemes
            .Where(x => x.DisplayName != null)
            .Select(x => new ViewModel.ExternalProvider(
                x.Name, 
                x.DisplayName
            )).ToList();

        var allowLocal = true;

        // var request = HttpContext.GetOpenIddictClientRequest();
        // var application = await _applicationManager.FindByClientIdAsync(request.ClientId);

        // if (application != null) 
        // {
        //     var properties = await _applicationManager.GetPropertiesAsync(application);
            
        //     if(properties.TryGetValue("enableLocalLogin", out var value)) 
        //     {
        //         allowLocal = value.GetBoolean();
        //     }
        // }

        View = new ViewModel
        {
            AllowRememberLogin = LoginOptions.AllowRememberLogin,
            EnableLocalLogin = allowLocal && LoginOptions.AllowLocalLogin,
            ExternalProviders = providers
        };
    }
}