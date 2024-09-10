using System.Collections.Immutable;

using AuthServer.Domain.AggregatesModel.ApplicationUserAggregate;

using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.RazorPages;

using OpenIddict.Abstractions;
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

    public ViewModel ViewModel { get; set; } = default!;

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

        var request = HttpContext.GetOpenIddictClientRequest();
        var application = await _applicationManager.FindByClientIdAsync(request.ClientId);

        if (application != null) 
        {
            var properties = await _applicationManager.GetPropertiesAsync(application);
            
            if(properties.TryGetValue("enableLocalLogin", out var value)) 
            {
                allowLocal = value.GetBoolean();
            }
        }

        ViewModel = new ViewModel
        {
            AllowRememberLogin = LoginOptions.AllowRememberLogin,
            EnableLocalLogin = allowLocal && LoginOptions.AllowLocalLogin,
            ExternalProviders = providers
        };
    }
}