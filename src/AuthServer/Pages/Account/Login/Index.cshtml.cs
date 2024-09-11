using System.Collections.Immutable;

using AuthServer.Domain.AggregatesModel.ApplicationUserAggregate;

using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
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