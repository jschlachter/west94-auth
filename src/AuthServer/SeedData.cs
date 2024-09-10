using AuthServer.Domain.AggregatesModel.ApplicationUserAggregate;
using AuthServer.Infrastructure;

using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

using OpenIddict.Abstractions;

namespace West94.AuthServer;

public class SeedData
{
    public static void EnsureSeedData(WebApplication app)
    {
        using var scope = app.Services.GetRequiredService<IServiceScopeFactory>().CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        context.Database.Migrate();
        EnsureSeedData(context);
    }

    static void EnsureSeedData(ApplicationDbContext context)
    {

    }
}