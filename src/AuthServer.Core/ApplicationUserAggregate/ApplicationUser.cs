using Microsoft.AspNetCore.Identity;

namespace AuthServer.Domain.AggregatesModel.ApplicationUserAggregate;

// Add profile data for application users by adding properties to the ApplicationUser class
public class ApplicationUser : IdentityUser { }