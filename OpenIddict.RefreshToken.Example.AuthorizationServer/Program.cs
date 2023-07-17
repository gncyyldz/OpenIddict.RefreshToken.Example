using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using OpenIddict.RefreshToken.Example.AuthorizationServer.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options => options.LoginPath = "/account/login");

builder.Services.AddOpenIddict()
    .AddCore(options => options.UseEntityFrameworkCore()
                               .UseDbContext<ApplicationDbContext>())
    .AddServer(options =>
    {
        options.SetTokenEndpointUris("/connect/token")
               .SetAuthorizationEndpointUris("/connect/authorize")
               .SetLogoutEndpointUris("/connect/logout")
               .SetUserinfoEndpointUris("/connect/userinfo")

               .AllowClientCredentialsFlow()
               .AllowAuthorizationCodeFlow()
               .AllowRefreshTokenFlow()

               .RequireProofKeyForCodeExchange()

               .AddEphemeralEncryptionKey()
               .AddEphemeralSigningKey()

               .DisableAccessTokenEncryption()

               .UseAspNetCore()

               .EnableTokenEndpointPassthrough()
               .EnableAuthorizationEndpointPassthrough()
               .EnableLogoutEndpointPassthrough()
               .EnableUserinfoEndpointPassthrough();

        options.RegisterScopes("read", "write");
    });

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("SQLServer"))
           .UseOpenIddict();
});

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
