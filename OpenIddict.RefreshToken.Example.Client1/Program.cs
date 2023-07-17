using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Client;
using OpenIddict.RefreshToken.Example.Client1.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("SQLServer"))
           .UseOpenIddict();
});

builder.Services.AddAuthentication(options => options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
                {
                    options.LoginPath = "/login";
                    options.ExpireTimeSpan = TimeSpan.FromMinutes(15);
                });

builder.Services.AddOpenIddict()
                .AddCore(options =>
                {
                    options.UseEntityFrameworkCore()
                           .UseDbContext<ApplicationDbContext>();
                })
                .AddClient(options =>
                {
                    options.SetRedirectionEndpointUris("/callback/login/local")
                           .SetPostLogoutRedirectionEndpointUris("/callback/logout/local")

                           .AddDevelopmentEncryptionCertificate()
                           .AddDevelopmentSigningCertificate()

                           .AllowAuthorizationCodeFlow()
                           .AllowRefreshTokenFlow()

                           .UseAspNetCore()
                            .EnableStatusCodePagesIntegration()
                            .EnableRedirectionEndpointPassthrough()
                            .EnablePostLogoutRedirectionEndpointPassthrough();

                    options.UseSystemNetHttp();

                    options.AddRegistration(new OpenIddictClientRegistration
                    {
                        Issuer = new Uri("https://localhost:7249", UriKind.Absolute),

                        ClientId = "my-client1",
                        ClientSecret = "my-client-secret1",
                        Scopes = { "read", "write", "offline_access" },

                        RedirectUri = new Uri("https://localhost:7247/callback/login/local", UriKind.Absolute),
                        PostLogoutRedirectUri = new Uri("https://localhost:7247/callback/logout/local", UriKind.Absolute)
                    }); ;
                })
                .AddValidation(options =>
                {
                    options.UseLocalServer();
                    options.UseAspNetCore();
                });

builder.Services.AddHttpClient();

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
