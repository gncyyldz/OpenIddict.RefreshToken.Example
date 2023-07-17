using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using OpenIddict.Client.AspNetCore;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.RefreshToken.Example.Client1.Controllers
{
    public class AuthenticationController : Controller
    {
        [HttpGet("~/login")]
        public IActionResult LogIn(string returnUrl)
        {
            var properties = new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictClientAspNetCoreConstants.Properties.Issuer] = "https://localhost:7249"
            });
            properties.RedirectUri = Url.IsLocalUrl(returnUrl) ? returnUrl : "/";

            //Challenge metodu ile OpenIddict middleware'ı sayesinde ilgili Issuer'a karşılık gelen client bilgilerini authorization server'a yönlendiriyoruz.
            return Challenge(properties, OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
        }

        [HttpPost("~/logout"), ValidateAntiForgeryToken]
        public async Task<ActionResult> LogOut(string returnUrl)
        {
            //Elde bulunan authentication cookie bilgilerini elde ediyoruz. Eğer yoksa zaten kullanıcının henüz oturum açmadığını anlıyoruz.
            var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (result is not { Succeeded: true })
                return Redirect(Url.IsLocalUrl(returnUrl) ? returnUrl : "/");

            //SignOut yaparak mevcut authentication cookie bilgilerini temizliyoruz.
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            var properties = new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictClientAspNetCoreConstants.Properties.Issuer] = "https://localhost:7249",
                [OpenIddictClientAspNetCoreConstants.Properties.IdentityTokenHint] = result.Properties.GetTokenValue(OpenIddictClientAspNetCoreConstants.Tokens.BackchannelIdentityToken)
            });
            properties.RedirectUri = Url.IsLocalUrl(returnUrl) ? returnUrl : "/";

            return SignOut(properties, OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
        }

        [HttpGet("~/callback/login/{provider}"), HttpPost("~/callback/login/{provider}"), IgnoreAntiforgeryToken]
        public async Task<ActionResult> LogInCallback()
        {
            // OpenIddict tarafından doğrulanan yetkilendirme verilerini elde ediyoruz.
            var result = await HttpContext.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);

            if (result.Principal.Identity is not ClaimsIdentity { IsAuthenticated: true })
                throw new InvalidOperationException("The external authorization data cannot be used for authentication.");

            var claims = new List<Claim>(result.Principal.Claims
                             .Select(claim => claim switch
                             {
                                 { Type: Claims.Subject } => new Claim(ClaimTypes.NameIdentifier, claim.Value, claim.ValueType, claim.Issuer),
                                 { Type: Claims.Name } => new Claim(ClaimTypes.Name, claim.Value, claim.ValueType, claim.Issuer),
                                 _ => claim
                             }));

            var identity = new ClaimsIdentity(claims,
                authenticationType: CookieAuthenticationDefaults.AuthenticationScheme,
                nameType: ClaimTypes.Name,
                roleType: ClaimTypes.Role);

            var properties = new AuthenticationProperties(result.Properties.Items);

            //Gerekirse authorization server tarafından döndürülen tokenlar authentication cookie'de de saklanabilir.
            properties.StoreTokens(result.Properties.GetTokens().Where(token => token switch
            {
                {
                    Name: OpenIddictClientAspNetCoreConstants.Tokens.BackchannelAccessToken or
                          OpenIddictClientAspNetCoreConstants.Tokens.BackchannelIdentityToken or
                          OpenIddictClientAspNetCoreConstants.Tokens.RefreshToken
                } => true,
                _ => false
            }));

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity), properties);

            return Redirect(properties.RedirectUri);
        }

        [HttpGet("~/callback/logout/{provider}"), HttpPost("~/callback/logout/{provider}"), IgnoreAntiforgeryToken]
        public async Task<ActionResult> LogOutCallback()
        {
            var result = await HttpContext.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
            return Redirect(result!.Properties!.RedirectUri);
        }

        [HttpGet("~/refresh")]
        //IdentityModel
        public async Task<IActionResult> Refresh()
        {
            string refreshToken = await HttpContext.GetTokenAsync(OpenIddictClientAspNetCoreConstants.Tokens.RefreshToken);
            HttpClient httpClient = new HttpClient();
            RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest()
            {
                ClientId = "my-client1",
                ClientSecret = "my-client-secret1",
                RefreshToken = refreshToken,
                Address = (await httpClient.GetDiscoveryDocumentAsync("https://localhost:7249")).TokenEndpoint
            };
            TokenResponse tokenResponse = await httpClient.RequestRefreshTokenAsync(refreshTokenRequest);
            AuthenticationProperties properties = (await HttpContext.AuthenticateAsync()).Properties;

            properties.StoreTokens(
                new List<AuthenticationToken> {
              new AuthenticationToken
                                     {
                                         Name = OpenIddictClientAspNetCoreConstants.Tokens.BackchannelIdentityToken,
                                         Value = tokenResponse.IdentityToken
                                     },
              new AuthenticationToken
                                     {
                                         Name = OpenIddictClientAspNetCoreConstants.Tokens.BackchannelAccessToken,
                                         Value = tokenResponse.AccessToken
                                     },
              new AuthenticationToken
                                     {
                                         Name = OpenIddictClientAspNetCoreConstants.Tokens.RefreshToken,
                                         Value = tokenResponse.RefreshToken
                                     },
              new AuthenticationToken
                                     {
                                         Name = OpenIdConnectParameterNames.ExpiresIn,
                                         Value = DateTime.UtcNow.AddSeconds(tokenResponse.ExpiresIn).ToString("O")
                                     },
                                       });
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, (await HttpContext.AuthenticateAsync()).Principal, properties);
            return RedirectToAction("Index", "Home");
        }
    }
}
