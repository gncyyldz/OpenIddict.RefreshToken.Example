using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using OpenIddict.RefreshToken.Example.AuthorizationServer.ViewModels;
using Microsoft.AspNetCore.Authorization;

namespace OpenIddict.RefreshToken.Example.AuthorizationServer.Controllers
{
    public class AuthorizationController : Controller
    {
        readonly IOpenIddictApplicationManager _applicationManager;
        public AuthorizationController(IOpenIddictApplicationManager applicationManager)
        {
            _applicationManager = applicationManager;
        }

        [HttpPost("~/connect/token")]
        public async Task<IActionResult> Exchange()
        {
            var request = HttpContext.GetOpenIddictServerRequest();
            ClaimsPrincipal principal = null;
            if (request?.IsAuthorizationCodeFlow() is not null)
            {
                //Authorization Code'da store edilen request sorumlusunu elde ediyoruz.
                principal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;
                principal.AddClaim(Claims.Name, "Gençay");
                principal.AddClaim(Claims.Profile, "Gençay Profile");
                principal.AddClaim(Claims.Email, "Gençay Email");
                principal.AddClaim("ornek-claim", "Örnek Claim");
                principal.AddClaim(JwtRegisteredClaimNames.Aud, "Example-OpenIddict");

                foreach (var claim in principal.Claims)
                    claim.SetDestinations(Destinations.AccessToken, Destinations.IdentityToken);

                //Principal'ı yani kullanıcı doğrula...
                //if ((await _userManager.GetUserAsync(principal)) != null)
                //{
                //    ...
                //}
            }
            else if (request?.IsRefreshTokenGrantType() is not null)
            {
                principal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;

                principal.AddClaim(Claims.Name, "Gençay");
                principal.AddClaim(Claims.Profile, "Gençay Profile");
                principal.AddClaim(Claims.Email, "Gençay Email");
                principal.AddClaim("ornek-claim", "Örnek Claim");
                principal.AddClaim(JwtRegisteredClaimNames.Aud, "Example-OpenIddict");

                foreach (var claim in principal.Claims)
                    claim.SetDestinations(Destinations.AccessToken, Destinations.IdentityToken);

                //Principal'ı yani kullanıcıyı doğrula
                //if ((await _userManager.GetUserAsnyc(principal)) != null)
                //{

                //}
            }
            else if (request?.IsClientCredentialsGrantType() is not null)
            {
                //Client credentials OpenIddict tarafından otomatik olarak doğrulanır.
                //Eğer ki gelen request'in body'sindeki client_id veya client_secret bilgileri geçersizse, burası tetiklenmeyecektir.

                var application = await _applicationManager.FindByClientIdAsync(request.ClientId);
                if (application is null)
                    throw new InvalidOperationException("This clientId was not found");

                var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

                //Token'a claim'leri ekleyelim. Subject'in eklenmesi zorunludur.
                //Destination'lar ile claim'lerin hangi token'a ekleneceğini belirtiyoruz. AccessToken mı? Identity Token mı? Yoksa her ikisi de mi?

                identity.AddClaim(Claims.Subject, (await _applicationManager.GetClientIdAsync(application) ?? throw new InvalidOperationException()));
                identity.AddClaim(Claims.Name, (await _applicationManager.GetDisplayNameAsync(application) ?? throw new InvalidOperationException()));
                identity.AddClaim("ozel-claim", "ozel-claim-value");
                identity.AddClaim(JwtRegisteredClaimNames.Aud, "Example-OpenIddict");

                principal = new ClaimsPrincipal(identity);

                foreach (var claim in principal.Claims)
                    claim.SetDestinations(Destinations.AccessToken, Destinations.IdentityToken);

                principal.SetScopes(request.GetScopes());

                //SignIn return etmek, biryandan OpenIddict'ten uygun access/identity token talebinde bulunmaktır.
            }
            else
                throw new NotImplementedException("The specified grant type is not implemented.");
            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        [HttpGet("~/connect/authorize"), HttpPost("~/connect/authorize")]
        public async Task<IActionResult> Authorize(string accept, string deny)
        {
            var request = HttpContext.GetOpenIddictServerRequest() ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");
            //Cookie'de authentication için tutulan veriden kullanıcı bilgisini alıyoruz.
            var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            //Eğer kullanıcı bilgisi yoksa kullanıcıyı login sayfasına yönlendiriyoruz.
            if (!result.Succeeded)
                return Challenge(authenticationSchemes: CookieAuthenticationDefaults.AuthenticationScheme,
                                properties: new AuthenticationProperties()
                                {
                                    RedirectUri = $"{Request.PathBase}{Request.Path}{(QueryString.Create(Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList()))}"
                                });

            var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIddictConstants.Claims.Subject, result.Principal.Identity.Name);
            identity.AddClaim(JwtRegisteredClaimNames.Aud, "Example-OpenIddict");
            identity.AddClaim("ornek-claim", "ornek claim value");

            var application = await _applicationManager.FindByClientIdAsync(request.ClientId);
            if (HttpContext.Request.Method == "GET")
                return View(new AuthorizeVM
                {
                    ApplicationName = await _applicationManager.GetLocalizedDisplayNameAsync(application),
                    Scopes = request.Scope
                });
            else if (!string.IsNullOrEmpty(accept))
            {
                var claimsPrincipal = new ClaimsPrincipal(identity);

                claimsPrincipal.SetDestinations(static claim => claim.Type switch
                {
                    Claims.Subject or "ornek-claim" => new[] { Destinations.AccessToken },
                    _ => new[] { Destinations.AccessToken, Destinations.IdentityToken }
                });

                //ya da

                //foreach (Claim claim in claimsPrincipal.Claims)
                //{
                //    claim.SetDestinations(claim.Type switch
                //    {
                //        Claims.Subject => new[] { Destinations.AccessToken },
                //        _ => new[] { Destinations.AccessToken, Destinations.IdentityToken }
                //    });
                //}

                claimsPrincipal.SetScopes(request.GetScopes());

                return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            return Forbid(authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                          properties: new AuthenticationProperties(new Dictionary<string, string>
                          {
                              [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidScope
                          }));
        }

        [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
        [HttpGet("~/connect/userinfo")]
        public async Task<IActionResult> UserInfo()
        {
            var claimPrincipal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;

            return Ok(new
            {
                //Authorization Code Flow yetkilendirmede 'The mandatory 'sub' claim cannot be found in the specified userinfo response/token.' hatasını almamak için UserInfo'dan geri döndürülen nesne içerisinde 'Sub' property'si bulunmak mecburiyetindedir.
                Sub = claimPrincipal.GetClaim(OpenIddictConstants.Claims.Subject),
                Aud = claimPrincipal.GetClaim(OpenIddictConstants.Claims.Audience),
                A = claimPrincipal.GetClaim("a"),
                B = claimPrincipal.GetClaim("b"),
                OrnekClaim = claimPrincipal.GetClaim("ornek-claim"),
                OzelClaim = claimPrincipal.GetClaim("ozel-claim")
            });
        }

        [HttpGet("~/connect/logout")]
        public IActionResult Logout() => SignOut(
         authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
         properties: new AuthenticationProperties
         {
             RedirectUri = "/"
         });
    }
}
