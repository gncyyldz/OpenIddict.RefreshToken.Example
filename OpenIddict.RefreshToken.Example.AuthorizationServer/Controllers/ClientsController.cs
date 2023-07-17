using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.RefreshToken.Example.AuthorizationServer.ViewModels;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.RefreshToken.Example.AuthorizationServer.Controllers
{
    public class ClientsController : Controller
    {
        readonly IOpenIddictApplicationManager _openIddictApplicationManager;

        public ClientsController(IOpenIddictApplicationManager openIddictApplicationManager)
        {
            _openIddictApplicationManager = openIddictApplicationManager;
        }

        [HttpGet]
        public async Task<IActionResult> CreateClient()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> CreateClient(ClientCreateVM model)
        {
            if (ModelState.IsValid)
            {
                var client = await _openIddictApplicationManager.FindByClientIdAsync(model.ClientId);
                if (client is null)
                {
                    await _openIddictApplicationManager.CreateAsync(new OpenIddictApplicationDescriptor
                    {
                        ClientId = model.ClientId,
                        ClientSecret = model.ClientSecret,
                        DisplayName = model.DisplayName,
                        RedirectUris = { new(model.RedirectUrl) },
                        PostLogoutRedirectUris = { new(model.PostLogoutRedirectUri) },
                        Permissions = {
                                        OpenIddictConstants.Permissions.Endpoints.Token,
                                        OpenIddictConstants.Permissions.Endpoints.Authorization,
                                        OpenIddictConstants.Permissions.Endpoints.Logout,

                                        OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                                        OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                                        OpenIddictConstants.Permissions.GrantTypes.RefreshToken,

                                        OpenIddictConstants.Permissions.Prefixes.Scope + "read",
                                        OpenIddictConstants.Permissions.Prefixes.Scope + "write",

                                        Permissions.Scopes.Email,
                                        Permissions.Scopes.Profile,
                                        Permissions.Scopes.Roles,

                                        OpenIddictConstants.Permissions.ResponseTypes.Code
                                      }
                    });
                    ViewBag.Message = "Client başarıyla oluşturulmuştur.";
                }
                else
                    ViewBag.Message = "Client zaten mevcuttur.";
                return View();
            }

            ViewBag.Message = "Lütfen client bilgilerini tam giriniz.";
            return View(model);
        }
    }
}
