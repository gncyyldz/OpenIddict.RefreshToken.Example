using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Client.AspNetCore;
using System.Diagnostics;

namespace OpenIddict.RefreshToken.Example.Client1.Controllers
{
    public class HomeController : Controller
    {
        readonly IHttpClientFactory _httpClientFactory;

        public HomeController(IHttpClientFactory httpClientFactory)
            => _httpClientFactory = httpClientFactory;

        public async Task<IActionResult> Index()
        {
            AuthenticateResult authenticateResult = await HttpContext.AuthenticateAsync();
            var properties = authenticateResult?.Properties?.Items.OrderBy(p => p.Key);
            ViewBag.Properties = properties;
            return View();
        }

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> Index(string button, CancellationToken cancellationToken)
        {
            string? token = await HttpContext.GetTokenAsync(CookieAuthenticationDefaults.AuthenticationScheme, OpenIddictClientAspNetCoreConstants.Tokens.BackchannelAccessToken);

            using HttpClient httpClient = _httpClientFactory.CreateClient();
            httpClient.DefaultRequestHeaders.Authorization = new("Bearer", token);

            using HttpRequestMessage httpRequestMessage = new(button == "GET" ? HttpMethod.Get : HttpMethod.Post, "https://localhost:7260/api/values");
            using HttpResponseMessage httpResponseMessage = await httpClient.SendAsync(httpRequestMessage, cancellationToken);
            return View(model: await httpResponseMessage.Content.ReadAsStringAsync(cancellationToken));
        }
    }
}