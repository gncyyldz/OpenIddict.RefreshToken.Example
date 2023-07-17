using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace OpenIddict.RefreshToken.Example.API1.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ValuesController : ControllerBase
    {
        [HttpGet]
        [Authorize("AccessReadPolicy")]
        public IActionResult Get()
        {
            return Ok("Read");
        }
        [HttpPost]
        [Authorize("AccessWritePolicy")]
        public IActionResult Post()
        {
            return Ok("Write");
        }
    }
}
