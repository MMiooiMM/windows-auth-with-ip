using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace windowsauth.ap.Controllers
{
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class UserController : ControllerBase
    {
        [HttpGet]
        public string Get()
        {
            return User.Identity.Name;
        }
    }
}