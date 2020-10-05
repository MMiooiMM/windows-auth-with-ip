using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace windowsauth.ap.Middlewares
{
    public class JwtValidationMiddleware
    {
        private readonly RequestDelegate _next;

        public JwtValidationMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            var tokenIp = context.User.Claims.FirstOrDefault(x => x.Type == "ip")?.Value;
            if (string.IsNullOrEmpty(tokenIp))
            {
                await context.Response.WriteAsync("Valid Error.");
                return;
            }

            var connectionIp = context.Connection.RemoteIpAddress.ToString();
            if (tokenIp != connectionIp)
            {
                await context.Response.WriteAsync("Valid Error.");
                return;
            }
            await _next(context);
        }
    }
}