using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace windowsauth.ap.Handlers
{
    public class CustomJwtSecurityTokenHandler : ISecurityTokenValidator
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly JwtSecurityTokenHandler _jwtSecurityTokenHandler;

        public CustomJwtSecurityTokenHandler(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
            _jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
        }

        public bool CanValidateToken => true;

        public int MaximumTokenSizeInBytes { get; set; } = TokenValidationParameters.DefaultMaximumTokenSizeInBytes;

        public bool CanReadToken(string securityToken)
        {
            return _jwtSecurityTokenHandler.CanReadToken(securityToken);
        }

        public ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
        {
            var token = _jwtSecurityTokenHandler.ReadToken(securityToken) as JwtSecurityToken;
            validatedToken = token;
            var ip = token.Claims.FirstOrDefault(claim => claim.Type == "ip");

            if (ip is null)
            {
                throw new SecurityTokenException();
            }

            var httpContextAccessor = _serviceProvider.GetService<IHttpContextAccessor>();

            if (ip.Value != httpContextAccessor.HttpContext.Connection.RemoteIpAddress.ToString())
            {
                throw new SecurityTokenValidationException();
            }

            return _jwtSecurityTokenHandler.ValidateToken(securityToken, validationParameters, out validatedToken);
        }
    }
}