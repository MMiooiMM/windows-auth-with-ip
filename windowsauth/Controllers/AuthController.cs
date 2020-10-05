using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace windowsauth.Controllers
{
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public AuthController(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        [HttpGet]
        public string Get()
        {
            var ip = _httpContextAccessor.HttpContext.Connection.RemoteIpAddress.ToString();
            var name = User.Identity.Name;
            return GenerateToken(ip, name);
        }

        private string GenerateToken(string ip, string userName, int expireMinutes = 30)
        {
            var issuer = "issuer";
            var signKey = "1234567890123456";

            // 設定要加入到 JWT Token 中的聲明資訊(Claims)
            var claims = new List<Claim>
            {
                // 在 RFC 7519 規格中(Section#4)，總共定義了 7 個預設的 Claims，我們應該只用的到兩種！
                //claims.Add(new Claim(JwtRegisteredClaimNames.Iss, issuer));
                new Claim(JwtRegisteredClaimNames.Sub, userName), // User.Identity.Name
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // JWT ID

                // 這個 Claim 也以直接被 JwtRegisteredClaimNames.Sub 取代，所以也是多餘的
                // claims.Add(new Claim(ClaimTypes.Name, userName));
                new Claim("ip", ip)
            };

            var userClaimsIdentity = new ClaimsIdentity(claims);

            // 建立一組對稱式加密的金鑰，主要用於 JWT 簽章之用
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signKey));

            // HmacSha256 有要求必須要大於 128 bits，所以 key 不能太短，至少要 16 字元以上
            // https://stackoverflow.com/questions/47279947/idx10603-the-algorithm-hs256-requires-the-securitykey-keysize-to-be-greater
            var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);

            // 建立 SecurityTokenDescriptor
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = issuer,
                //Audience = issuer, // 由於你的 API 受眾通常沒有區分特別對象，因此通常不太需要設定，也不太需要驗證
                //NotBefore = DateTime.Now, // 預設值就是 DateTime.Now
                //IssuedAt = DateTime.Now, // 預設值就是 DateTime.Now
                Subject = userClaimsIdentity,
                Expires = DateTime.Now.AddMinutes(expireMinutes),
                SigningCredentials = signingCredentials
            };

            // 產出所需要的 JWT securityToken 物件，並取得序列化後的 Token 結果(字串格式)
            var tokenHandler = new JwtSecurityTokenHandler();
            var securityToken = tokenHandler.CreateToken(tokenDescriptor);
            var serializeToken = tokenHandler.WriteToken(securityToken);

            return serializeToken;
        }
    }
}