using Auth;
using Auth.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using System.IdentityModel.Tokens.Jwt;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Controllers
{
    [Route("[controller]/[action]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        // POST: auth/login
        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> Login([FromBody] LoginUser user)
        {
            if (string.IsNullOrEmpty(user.UserName))
            {
                return BadRequest(new { message = "Email address needs to entered" });
            }
            else if (string.IsNullOrEmpty(user.Password))
            {
                return BadRequest(new { message = "Password needs to entered" });
            }

            var loggedInUser = await _authService.Login(user.UserName, user.Password, "read:user-info read:files");

            if (loggedInUser != null)
            {
                Response.Cookies.Append("token", loggedInUser.Token, new CookieOptions()
                {
                    Domain = ".azurewebsites.net",
                    SameSite = SameSiteMode.None,
                    Secure = true,
                    MaxAge = TimeSpan.FromMinutes(30),
                });

                return Ok(loggedInUser);
            }

            return BadRequest(new { message = "User login unsuccessful" });
        }

        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> LoginForm([FromForm] string username, [FromForm] string password, [FromForm] string redirectTo)
        {
            var res = await this.Login(new LoginUser
            {
                UserName = username,
                Password = password
            });

            return Redirect(redirectTo);
        }

        // POST: auth/register
        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> Register([FromBody] RegisterUser user)
        {
            if (string.IsNullOrEmpty(user.Name))
            {
                return BadRequest(new { message = "Name needs to entered" });
            }
            else if (string.IsNullOrEmpty(user.UserName))
            {
                return BadRequest(new { message = "User name needs to entered" });
            }
            else if (string.IsNullOrEmpty(user.Password))
            {
                return BadRequest(new { message = "Password needs to entered" });
            }

            User userToRegister = new(user.UserName, user.Name, user.Password, user.Role);

            User registeredUser = await _authService.Register(userToRegister);

            User loggedInUser = await _authService.Login(registeredUser.UserName, user.Password, "read:user-info read:files");

            if (loggedInUser != null)
            {
                Response.Cookies.Append("token", loggedInUser.Token, new CookieOptions()
                {
                    Domain = ".azurewebsites.net",
                    SameSite = SameSiteMode.None,
                    Secure = true,
                    MaxAge = TimeSpan.FromMinutes(30),
                });

                return Ok(loggedInUser);
            }

            return BadRequest(new { message = "User registration unsuccessful" });
        }

        [AllowAnonymous]
        [HttpGet]
        public IActionResult UserInfoJs()
        {
            if (Request.Cookies.Any(pair => string.Compare(pair.Key, "token", StringComparison.InvariantCultureIgnoreCase) == 0))
            {
                var token = Request.Cookies["token"];

                return Content($"document.cookie='token={token}';", "application/javascript");
            }

            return Content("", "application/javascript");
        }

        // GET: auth/test
        [Authorize(Roles = "Everyone")]
        [HttpGet]
        public IActionResult Test()
        {
            var token = Request.Headers.TryGetValue("Authorization", out var authToken) ? authToken.ToString()
             : Request.Cookies.TryGetValue("token", out var value) ? value
             : string.Empty;

            if (token.StartsWith("Bearer"))
            {
                token = token.Substring("Bearer ".Length).Trim();
            }
            var handler = new JwtSecurityTokenHandler();

            JwtSecurityToken jwt = handler.ReadJwtToken(token);

            var claims = new Dictionary<string, string>();

            foreach (var claim in jwt.Claims)
            {
                claims.Add(claim.Type, claim.Value);
            }

            return Ok(claims);
        }
        // GET: auth/test-scope
        [Authorize("read:user-info")]
        [HttpGet]
        [ActionName("user-info")]
        public IActionResult UserInfo()
        {
            var token = Request.Headers.TryGetValue("Authorization", out var authToken) ? authToken.ToString()
             : Request.Cookies.TryGetValue("token", out var value) ? value
             : string.Empty;

            if (token.StartsWith("Bearer"))
            {
                token = token.Substring("Bearer ".Length).Trim();
            }
            var handler = new JwtSecurityTokenHandler();

            JwtSecurityToken jwt = handler.ReadJwtToken(token);

            var claims = new Dictionary<string, string>();

            foreach (var claim in jwt.Claims)
            {
                claims.Add(claim.Type, claim.Value);
            }

            return Ok(claims);
        }
    }
}