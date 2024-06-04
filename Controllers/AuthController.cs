using Auth;
using Auth.Models;
using Idm.Endpoints;
using Idm.OauthRequest;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Primitives;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Json;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Controllers;

[Route("[controller]/[action]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IAuthService _authService;
    private readonly CookieOptions cookieOptions;
    private readonly IConfiguration _configuration;

    public AuthController(IAuthService authService, IHttpContextAccessor httpContextAccessor, IConfiguration configuration)
    {
        _authService = authService;
        _httpContextAccessor = httpContextAccessor;
        _configuration = configuration;
        this.cookieOptions = new CookieOptions()
        {
            SameSite = SameSiteMode.None,
            Secure = true,
            HttpOnly = false,
            MaxAge = TimeSpan.FromMinutes(30)
        };
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
            Response.Cookies.Append("token", loggedInUser.Token, this.cookieOptions);
            Response.Cookies.Append("x-token", loggedInUser.Token, new CookieOptions
            {
                SameSite = SameSiteMode.None,
                Secure = this.cookieOptions.Secure,
                HttpOnly = this.cookieOptions.HttpOnly,
                MaxAge = this.cookieOptions.MaxAge,
                Domain = ".azurewebsites.net"
            });
            Response.Headers.Append("Authorization", loggedInUser.Token);

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
            Response.Cookies.Append("token", loggedInUser.Token, this.cookieOptions);

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

    // .well-known/openid-configuration
    [HttpGet("~/.well-known/openid-configuration")]
    [AllowAnonymous]
    public IActionResult GetConfiguration()
    {
        var jwtIssuer = _configuration["JWT:Issuer"];
        var response = new DiscoveryResponse
        {
            issuer = jwtIssuer,
            authorization_endpoint = $"{jwtIssuer}/Auth/Authorize",
            token_endpoint = $"{jwtIssuer}/Auth/Token",
            token_endpoint_auth_methods_supported = ["client_secret_basic", "private_key_jwt"],
            token_endpoint_auth_signing_alg_values_supported = ["RS256", "ES256"],

            acr_values_supported = ["urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:bronze"],
            response_types_supported = ["code", "code id_token", "id_token", "token id_token"],
            subject_types_supported = ["public", "pairwise"],

            userinfo_encryption_enc_values_supported = ["A128CBC-HS256", "A128GCM"],
            id_token_signing_alg_values_supported = ["RS256", "ES256", "HS256"],
            id_token_encryption_alg_values_supported = ["RSA1_5", "A128KW"],
            id_token_encryption_enc_values_supported = ["A128CBC-HS256", "A128GCM"],
            request_object_signing_alg_values_supported = ["none", "RS256", "ES256"],
            display_values_supported = ["page", "popup"],
            claim_types_supported = ["normal", "distributed"],

            scopes_supported = ["openid", "profile", "email", "address", "phone", "offline_access"],
            claims_supported = [ "sub", "iss", "auth_time", "acr", "name", "given_name",
                    "family_name", "nickname", "profile", "picture", "website", "email", "email_verified",
                    "locale", "zoneinfo" ],
            claims_parameter_supported = true,
            service_documentation = $"{jwtIssuer}/connect/service_documentation.html",
            ui_locales_supported = ["en-US", "en-GB", "en-CA", "fr-FR", "fr-CA"]

        };

        return Ok(response);
    }

    [AllowAnonymous]
    [HttpGet]
    public IActionResult Authorize([FromQuery] AuthorizationRequest authorizationRequest)
    {
        var result = this._authService.AuthorizeRequest(_httpContextAccessor, authorizationRequest);

        if (result.HasError)
        {
            return RedirectToAction("Error", new { error = result.Error });
        }

        var loginModel = new OpenIdConnectLoginRequest
        {
            RedirectUri = result.RedirectUri,
            Code = result.Code,
            RequestedScopes = result.RequestedScopes,
            Nonce = result.Nonce
        };

        return RedirectToAction("Login", "Home", loginModel);
    }

    [AllowAnonymous]
    [HttpGet]
    public IActionResult Error(string error)
    {
        return Ok(error);
    }

    [AllowAnonymous]
    [HttpPost]
    public async Task<IActionResult> Token()
    {
        var result = await this._authService.GenerateToken(_httpContextAccessor);

        if (result.HasError)
        {
            return Ok("0");
        }

        return Ok(result);
    }
}