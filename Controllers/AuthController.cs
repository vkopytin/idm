using AppConfiguration;
using Auth;
using Auth.Exceptions;
using Auth.Models;
using Idm.Endpoints;
using Idm.OauthRequest;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.IdentityModel.Tokens.Jwt;

namespace Controllers;

[Route("[controller]/[action]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly IHttpContextAccessor httpContextAccessor;
    private readonly IAuthService authService;
    private readonly CookieOptions cookieOptions;
    private readonly JwtOptions jwtOptions;
    private readonly ILogger logger;

    public AuthController(
        IAuthService authService,
        IHttpContextAccessor httpContextAccessor,
        JwtOptions jwtOptions,
        ILogger<AuthController> logger)
    {
        this.authService = authService;
        this.httpContextAccessor = httpContextAccessor;
        this.jwtOptions = jwtOptions;
        this.logger = logger;
        cookieOptions = new CookieOptions()
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
            return BadRequest(new { message = "Email address needs to be entered" });
        }

        if (string.IsNullOrEmpty(user.Password))
        {
            return BadRequest(new { message = "Password needs to be entered" });
        }

        try
        {
            var scopes = "read:user-info read:files";
            var loggedInUser = await authService.Login(user.UserName, user.Password, scopes);

            if (loggedInUser is null)
            {
                return BadRequest(new { message = "User login unsuccessful" });
            }

            return Ok(loggedInUser);
        }
        catch (AuthErrorException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, ex.Message);

            return BadRequest(new { message = "User login unsuccessful" });
        }
    }

    [AllowAnonymous]
    [HttpPost]
    public async Task<IActionResult> LoginForm([FromForm] string username, [FromForm] string password, [FromForm] string redirectTo)
    {
        var res = await Login(new LoginUser
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

        var userToRegister = new User(user.UserName, user.Name, user.Password, user.Role);

        var registeredUser = await authService.Register(userToRegister);

        try
        {
            var scopes = "read:user-info read:files";
            var loggedInUser = await authService.Login(registeredUser.UserName, user.Password, scopes);

            return Ok(loggedInUser);
        }
        catch (AuthErrorException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, ex.Message);

            return BadRequest(new { message = "User registration unsuccessful" });
        }
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
        var jwtIssuer = jwtOptions.Issuer;
        var response = new DiscoveryResponse(
            issuer: jwtIssuer,
            authorization_endpoint: $"{jwtIssuer}/Auth/Authorize",
            token_endpoint: $"{jwtIssuer}/Auth/Token",
            token_endpoint_auth_methods_supported: ["client_secret_basic", "private_key_jwt"],
            token_endpoint_auth_signing_alg_values_supported: ["RS256", "ES256"],
            userinfo_endpoint: null,
            check_session_iframe: null,
            end_session_endpoint: null,
            jwks_uri: null,
            registration_endpoint: null,
            scopes_supported: ["openid", "profile", "email", "address", "phone", "offline_access"],
            response_types_supported: ["code", "code id_token", "id_token", "token id_token"],
            acr_values_supported: ["urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:bronze"],
            subject_types_supported: ["public", "pairwise"],
            userinfo_signing_alg_values_supported: null,
            userinfo_encryption_alg_values_supported: null,
            userinfo_encryption_enc_values_supported: ["A128CBC-HS256", "A128GCM"],
            id_token_signing_alg_values_supported: ["RS256", "ES256", "HS256"],
            id_token_encryption_alg_values_supported: ["RSA1_5", "A128KW"],
            id_token_encryption_enc_values_supported: ["A128CBC-HS256", "A128GCM"],
            request_object_signing_alg_values_supported: ["none", "RS256", "ES256"],
            display_values_supported: ["page", "popup"],
            claim_types_supported: ["normal", "distributed"],
            claims_supported:
            [
                "sub", "iss", "auth_time", "acr", "name", "given_name",
                "family_name", "nickname", "profile", "picture", "website", "email", "email_verified",
                "locale", "zoneinfo"
            ],
            claims_parameter_supported: true,
            service_documentation: $"{jwtIssuer}/connect/service_documentation.html",
            ui_locales_supported: ["en-US", "en-GB", "en-CA", "fr-FR", "fr-CA"]
        );

        return Ok(response);
    }

    [AllowAnonymous]
    [HttpGet]
    public IActionResult Authorize([FromQuery] AuthorizationRequest authorizationRequest)
    {
        var result = authService.AuthorizeRequest(httpContextAccessor, authorizationRequest);

        if (result.HasError)
        {
            return RedirectToAction("Error", new { error = result.Error });
        }

        var loginModel = new OpenIdConnectLoginRequest
        (
            UserName: null,
            Password: null,
            RedirectUri: result.RedirectUri,
            Code: result.Code,
            RequestedScopes: result.RequestedScopes,
            Nonce: result.Nonce
        );

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
        var result = await authService.GenerateToken(httpContextAccessor);

        if (result.HasError)
        {
            return Ok("0");
        }

        return Ok(result);
    }
}