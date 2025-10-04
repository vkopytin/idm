using AppConfiguration;
using Auth;
using Auth.Services;
using Idm.Common;
using Idm.Models;
using Idm.OauthRequest;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Controllers;

[Route("[controller]/[action]")]
[AllowAnonymous]
public class HomeController : Controller
{
  private readonly MainSettings settings;
  private readonly GoogleService googleService;
  private readonly IAuthService authService;
  private readonly ILogger logger;

  public HomeController(
    IAuthService authService,
    GoogleService googleService,
    MainSettings settings,
    ILogger<HomeController> logger
  )
  {
    this.settings = settings;
    this.googleService = googleService;
    this.authService = authService;
    this.logger = logger;
  }

  [HttpGet]
  public IActionResult Index()
  {
    return View();
  }

  [HttpGet]
  [ActionName("login")]
  public IActionResult LoginGet(OpenIdConnectLoginRequest loginRequest)
  {
    return View(loginRequest);
  }

  [HttpPost]
  [AllowAnonymous]
  [ActionName("GoogleLogin")]
  public IActionResult GoogleLogin(OpenIdConnectLoginRequest loginRequest)
  {
    var url = googleService.BuildAuthUrl(loginRequest);

    return Redirect(url);
  }

  [HttpPost]
  [AllowAnonymous]
  [ActionName("login")]
  public async Task<IActionResult> LoginPost(OpenIdConnectLoginRequest loginRequest)
  {
    if (string.IsNullOrEmpty(loginRequest.UserName))
    {
      return BadRequest(new { message = "Email address needs to entered" });
    }
    else if (string.IsNullOrEmpty(loginRequest.Password))
    {
      return BadRequest(new { message = "Password needs to entered" });
    }

    var (user, loginError) = await authService.Login(loginRequest.UserName, loginRequest.Password, "read:user-info read:files");

    if (user is null)
    {
      return RedirectToAction("Error", new LoginError(
        Message: loginError?.Message ?? loginError?.Error.ToString() ?? "Unexpected error",
        UserName: loginRequest.UserName,
        Password: loginRequest.Password,
        RedirectUri: loginRequest.RedirectUri,
        Code: loginRequest.Code,
        Nonce: loginRequest.Nonce,
        RequestedScopes: loginRequest.RequestedScopes
      ));
    }

    if (loginError is not null)
    {
      return RedirectToAction("Error", new { error = "invalid_login" });
    }

    var (_, updateCodeError) = await authService.UpdatedClientDataByCode(loginRequest.Code, loginRequest.RequestedScopes,
        user, loginRequest.Nonce);

    if (updateCodeError is not null)
    {
      logger.LogError("SSO Login Error: {error}, Message: {message}",
        updateCodeError.Error.GetEnumDescription(),
        updateCodeError.Message
      );
      return RedirectToAction("Error", new { error = "invalid_request" });
    }

    var redirectUri = loginRequest.RedirectUri + "&code=" + loginRequest.Code;
    return Redirect(redirectUri);
  }

  [HttpGet]
  [ActionName("error")]
  public IActionResult Error(LoginError error)
  {
    return View("Error", error);
  }

}
