using Auth;
using Idm.OauthRequest;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Controllers;

[Route("[controller]/[action]")]
[AllowAnonymous]
public class HomeController : Controller
{
  private readonly IAuthService _authService;

  public HomeController(IAuthService authService)
  {
    _authService = authService;

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

    var loggedInUser = await _authService.Login(loginRequest.UserName, loginRequest.Password, "read:user-info read:files");

    if (loggedInUser is null)
    {
      return RedirectToAction("Error", new { error = "invalid_login" });
    }

    var result = this._authService.UpdatedClientDataByCode(loginRequest.Code, loginRequest.RequestedScopes,
        loginRequest.UserName, nonce: loginRequest.Nonce);
    if (result != null)
    {
      loginRequest.RedirectUri = loginRequest.RedirectUri + "&code=" + loginRequest.Code;
      return Redirect(loginRequest.RedirectUri);
    }
    return RedirectToAction("Error", new { error = "invalid_request" });
  }

}
