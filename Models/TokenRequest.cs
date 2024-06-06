using Microsoft.AspNetCore.Mvc;

namespace Idm.OauthRequest;

public record TokenRequest(
  [FromForm(Name ="client_id")]
  string ClientId,
  [FromForm(Name = "client_secret")]
  string? ClientSecret,
  [FromForm(Name = "code")]
  string Code,
  [FromForm(Name = "grant_type")]
  string GrantType,
  [FromForm(Name = "redirect_uri")]
  string RedirectUri,
  [FromForm(Name = "code_verifier")]
  string CodeVerifier
);
