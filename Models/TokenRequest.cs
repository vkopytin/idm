namespace Idm.OauthRequest;

public record TokenRequest(
  string ClientId,
  string ClientSecret,
  string Code,
  string GrantType,
  string RedirectUri,
  string CodeVerifier
);
