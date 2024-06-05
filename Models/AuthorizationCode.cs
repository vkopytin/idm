namespace Idm.Models;

public record AuthorizationCode
(
  string ClientId,
  string ClientSecret,
  string RedirectUri,

  IList<string> RequestedScopes,
  DateTime CreationTime,

  string? UserId = null,
  string? Nonce = null,
  bool IsOpenId = true
);
