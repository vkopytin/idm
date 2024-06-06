namespace Idm.Models;

public record AuthorizationCode
(
  string ClientId,
  string ClientSecret,
  string RedirectUri,

  string[] RequestedScopes,
  DateTime CreationTime,

  string Nonce,
  string? UserId = null,
  bool IsOpenId = true
);
