namespace Idm.Models;

public record LoginError(
  string Message,
  string? UserName,
  string? Password,
  string RedirectUri,
  string Code,
  string Nonce,
  IList<string> RequestedScopes
);
