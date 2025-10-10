using Auth.Models;

namespace Idm.Models;

public record AuthorizationCode
(
  string ClientId,
  string ClientSecret,
  string RedirectUri,

  string[] RequestedScopes,
  DateTime CreationTime,

  string Nonce,
  string OpenId,
  string? UserId = null,
  bool IsOpenId = true,

  string? BackUrl = null
)
{
  internal static AuthorizationCode? FromModel(AuthCode existing)
  {
    if (existing is null) return null;

    return new AuthorizationCode
    (
      ClientId: existing.ClientId,
      ClientSecret: existing.ClientSecret,
      RedirectUri: existing.RedirectUri,
      RequestedScopes: existing.RequestedScopes,
      CreationTime: existing.CreationTime,
      Nonce: existing.Nonce,
      OpenId: existing.OpenId,
      UserId: existing.UserId,
      IsOpenId: existing.IsOpenId
    );
  }
}