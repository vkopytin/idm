namespace Idm.OauthResponse;

public record AuthorizeResponse
(
  /// <summary>
  /// code or implicit grant or client creditional 
  /// </summary>
  string? ResponseType = null,
  string? Code = null,
  /// <summary>
  /// required if it was present in the client authorization request
  /// </summary>
  string? State = null,

  string? RedirectUri = null,
  IList<string>? RequestedScopes = null,
  string? GrantType = null,
  string? Nonce = null,
  string? Error = null,
  string? ErrorUri = null,
  string? ErrorDescription = null
)
{
  public bool HasError => !string.IsNullOrEmpty(Error);
}
