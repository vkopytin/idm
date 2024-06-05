namespace Idm.OauthResponse;

public record AuthorizeResponse
(
  /// <summary>
  /// code or implicit grant or client creditional 
  /// </summary>
  string Code,
  /// <summary>
  /// required if it was present in the client authorization request
  /// </summary>
  string State,

  string RedirectUri,
  IList<string> RequestedScopes,
  string Nonce
);
