namespace Idm.OauthRequest;

public record AuthorizationRequest
(
  /// <summary>
  /// Response Type, is required
  /// </summary>
  string response_type,

  /// <summary>
  /// Client Id, is required
  /// </summary>

  string client_id,

  /// <summary>
  /// Redirect Uri, is optional
  /// The redirection endpoint URI MUST be an absolute URI as defined by
  /// [RFC3986] Section 4.3
  /// </summary>

  string redirect_uri,

  /// <summary>
  /// Optional
  /// </summary>
  string scope,

  /// <summary>
  /// Return the state in the result 
  /// if it was present in the client authorization request
  /// </summary>
  string state
);
