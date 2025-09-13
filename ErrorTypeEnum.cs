using System.ComponentModel;

namespace Idm.OauthResponse;

public enum ErrorTypeEnum : byte
{
  [Description("invalid_request")]
  InvalidRequest,

  [Description("unauthorized_client")]
  UnAuthoriazedClient,

  [Description("access_denied")]
  AccessDenied,

  [Description("invalid_password")]
  AccessDeniedInvalidPassword,

  [Description("unsupported_response_type")]
  UnSupportedResponseType,

  [Description("invlaid_code")]
  InvalidCode,

  [Description("invalid_scope")]
  InvalidScope,

  [Description("_invalid_identity_principal")]
  InvalidIdentityPrincipal,

  [Description("server_error")]
  ServerError,

  [Description("temporarily_unavailable")]
  TemporarilyUnAvailable,

  [Description("invalid_grant")]
  InvalidGrant,

  [Description("invalid_client")]
  InvalidClient
}
