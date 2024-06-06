using Idm.OauthResponse;

namespace Auth.Errors;

public record AuthError
(
  ErrorTypeEnum Error,
  string? Message = null
);
