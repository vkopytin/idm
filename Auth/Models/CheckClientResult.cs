namespace Idm.Auth.Models;

public record CheckClientResult(
  Client? Client = null,
  /// <summary>
  /// The clinet is found in my Clients Store
  /// </summary>
  bool IsSuccess = false,
  string? Error = null,
  string? ErrorDescription = null
);
