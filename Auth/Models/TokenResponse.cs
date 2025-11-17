using System.Text.Json.Serialization;

namespace Auth.Models.Google;

public record TokenResponse(
  [property: JsonPropertyName("access_token")]
  string AccessToken,
  [property: JsonPropertyName("expires_in")]
  int ExpiresIn,
  [property: JsonPropertyName("token_type")]
  string TokenType,
  [property: JsonPropertyName("scope")]
  string Scope,
  [property: JsonPropertyName("refresh_token")]
  string RefreshToken,
  [property: JsonPropertyName("backUrl")]
  string BackUrl = ""
);
