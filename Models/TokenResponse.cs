using Idm.Common;
using Idm.Models;

namespace Idm.OauthResponse;

public record TokenResponse(
    string access_token,
    string? id_token,
    string? refresh_token,
    string expires_at,
    string code,
    string token_type
)
{
  public TokenResponse(
      string access_token,
      string? id_token,
      string? refresh_token,
      string expires_at,
      string code
  ) : this(access_token, id_token, refresh_token, expires_at, code, TokenTypeEnum.Bearer.GetEnumDescription())
  {

  }
}
