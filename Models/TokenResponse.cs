using Idm.Common;
using Idm.Models;

namespace Idm.OauthResponse;

public record TokenResponse(
    string access_token,
    string id_token,
    string code,
    string token_type
)
{
  public TokenResponse(
      string access_token,
      string id_token,
      string code
  ) : this(access_token, id_token, code, TokenTypeEnum.Bearer.GetEnumDescription())
  {

  }
}
