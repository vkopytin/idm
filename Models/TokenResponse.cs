using Idm.Common;
using Idm.Models;

namespace Idm.OauthResponse;

public record TokenResponse(
    string? access_token,
    string? id_token,
    string? code,
    string? Error,
    string? ErrorUri,
    string? ErrorDescription,
    string? token_type
)
{
  public bool HasError => !string.IsNullOrEmpty(Error);

  public TokenResponse(
      string? access_token = null,
      string? id_token = null,
      string? code = null,
      string? Error = null,
      string? ErrorUri = null,
      string? ErrorDescription = null
  ) : this(access_token, id_token, code, Error, ErrorUri, ErrorDescription, TokenTypeEnum.Bearer.GetEnumDescription())
  {

  }
}
