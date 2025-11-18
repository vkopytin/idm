using Idm.Common;

namespace Idm.Models;

/// <summary>
/// https://www.rfc-editor.org/rfc/rfc6749#page-23
/// </summaty>
public class GrantTypes
{
  public static IList<string> Code =>
      [AuthorizationGrantTypesEnum.Code.GetEnumDescription()];

  public static IList<string> Implicit =>
      [AuthorizationGrantTypesEnum.Implicit.GetEnumDescription()];
  public static IList<string> ClientCredentials =>
      [AuthorizationGrantTypesEnum.ClientCredentials.GetEnumDescription()];
  public static IList<string> ResourceOwnerPassword =>
      [AuthorizationGrantTypesEnum.ResourceOwnerPassword.GetEnumDescription()];
}
