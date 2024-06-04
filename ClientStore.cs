using System.Collections.Generic;

namespace Idm.Models;

public class ClientStore
{
  public IEnumerable<Client> Clients =
  [
    new Client
    {
        ClientName = "platformnet .Net 6",
        ClientId = "platformnet6",
        ClientSecret = "qarxcmlxcahildalknv-qarxcmlxcahildalknv-qarxcmlxcahildalknv-123",
        AllowedScopes = ["openid", "profile"],
        GrantType = GrantTypes.Code,
        IsActive = true,
        ClientUri = "https://localhost:3001",
        RedirectUri = "https://localhost:3001/signin-oidc"
    }
  ];
}
