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
        ClientSecret = "some-secret-key-with-long-description-on-prod",
        AllowedScopes = ["openid", "profile"],
        GrantType = GrantTypes.Code,
        IsActive = true,
        ClientUri = "https://localhost:3001",
        RedirectUri = "https://localhost:3001/signin-oidc"
    },
    new Client
    {
        ClientName = "platformnet .Net 6",
        ClientId = "platformnet6",
        ClientSecret = "some-secret-key-with-long-description-on-prod",
        AllowedScopes = ["openid", "profile"],
        GrantType = GrantTypes.Code,
        IsActive = true,
        ClientUri = "https://https://account1.azurewebsites.net",
        RedirectUri = "https://https://account1.azurewebsites.net/signin-oidc"
    }
  ];
}
