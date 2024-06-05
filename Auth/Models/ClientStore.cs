using Idm.Models;

namespace Idm.Auth.Models;

public class ClientStore
{
  public IEnumerable<Client> Clients =
  [
    new Client
    (
      ClientName: "platformnet .Net 6",
      ClientId: "platformnet6",
      ClientSecret: "some-secret-key-with-long-description-on-prod",
      AllowedScopes: ["openid", "profile"],
      GrantType: GrantTypes.Code,
      IsActive: true,
      ClientUri: "https://localhost:3001",
      RedirectUri: "https://localhost:3001/signin-oidc"
    ),
    new Client
    (
      ClientName: "platformnet .Net 6",
      ClientId: "platformnet6 on prod",
      ClientSecret: "some-secret-key-with-long-description-on-prod",
      AllowedScopes: ["openid", "profile"],
      GrantType: GrantTypes.Code,
      IsActive: true,
      ClientUri: "https://account1.azurewebsites.net",
      RedirectUri: "https://account1.azurewebsites.net/signin-oidc"
    ),
    new Client
    (
      ClientName: "angular app",
      ClientId: "local-dev",
      ClientSecret: "some-secret-key-with-long-description-on-prod",
      AllowedScopes: ["openid", "profile"],
      GrantType: GrantTypes.Code,
      IsActive: true,
      ClientUri: "https://local-dev.azurewebsites.net",
      RedirectUri: "https://local-dev.azurewebsites.net/signin-oidc"
    )
  ];

  public Client? findByClientId(string clientId)
  {
    return Clients.Where(x => x.ClientId == clientId).FirstOrDefault();
  }
}
