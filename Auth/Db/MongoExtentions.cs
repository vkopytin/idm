using Auth.Models;
using Idm.Models;
using Microsoft.Extensions.Configuration;
using MongoDB.Driver;

public static class MongoExtensions
{
  public static MongoClient CreateMongoClient(this IConfiguration configuration, string mongoDBConnection)
  {
    var connectionString = configuration.GetConnectionString(mongoDBConnection);

    var settings = MongoClientSettings.FromUrl(new MongoUrl(connectionString));

    return new MongoClient(settings);
  }

  public static AuthCode ToModel(this AuthorizationCode code)
  {
    return new AuthCode
    {
      ClientId = code.ClientId,
      ClientSecret = code.ClientSecret,
      RedirectUri = code.RedirectUri,
      Nonce = code.Nonce,
      OpenId = code.OpenId,
      RequestedScopes = code.RequestedScopes.ToArray(),
      CreationTime = code.CreationTime,
      UserId = code.UserId,
      IsOpenId = !string.IsNullOrEmpty(code.OpenId)
    };
  }
}
