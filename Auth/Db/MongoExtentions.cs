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
}
