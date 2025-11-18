using System.Data;
using Microsoft.Extensions.Configuration;
using Npgsql;

namespace Auth.Db;

public class NpgsqlDbConnectionFactory : IDbConnectionFactory
{
  private readonly string _connectionString;

  public NpgsqlDbConnectionFactory(IConfiguration configuration)
  {
    _connectionString = configuration.GetConnectionString("PostgreSqlConnection")
                        ?? throw new InvalidOperationException("PostgreSqlConnection string is not configured.");
  }

  public async Task<IDbConnection> CreateConnectionAsync(CancellationToken cancellationToken = default)
  {
    var url = new Uri(_connectionString);
    var sb = new NpgsqlConnectionStringBuilder();
    sb.Host = url.Host;
    sb.Port = url.Port;
    sb.Username = url.UserInfo.Split(':')[0];
    sb.Password = url.UserInfo.Split(':')[1];
    sb.Database = url.AbsolutePath.TrimStart('/');
    sb.SslMode = SslMode.Require;

    var connection = new NpgsqlConnection(sb.ConnectionString);
    await connection.OpenAsync(cancellationToken);
    return connection;
  }
}

public interface IDbConnectionFactory
{
  Task<IDbConnection> CreateConnectionAsync(CancellationToken cancellationToken = default);
}

