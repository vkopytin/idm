using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using MongoDB.Bson.Serialization.Attributes;

namespace Auth.Models;

public class AuthToken
{
  [Key]
  [BsonId]
  [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
  public Guid Id { get; set; }
  public string CreatedAt { get; set; } = DateTime.UtcNow.ToString("o");
  public string AccessToken { get; set; }
  public string RefreshToken { get; set; }
  public DateTime Expiration { get; set; }
  public string SecurityGroupId { get; set; }
  public string[] Scopes { get; set; } = [];
  public string TokenType { get; set; } = "Bearer";
}
