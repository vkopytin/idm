using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using MongoDB.Bson.Serialization.Attributes;

namespace Auth.Models;

public class AuthCode
{
  [Key]
  [BsonId]
  [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
  public Guid Id { get; set; }
  public string ClientId { get; set; }
  public string ClientSecret { get; set; }
  public string RedirectUri { get; set; }

  public string[] RequestedScopes { get; set; }
  public DateTime CreationTime { get; set; }

  public string Nonce { get; set; }
  public string OpenId { get; set; }
  public string? UserId { get; set; }
  public bool IsOpenId { get; set; }
}
