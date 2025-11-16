using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Auth.Models;

[Table("WebSite")]
public class WebSite
{
  [Key]
  [BsonId]
  [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
  public Guid Id { get; set; }
  public string? Name { get; set; }
  public string? HostName { get; set; }
  public ObjectId? UserId { get; set; }
  [ForeignKey("UserId")]
  public User? User { get; set; }
}
