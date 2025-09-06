using System.ComponentModel.DataAnnotations;

namespace Auth.Models;

public class SecurityGroup
{
    [Key]
    public MongoDB.Bson.ObjectId Id { get; set; }
    public string GroupName { get; set; } = "";
}
