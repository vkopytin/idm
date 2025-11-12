using System.ComponentModel.DataAnnotations;

namespace Auth.Models;

public class RoleModel
{
  [Key]
  public string RoleName { get; set; } = "";
  public int Permissions { get; set; } = 0; // Value from enum RolePermissions
}
