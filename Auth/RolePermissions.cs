namespace Auth;

public enum RolePermissions
{
  None = 0,
  List = 1 << 0,   // 1
  Read = 1 << 1,   // 2
  Edit = 1 << 2,   // 4
  Remove = 1 << 3, // 8
  Export = 1 << 4, // 16
}
