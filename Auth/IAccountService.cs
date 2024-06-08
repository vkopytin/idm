using Auth.Errors;
using Auth.Models;

namespace Auth;

public interface IAccountService
{
  Task<(Client[]?, AuthError?)> ListClients();
  Task<(Client?, AuthError?)> GetClient(string clientId);
}
