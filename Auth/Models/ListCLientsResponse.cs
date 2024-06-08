using Auth.Models;

namespace Account.Models;

public record ListClientsResponse(
  Client[] authClients
);
