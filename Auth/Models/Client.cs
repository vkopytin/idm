namespace Auth.Models;

public record Client(
    string ClientName,
    string ClientId,
    string ClientSecret,
    IList<string> GrantType,
    IList<string> AllowedScopes,
    string ClientUri,
    string RedirectUri,
    bool IsActive = false
);
