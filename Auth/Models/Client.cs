namespace Auth.Models;

public record Client(
    string ClientName,
    string ClientId,
    string ClientSecret,
    string SecurityGroupId,
    IList<string> GrantType,
    IList<string> AllowedScopes,
    string ClientUri,
    string RedirectUri,
    bool IsActive = false
);
