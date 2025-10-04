namespace Idm.OauthRequest;

public record OpenIdConnectLoginRequest(
    string? UserName,
    string? Password,
    string RedirectUri,
    string Code,
    string Nonce,
    IList<string> RequestedScopes,
    string? ResponseType = null,
    string? AccessType = null
);
