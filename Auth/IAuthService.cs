using Auth.Errors;
using Auth.Models;
using Idm.Models;
using Idm.OauthRequest;
using Idm.OauthResponse;

namespace Auth;

public interface IAuthService
{
    public Task<(User?, AuthError?)> Login(string email, string password, string scope);
    public Task<User> Register(User user);

    Task<(AuthorizeResponse?, AuthError?)> AuthorizeRequest(AuthorizationRequest authorizationRequest);
    Task<(AuthorizationCode?, AuthError?)> UpdatedClientDataByCode(string key, IEnumerable<string> requestdScopes, string userName, string nonce);
    Task<(TokenResponse?, AuthError?)> GenerateToken(TokenRequest request);
}
