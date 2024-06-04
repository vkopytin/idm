using Auth.Models;
using Idm.Models;
using Idm.OauthRequest;
using Idm.OauthResponse;
using Microsoft.AspNetCore.Http;

namespace Auth;

public interface IAuthService
{
    public Task<User> Login(string email, string password, string scope);
    public Task<User> Register(User user);

    string GenerateAuthorizationCode(string clientId, IList<string> requestedScope);
    AuthorizationCode GetClientDataByCode(string key);
    AuthorizationCode RemoveClientDataByCode(string key);

    AuthorizeResponse AuthorizeRequest(IHttpContextAccessor httpContextAccessor, AuthorizationRequest authorizationRequest);
    AuthorizationCode UpdatedClientDataByCode(string key, IList<string> requestdScopes, string userName, string password = null, string nonce = null);
    TokenResponse GenerateToken(IHttpContextAccessor httpContextAccessor);
}