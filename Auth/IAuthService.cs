using Auth.Errors;
using Auth.Models;
using Idm.Models;
using Idm.OauthRequest;
using Idm.OauthResponse;
using Microsoft.AspNetCore.Http;

namespace Auth;

public interface IAuthService
{
    public Task<(User?, AuthError?)> Login(string email, string password, string scope);
    public Task<User> Register(User user);

    (AuthorizeResponse?, AuthError?) AuthorizeRequest(IHttpContextAccessor httpContextAccessor, AuthorizationRequest authorizationRequest);
    (AuthorizationCode?, AuthError) UpdatedClientDataByCode(string key, IList<string> requestdScopes, string userName, string password = null, string nonce = null);
    Task<(TokenResponse?, AuthError?)> GenerateToken(IHttpContextAccessor httpContextAccessor);
}
