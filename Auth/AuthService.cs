using Auth.Db;
using Auth.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Collections.Concurrent;
using Idm.Models;
using Microsoft.EntityFrameworkCore;

namespace Auth;

using BCrypt.Net;
using Idm.Common;
using Idm.OauthRequest;
using Idm.OauthResponse;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;

public class AuthService : IAuthService
{
    private readonly ConcurrentDictionary<string, AuthorizationCode> _codeIssued = new ConcurrentDictionary<string, AuthorizationCode>();
    private readonly ClientStore _clientStore = new ClientStore();
    private static string keyAlg = "66007d41-6924-49f2-ac0c-e63c4b1a1730";
    private readonly MongoDbContext _dbContext;
    private readonly IConfiguration _configuration;

    public AuthService(MongoDbContext dbContext, IConfiguration configuration)
    {
        _dbContext = dbContext;
        _configuration = configuration;
    }

    public async Task<User> Login(string email, string password, string scopes)
    {
        User? user = await _dbContext.Users.FirstOrDefaultAsync(user => user.UserName == email);

        if (user == null || BCrypt.Verify(password, user.Password) == false)
        {
            return null; //returning null intentionally to show that login was unsuccessful
        }

        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_configuration["JWT:SecretKey"]);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(
            [
                new (ClaimTypes.Name, user.UserName),
                new (ClaimTypes.GivenName, user.Name),
                new (ClaimTypes.Role, user.Role),
                new ("scopes", scopes)
            ]),
            IssuedAt = DateTime.UtcNow,
            Issuer = _configuration["JWT:Issuer"],
            Audience = _configuration["JWT:Audience"],
            Expires = DateTime.UtcNow.AddMinutes(30),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        user.Token = tokenHandler.WriteToken(token);
        user.IsActive = true;

        return user;
    }

    public async Task<User> Register(User user)
    {
        user.Password = BCrypt.HashPassword(user.Password);
        _dbContext.Users.Add(user);
        await _dbContext.SaveChangesAsync();

        return user;
    }

    // Here I genrate the code for authorization, and I will store it 
    // in the Concurrent Dictionary

    public string GenerateAuthorizationCode(string clientId, IList<string> requestedScope)
    {
        var client = _clientStore.Clients.Where(x => x.ClientId == clientId).FirstOrDefault();

        if (client != null)
        {
            var code = Guid.NewGuid().ToString();

            var authoCode = new AuthorizationCode
            {
                ClientId = clientId,
                RedirectUri = client.RedirectUri,
                RequestedScopes = requestedScope,
            };

            // then store the code is the Concurrent Dictionary
            _codeIssued[code] = authoCode;

            return code;
        }
        return null;

    }

    public AuthorizationCode GetClientDataByCode(string key)
    {
        AuthorizationCode authorizationCode;
        if (_codeIssued.TryGetValue(key, out authorizationCode))
        {
            return authorizationCode;
        }
        return null;
    }

    public AuthorizationCode RemoveClientDataByCode(string key)
    {
        AuthorizationCode authorizationCode;
        _codeIssued.TryRemove(key, out authorizationCode);
        return null;
    }

    public AuthorizeResponse AuthorizeRequest(IHttpContextAccessor httpContextAccessor, AuthorizationRequest authorizationRequest)
    {
        AuthorizeResponse response = new AuthorizeResponse();

        if (httpContextAccessor == null)
        {
            response.Error = ErrorTypeEnum.ServerError.GetEnumDescription();
            return response;
        }

        var client = VerifyClientById(authorizationRequest.client_id);
        if (!client.IsSuccess)
        {
            response.Error = client.ErrorDescription;
            return response;
        }

        if (string.IsNullOrEmpty(authorizationRequest.response_type) || authorizationRequest.response_type != "code")
        {
            response.Error = ErrorTypeEnum.InvalidRequest.GetEnumDescription();
            response.ErrorDescription = "response_type is required or is not valid";
            return response;
        }

        if (!authorizationRequest.redirect_uri.IsRedirectUriStartWithHttps() && !httpContextAccessor.HttpContext.Request.IsHttps)
        {
            response.Error = ErrorTypeEnum.InvalidRequest.GetEnumDescription();
            response.ErrorDescription = "redirect_url is not secure, MUST be TLS";
            return response;
        }


        // check the return url is match the one that in the client store


        // check the scope in the client store with the
        // one that is comming from the request MUST be matched at leaset one

        var scopes = authorizationRequest.scope.Split(' ');

        var clientScopes = from m in client.Client.AllowedScopes
                           where scopes.Contains(m)
                           select m;

        if (!clientScopes.Any())
        {
            response.Error = ErrorTypeEnum.InValidScope.GetEnumDescription();
            response.ErrorDescription = "scopes are invalids";
            return response;
        }

        string nonce = httpContextAccessor.HttpContext.Request.Query["nonce"].ToString();

        // Verify that a scope parameter is present and contains the openid scope value.
        // (If no openid scope value is present,
        // the request may still be a valid OAuth 2.0 request, but is not an OpenID Connect request.)

        string code = this.GenerateAuthorizationCode(authorizationRequest.client_id, clientScopes.ToList());
        if (code == null)
        {
            response.Error = ErrorTypeEnum.TemporarilyUnAvailable.GetEnumDescription();
            return response;
        }

        response.RedirectUri = client.Client.RedirectUri + "?response_type=code" + "&state=" + authorizationRequest.state;
        response.Code = code;
        response.State = authorizationRequest.state;
        response.RequestedScopes = clientScopes.ToList();
        response.Nonce = nonce;

        return response;

    }

    private CheckClientResult VerifyClientById(string clientId, bool checkWithSecret = false, string clientSecret = null)
    {
        CheckClientResult result = new CheckClientResult() { IsSuccess = false };

        if (!string.IsNullOrWhiteSpace(clientId))
        {
            var client = _clientStore.Clients.Where(x => x.ClientId.Equals(clientId, StringComparison.OrdinalIgnoreCase)).FirstOrDefault();

            if (client != null)
            {
                if (checkWithSecret && !string.IsNullOrEmpty(clientSecret))
                {
                    bool hasSamesecretId = client.ClientSecret.Equals(clientSecret, StringComparison.InvariantCulture);
                    if (!hasSamesecretId)
                    {
                        result.Error = ErrorTypeEnum.InvalidClient.GetEnumDescription();
                        return result;
                    }
                }


                // check if client is enabled or not

                if (client.IsActive)
                {
                    result.IsSuccess = true;
                    result.Client = client;

                    return result;
                }
                else
                {
                    result.ErrorDescription = ErrorTypeEnum.UnAuthoriazedClient.GetEnumDescription();
                    return result;
                }
            }
        }

        result.ErrorDescription = ErrorTypeEnum.AccessDenied.GetEnumDescription();
        return result;
    }

    // Before updated the Concurrent Dictionary I have to Process User Sign In,
    // and check the user credienail first
    // But here I merge this process here inside update Concurrent Dictionary method
    public AuthorizationCode UpdatedClientDataByCode(string key, IList<string> requestdScopes,
        string userName, string password = null, string nonce = null)
    {
        var oldValue = GetClientDataByCode(key);

        if (oldValue != null)
        {
            // check the requested scopes with the one that are stored in the Client Store 
            var client = _clientStore.Clients.Where(x => x.ClientId == oldValue.ClientId).FirstOrDefault();

            if (client != null)
            {
                var clientScope = (from m in client.AllowedScopes
                                   where requestdScopes.Contains(m)
                                   select m).ToList();

                if (!clientScope.Any())
                    return null;

                AuthorizationCode newValue = new AuthorizationCode
                {
                    ClientId = oldValue.ClientId,
                    CreationTime = oldValue.CreationTime,
                    IsOpenId = requestdScopes.Contains("openId") || requestdScopes.Contains("profile"),
                    RedirectUri = oldValue.RedirectUri,
                    RequestedScopes = requestdScopes,
                    Nonce = nonce
                };

                // ------------------ I suppose the user name and password is correct  -----------------
                var claims = new List<Claim>();

                if (newValue.IsOpenId)
                {
                    if (!string.IsNullOrEmpty(userName))
                    {
                        claims.Add(new Claim(ClaimTypes.Name, userName));
                    }
                }

                var claimIdentity = new ClaimsIdentity(claims);
                newValue.Subject = new ClaimsPrincipal(claimIdentity);
                // ------------------ -----------------------------------------------  -----------------

                var result = _codeIssued.TryUpdate(key, newValue, oldValue);

                if (result)
                    return newValue;
                return null;
            }
        }
        return null;
    }

    public TokenResponse GenerateToken(IHttpContextAccessor httpContextAccessor)
    {
        TokenRequest request = new TokenRequest
        {
            CodeVerifier = httpContextAccessor.HttpContext.Request.Form["code_verifier"],
            ClientId = httpContextAccessor.HttpContext.Request.Form["client_id"],
            ClientSecret = httpContextAccessor.HttpContext.Request.Form["client_secret"],
            Code = httpContextAccessor.HttpContext.Request.Form["code"],
            GrantType = httpContextAccessor.HttpContext.Request.Form["grant_type"],
            RedirectUri = httpContextAccessor.HttpContext.Request.Form["redirect_uri"]
        };

        var checkClientResult = this.VerifyClientById(request.ClientId, true, request.ClientSecret);
        if (!checkClientResult.IsSuccess)
        {
            return new TokenResponse { Error = checkClientResult.Error, ErrorDescription = checkClientResult.ErrorDescription };
        }

        // check code from the Concurrent Dictionary
        var clientCodeChecker = this.GetClientDataByCode(request.Code);
        if (clientCodeChecker == null)
            return new TokenResponse { Error = ErrorTypeEnum.InvalidGrant.GetEnumDescription() };


        // check if the current client who is one made this authentication request

        if (request.ClientId != clientCodeChecker.ClientId)
            return new TokenResponse { Error = ErrorTypeEnum.InvalidGrant.GetEnumDescription() };

        // TODO: 
        // also I have to check the rediret uri 


        // Now here I will Issue the Id_token
        JwtSecurityToken id_token = null;
        if (clientCodeChecker.IsOpenId)
        {
            // Generate Identity Token
            int iat = (int)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalSeconds;

            string[] amrs = ["pwd"];

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keyAlg));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>()
            {
                new("sub", "856933325856"),
                new("given_name", "Volodymyr Kopytin"),
                new("iat", iat.ToString(), ClaimValueTypes.Integer), // time stamp
                new("nonce", clientCodeChecker.Nonce),
                new("scopes", "read:files")
            };
            foreach (var amr in amrs)
            {
                claims.Add(new Claim("amr", amr)); // authentication method reference
            }

            claims.AddRange(clientCodeChecker.Subject.Claims);

            id_token = new JwtSecurityToken(_configuration["JWT:Issuer"], request.ClientId, claims,
                signingCredentials: credentials,
                expires: DateTime.UtcNow.AddMinutes(
                   int.Parse("5")
                )
            );
        }

        // Here I have to generate access token 
        var key_at = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keyAlg));
        var credentials_at = new SigningCredentials(key_at, SecurityAlgorithms.HmacSha256);

        var claims_at = new List<Claim>();
        var access_token = new JwtSecurityToken(_configuration["JWT:Issuer"], request.ClientId, claims_at, signingCredentials: credentials_at,
            expires: DateTime.UtcNow.AddMinutes(
               int.Parse("5")));

        // here remoce the code from the Concurrent Dictionary
        this.RemoveClientDataByCode(request.Code);

        return new TokenResponse
        {
            access_token = new JwtSecurityTokenHandler().WriteToken(access_token),
            id_token = id_token != null ? new JwtSecurityTokenHandler().WriteToken(id_token) : null,
            code = request.Code
        };
    }
}
