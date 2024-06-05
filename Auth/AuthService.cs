using Auth.Db;
using Auth.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Collections.Concurrent;
using Idm.Models;
using Microsoft.EntityFrameworkCore;

namespace Auth;

using AppConfiguration;
using BCrypt.Net;
using Idm.Auth.Models;
using Idm.Common;
using Idm.OauthRequest;
using Idm.OauthResponse;
using Microsoft.AspNetCore.Http;

public class AuthService : IAuthService
{
    private readonly ConcurrentDictionary<string, AuthorizationCode> _codeIssued = new ConcurrentDictionary<string, AuthorizationCode>();
    private readonly ClientStore _clientStore = new ClientStore();
    private readonly MongoDbContext _dbContext;
    private readonly JwtOptions jwtOptions;

    public AuthService(MongoDbContext dbContext, JwtOptions options)
    {
        _dbContext = dbContext;
        jwtOptions = options;
    }

    public async Task<User> Login(string email, string password, string scopes)
    {
        User? user = await _dbContext.Users.FirstOrDefaultAsync(user => user.UserName == email);

        if (user == null || BCrypt.Verify(password, user.Password) == false)
        {
            return null; //returning null intentionally to show that login was unsuccessful
        }

        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(jwtOptions.SecretKey);

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
            Issuer = jwtOptions.Issuer,
            Audience = jwtOptions.Audience,
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
            (
                ClientId: clientId,
                ClientSecret: client.ClientSecret,
                RedirectUri: client.RedirectUri,
                RequestedScopes: requestedScope,
                CreationTime: DateTime.Now
            );

            // then store the code is the Concurrent Dictionary
            _codeIssued[code] = authoCode;

            return code;
        }
        return null;

    }

    public AuthorizationCode GetClientDataByCode(string key)
    {
        if (_codeIssued.TryGetValue(key, out var authorizationCode))
        {
            return authorizationCode;
        }
        return null;
    }

    public AuthorizationCode RemoveClientDataByCode(string key)
    {
        _codeIssued.TryRemove(key, out var authorizationCode);
        return authorizationCode;
    }

    public AuthorizeResponse AuthorizeRequest(IHttpContextAccessor httpContextAccessor, AuthorizationRequest authorizationRequest)
    {
        if (httpContextAccessor == null)
        {
            return new()
            {
                Error = ErrorTypeEnum.ServerError.GetEnumDescription()
            };
        }

        var client = VerifyClientById(authorizationRequest.client_id);
        if (!client.IsSuccess)
        {
            return new()
            {
                Error = client.ErrorDescription
            };
        }

        if (authorizationRequest.response_type != "code")
        {
            return new()
            {
                Error = ErrorTypeEnum.InvalidRequest.GetEnumDescription(),
                ErrorDescription = "response_type is required or is not valid"
            };
        }

        if (!authorizationRequest.redirect_uri.IsRedirectUriStartWithHttps() && !httpContextAccessor.HttpContext.Request.IsHttps)
        {
            return new()
            {
                Error = ErrorTypeEnum.InvalidRequest.GetEnumDescription(),
                ErrorDescription = "redirect_url is not secure, MUST be TLS"
            };
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
            return new()
            {
                Error = ErrorTypeEnum.InValidScope.GetEnumDescription(),
                ErrorDescription = "scopes are invalids"
            };
        }

        string code = this.GenerateAuthorizationCode(authorizationRequest.client_id, clientScopes.ToList());
        if (code == null)
        {
            return new()
            {
                Error = ErrorTypeEnum.TemporarilyUnAvailable.GetEnumDescription()
            };
        }

        return new()
        {
            RedirectUri = client.Client.RedirectUri + "?response_type=code" + "&state=" + authorizationRequest.state,
            Code = code,
            State = authorizationRequest.state,
            RequestedScopes = clientScopes.ToList(),
            Nonce = httpContextAccessor.HttpContext?.Request.Query["nonce"].ToString()
        };
    }

    private CheckClientResult VerifyClientById(string clientId, bool checkWithSecret = false, string clientSecret = null)
    {
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
                        return new(
                            Error: ErrorTypeEnum.InvalidClient.GetEnumDescription()
                        );
                    }
                }

                if (client.IsActive)
                {
                    return new(
                        IsSuccess: true,
                        Client: client
                    );
                }
                else
                {
                    return new(
                        ErrorDescription: ErrorTypeEnum.UnAuthoriazedClient.GetEnumDescription()
                    );
                }
            }
        }

        return new(
            ErrorDescription: ErrorTypeEnum.AccessDenied.GetEnumDescription()
        );
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
                {
                    return null;
                }

                AuthorizationCode newValue = oldValue with
                {
                    IsOpenId = requestdScopes.Contains("openId") || requestdScopes.Contains("profile"),
                    RequestedScopes = requestdScopes,
                    Nonce = nonce,
                    UserId = userName
                };

                var result = _codeIssued.TryUpdate(key, newValue, oldValue);

                if (result)
                    return newValue;
                return null;
            }
        }
        return null;
    }

    public async Task<TokenResponse> GenerateToken(IHttpContextAccessor httpContextAccessor)
    {
        var form = httpContextAccessor.HttpContext?.Request.Form;
        TokenRequest request = new
        (
            CodeVerifier: form["code_verifier"],
            ClientId: form["client_id"],
            ClientSecret: form["client_secret"],
            Code: form["code"],
            GrantType: form["grant_type"],
            RedirectUri: form["redirect_uri"]
        );

        if (request.Code == null)
        {
            return new() { Error = ErrorTypeEnum.InvalidGrant.GetEnumDescription() };
        }

        var checkClientResult = this.VerifyClientById(request.ClientId, true, request.ClientSecret);
        if (!checkClientResult.IsSuccess)
        {
            return new() { Error = checkClientResult.Error, ErrorDescription = checkClientResult.ErrorDescription };
        }

        // check code from the Concurrent Dictionary
        var clientCodeChecker = this.GetClientDataByCode(request.Code);
        if (clientCodeChecker == null)
        {
            return new() { Error = ErrorTypeEnum.InvalidGrant.GetEnumDescription() };
        }

        var user = await _dbContext.Users.FirstOrDefaultAsync(user => user.UserName == clientCodeChecker.UserId);
        if (user is null)
        {
            return new() { Error = ErrorTypeEnum.AccessDenied.GetEnumDescription() };
        }
        // check if the current client who is one made this authentication request

        if (request.ClientId != clientCodeChecker.ClientId)
            return new() { Error = ErrorTypeEnum.InvalidGrant.GetEnumDescription() };

        int iat = (int)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalSeconds;

        JwtSecurityToken? id_token = null;
        if (clientCodeChecker.IsOpenId)
        {
            string[] amrs = ["pwd"];

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(checkClientResult.Client.ClientSecret));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>()
            {
                new(ClaimTypes.Name, user.UserName),
                new(ClaimTypes.GivenName, user.Name),
                new(ClaimTypes.Role, user.Role),
                new("sub", "856933325856"),
                new("iat", iat.ToString(), ClaimValueTypes.Integer), // time stamp
                new("nonce", clientCodeChecker.Nonce),
                new("scopes", "read:files"),
            };
            foreach (var amr in amrs)
            {
                claims.Add(new Claim("amr", amr)); // authentication method reference
            }

            id_token = new JwtSecurityToken(jwtOptions.Issuer, request.ClientId, claims,
                signingCredentials: credentials,
                expires: DateTime.UtcNow.AddMinutes(
                   int.Parse("5")
                )
            );
        }

        // Here I have to generate access token 
        var key_at = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(checkClientResult.Client.ClientSecret));
        var credentials_at = new SigningCredentials(key_at, SecurityAlgorithms.HmacSha256);

        Claim[] claims_at = [
            new("iss", checkClientResult.Client.ClientUri),
            new("iat", iat.ToString(), ClaimValueTypes.Integer), // time stamp
            new("scopes", "read:files"),
        ];
        var access_token = new JwtSecurityToken(jwtOptions.Issuer, request.ClientId, claims_at, signingCredentials: credentials_at,
            expires: DateTime.UtcNow.AddMinutes(
               int.Parse("5")));

        // here remoce the code from the Concurrent Dictionary
        this.RemoveClientDataByCode(request.Code);

        return new()
        {
            access_token = new JwtSecurityTokenHandler().WriteToken(access_token),
            id_token = id_token != null ? new JwtSecurityTokenHandler().WriteToken(id_token) : null,
            code = request.Code
        };
    }
}
