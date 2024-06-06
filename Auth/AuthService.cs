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
using Auth.Errors;
using BCrypt.Net;
using Idm.Auth.Models;
using Idm.Common;
using Idm.OauthRequest;
using Idm.OauthResponse;
using static Idm.OauthResponse.ErrorTypeEnum;

public class AuthService : IAuthService
{
    private readonly ConcurrentDictionary<string, AuthorizationCode> issuedCodes = new ConcurrentDictionary<string, AuthorizationCode>();
    private readonly ClientStore clientStore = new();
    private readonly MongoDbContext dbContext;
    private readonly JwtOptions jwtOptions;

    public AuthService(MongoDbContext dbContext, JwtOptions options)
    {
        this.dbContext = dbContext;
        jwtOptions = options;
    }

    public async Task<(User?, AuthError?)> Login(string email, string password, string scopes)
    {
        var user = await dbContext.Users.FirstOrDefaultAsync(user => user.UserName == email);
        if (user is null)
        {
            return (null, new AuthError(AccessDenied, "login not found"));
        }

        if (BCrypt.Verify(password, user.Password) == false)
        {
            return (null, new AuthError(AccessDenied, "wrong password"));
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

        return (user, null);
    }

    public async Task<User> Register(User user)
    {
        user.Password = BCrypt.HashPassword(user.Password);
        dbContext.Users.Add(user);

        await dbContext.SaveChangesAsync();

        return user;
    }

    public (AuthorizeResponse?, AuthError?) AuthorizeRequest(AuthorizationRequest authorizationRequest)
    {
        var (client, err) = VerifyClientById(authorizationRequest.client_id);
        if (client is null)
        {
            return (null, new(InvalidClient, err?.Error.GetEnumDescription()));
        }

        if (authorizationRequest.response_type != "code")
        {
            return (null, new(InvalidRequest, "response_type is required or is not valid"));
        }

        if (!authorizationRequest.redirect_uri.IsRedirectUriStartWithHttps())
        {
            return (null, new(InvalidRequest, "redirect_url is not secure, MUST be TLS"));
        }

        var scopes = authorizationRequest.scope.Split(' ');

        var clientScopes = from m in client.AllowedScopes
                           where scopes.Contains(m)
                           select m;

        if (!clientScopes.Any())
        {
            return (null, new(InValidScope, "scopes are invalid"));
        }

        var code = GenerateAuthorizationCode(client, clientScopes.ToArray(), authorizationRequest.nonce);
        if (code == null)
        {
            return (null, new(TemporarilyUnAvailable));
        }

        return (new(
            RedirectUri: client.RedirectUri + "?response_type=code" + "&state=" + authorizationRequest.state,
            Code: code,
            State: authorizationRequest.state,
            RequestedScopes: clientScopes.ToList(),
            Nonce: authorizationRequest.nonce
        ), null);
    }

    // Before updated the Concurrent Dictionary I have to Process User Sign In,
    // and check the user credienail first
    // But here I merge this process here inside update Concurrent Dictionary method
    public (AuthorizationCode?, AuthError?) UpdatedClientDataByCode(string key, IEnumerable<string> requestdScopes,
        string userName, string nonce)
    {
        var oldValue = GetClientDataByCode(key);

        if (oldValue is null)
        {
            return (null, new AuthError(InvalidRequest));
        }

        // check the requested scopes with the one that are stored in the Client Store 
        var client = clientStore.Clients.Where(x => x.ClientId == oldValue.ClientId).FirstOrDefault();
        if (client is null)
        {
            return (null, new AuthError(InvalidRequest));
        }

        var clientScope = from m in client.AllowedScopes
                          where requestdScopes.Contains(m)
                          select m;

        if (!clientScope.Any())
        {
            return (null, new(InValidScope));
        }

        var newValue = oldValue with
        {
            IsOpenId = requestdScopes.Contains("openId") || requestdScopes.Contains("profile"),
            RequestedScopes = requestdScopes.ToArray(),
            Nonce = nonce,
            UserId = userName
        };

        var result = issuedCodes.TryUpdate(key, newValue, oldValue);

        if (result)
        {
            return (newValue, null);
        }

        return (null, new(InvalidCode));
    }

    public async Task<(TokenResponse?, AuthError?)> GenerateToken(TokenRequest request)
    {
        var tokenExpirationInMinutes = 5;
        if (request.Code == null)
        {
            return (null, new(InvalidGrant));
        }

        var (client, err) = VerifyClientById(request.ClientId, true, request.ClientSecret);
        if (client is null)
        {
            return (null, err);
        }

        // check code from the Concurrent Dictionary
        var clientCodeChecker = GetClientDataByCode(request.Code);
        if (clientCodeChecker is null)
        {
            return (null, new(InvalidGrant));
        }

        var user = await dbContext.Users.FirstOrDefaultAsync(user => user.UserName == clientCodeChecker.UserId);
        if (user is null)
        {
            return (null, new(AccessDenied));
        }
        // check if the current client who is one made this authentication request

        if (request.ClientId != clientCodeChecker.ClientId)
        {
            return (null, new(InvalidGrant));
        }

        int iat = (int)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalSeconds;

        JwtSecurityToken? id_token = null;
        if (clientCodeChecker.IsOpenId)
        {
            string[] amrs = ["pwd"];

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(client.ClientSecret));
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
                new("exp", EpochTime.GetIntDate(DateTime.Now.AddMinutes(tokenExpirationInMinutes)).ToString(), ClaimValueTypes.Integer64),
            };
            foreach (var amr in amrs)
            {
                claims.Add(new Claim("amr", amr)); // authentication method reference
            }

            id_token = new JwtSecurityToken(jwtOptions.Issuer, request.ClientId, claims,
                signingCredentials: credentials,
                expires: DateTime.UtcNow.AddMinutes(tokenExpirationInMinutes)
            );
        }

        // Here I have to generate access token 
        var key_at = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(client.ClientSecret));
        var credentials_at = new SigningCredentials(key_at, SecurityAlgorithms.HmacSha256);

        Claim[] claims_at = [
            new("iss", client.ClientUri),
            new("iat", iat.ToString(), ClaimValueTypes.Integer), // time stamp
            new("scopes", "read:files"),
            new("exp", EpochTime.GetIntDate(DateTime.Now.AddMinutes(tokenExpirationInMinutes)).ToString(), ClaimValueTypes.Integer64),
        ];
        var access_token = new JwtSecurityToken(jwtOptions.Issuer, request.ClientId, claims_at, signingCredentials: credentials_at,
            expires: DateTime.UtcNow.AddMinutes(tokenExpirationInMinutes));

        // here remoce the code from the Concurrent Dictionary
        RemoveClientDataByCode(request.Code);

        return (new
        (
            access_token: new JwtSecurityTokenHandler().WriteToken(access_token),
            id_token: id_token != null ? new JwtSecurityTokenHandler().WriteToken(id_token) : null,
            code: request.Code
        ), null);
    }

    private string GenerateAuthorizationCode(Client client, IEnumerable<string> requestedScope, string nonce)
    {
        var code = Guid.NewGuid().ToString();

        var authoCode = new AuthorizationCode
        (
            ClientId: client.ClientId,
            ClientSecret: client.ClientSecret,
            RedirectUri: client.RedirectUri,
            RequestedScopes: requestedScope.ToArray(),
            CreationTime: DateTime.Now,
            Nonce: nonce
        );

        // then store the code is the Concurrent Dictionary
        issuedCodes[code] = authoCode;

        return code;

    }

    private AuthorizationCode? GetClientDataByCode(string key)
    {
        if (issuedCodes.TryGetValue(key, out var authorizationCode))
        {
            return authorizationCode;
        }

        return null;
    }

    private AuthorizationCode? RemoveClientDataByCode(string key)
    {
        issuedCodes.TryRemove(key, out var authorizationCode);

        return authorizationCode;
    }

    private (Client?, AuthError?) VerifyClientById(string clientId, bool checkWithSecret = false, string? clientSecret = null)
    {
        if (string.IsNullOrWhiteSpace(clientId))
        {
            return (null, new(AccessDenied));
        }

        var client = clientStore.findByClientId(clientId);

        if (client is null)
        {
            return (null, new(AccessDenied));
        }

        if (checkWithSecret && !string.IsNullOrEmpty(clientSecret))
        {
            bool hasSamesecretId = client.ClientSecret.Equals(clientSecret, StringComparison.InvariantCulture);
            if (!hasSamesecretId)
            {
                return (null, new(InvalidClient));
            }
        }

        if (client.IsActive)
        {
            return (client, null);
        }

        return (null, new(UnAuthoriazedClient));
    }
}
