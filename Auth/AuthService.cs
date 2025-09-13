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

using System.Security.Cryptography;
using AppConfiguration;
using Auth.Errors;
using BCrypt.Net;
using DnsClient.Protocol;
using Idm.Common;
using Idm.OauthRequest;
using Idm.OauthResponse;
using static Idm.OauthResponse.ErrorTypeEnum;

public class AuthService : IAuthService
{
  private readonly ConcurrentDictionary<string, AuthorizationCode> issuedCodes = new ConcurrentDictionary<string, AuthorizationCode>();
  private readonly MongoDbContext dbContext;
  private readonly IAccountService accountService;
  private readonly JwtOptions jwtOptions;

  public AuthService(MongoDbContext dbContext, IAccountService accountService, JwtOptions options)
  {
    this.dbContext = dbContext;
    jwtOptions = options;
    this.accountService = accountService;
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
      return (null, new AuthError(AccessDeniedInvalidPassword, "wrong password"));
    }

    this.EnsureSecurityGroup(user);

    var tokenHandler = new JwtSecurityTokenHandler();
    var key = Encoding.ASCII.GetBytes(jwtOptions.SecretKey);

    var tokenDescriptor = new SecurityTokenDescriptor
    {
      Subject = new ClaimsIdentity(
        [
            new ("sub", user.Id.ToString()),
                new ("oid", user.SecurityGroupId.ToString() ?? ""),
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
    var group = new SecurityGroup
    {
      GroupName = user.UserName,
    };
    user.Password = BCrypt.HashPassword(user.Password);
    dbContext.Users.Add(user);
    dbContext.SecurityGroups.Add(group);

    await dbContext.SaveChangesAsync();

    var createdUser = await dbContext.Users.FirstOrDefaultAsync(u => u.UserName == user.UserName);
    if (createdUser is null)
    {
      throw new Exception("User was not created");
    }

    this.EnsureSecurityGroup(createdUser);

    return user;
  }

  public async Task<(AuthorizeResponse?, AuthError?)> AuthorizeRequest(AuthorizationRequest authorizationRequest)
  {
    var (client, err) = await VerifyClientById(authorizationRequest.client_id);
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
      return (null, new(InvalidScope, "scopes are invalid"));
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
  public async Task<(AuthorizationCode?, AuthError?)> UpdatedClientDataByCode(
      string key, IEnumerable<string> requestdScopes, User user, string nonce
  )
  {
    var oldValue = GetClientDataByCode(key);

    if (oldValue is null)
    {
      return (null, new AuthError(InvalidRequest));
    }

    var (client, err) = await accountService.GetClient(oldValue.ClientId);
    if (client is null)
    {
      return (null, new AuthError(InvalidRequest));
    }

    var clientScope = from m in client.AllowedScopes
                      where requestdScopes.Contains(m)
                      select m;

    if (!clientScope.Any())
    {
      return (null, new(InvalidScope));
    }

    var newValue = oldValue with
    {
      IsOpenId = true,
      RequestedScopes = requestdScopes.ToArray(),
      Nonce = nonce,
      UserId = user.UserName,
      OpenId = user.SecurityGroupId.ToString() ?? ""
    };

    if (issuedCodes.TryUpdate(key, newValue, oldValue))
    {
      return (newValue, null);
    }

    return (null, new(InvalidCode));
  }

  public async Task<(TokenResponse?, AuthError?)> GenerateToken(TokenRequest request)
  {
    if (request.Code == null)
    {
      return (null, new(InvalidGrant));
    }

    var (client, err) = await VerifyClientById(request.ClientId, true, request.ClientSecret);
    if (client is null)
    {
      return (null, new(InvalidClient, Message: "Generate token error"));
    }

    // check code from the Concurrent Dictionary
    var clientCodeChecker = GetClientDataByCode(request.Code);
    if (clientCodeChecker is null)
    {
      return (null, new(InvalidGrant, "Can't find the login information"));
    }

    var user = await dbContext.Users.FirstOrDefaultAsync(user => user.UserName == clientCodeChecker.UserId);
    if (user is null)
    {
      return (null, new(AccessDenied, "User was not found"));
    }

    // check if the current client who is one made this authentication request
    if (request.ClientId != clientCodeChecker.ClientId)
    {
      return (null, new(InvalidGrant, "Something wrong with the provided ClientId"));
    }

    int iat = (int)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalSeconds;

    JwtSecurityToken? idToken = null;
    if (clientCodeChecker.IsOpenId)
    {
      idToken = GenerateIdToken(clientCodeChecker, user);
    }

    var accessToken = GenerateAccessToken(clientCodeChecker, client.ClientUri);
    var refreshToken = GenerateRefreshToken(clientCodeChecker, user.UserName);

    // here remoce the code from the Concurrent Dictionary
    RemoveClientDataByCode(request.Code);

    var since = EpochTime.GetIntDate(DateTime.Now);
    var expiresIn = long.Parse(accessToken.Claims.First(claim => claim.Type.Equals("exp")).Value);

    return (new(
        access_token: new JwtSecurityTokenHandler().WriteToken(accessToken),
        id_token: idToken != null ? new JwtSecurityTokenHandler().WriteToken(idToken) : null,
        refresh_token: new JwtSecurityTokenHandler().WriteToken(refreshToken),
        code: request.Code,
        expires_in: $"{expiresIn - since}"
    ), null);
  }

  public async Task<(TokenResponse?, AuthError?)> RefreshToken(string clientId, string refreshToken)
  {
    var (client, err) = await VerifyClientById(clientId);
    if (client is null)
    {
      return (null, err);
    }

    var principal = GetPrincipalFromExpiredToken(refreshToken, client.ClientSecret);
    var userName = principal?.Identity?.Name;
    if (string.IsNullOrEmpty(userName))
    {
      return (null, new(InvalidIdentityPrincipal, "Can't get valid principal from the provided refresh token"));
    }
    var user = await dbContext.Users.FirstOrDefaultAsync(user => user.UserName == userName);
    if (user is null)
    {
      return (null, new(AccessDenied, $"Can't find the user identified by '{userName}'"));
    }
    var scopesClaim = principal?.FindFirst(c => c.Type == "scopes" && c.Issuer == jwtOptions.Issuer);
    if (scopesClaim is null)
    {
      return (null, new(InvalidScope, "Can't get valid scope from the provided principal"));
    }
    var authCodeId = GenerateAuthorizationCode(client, scopesClaim.Value.Split(' '), refreshToken);
    (var code, err) = await UpdatedClientDataByCode(authCodeId, scopesClaim.Value.Split(' '), user, string.Empty);
    if (code is null)
    {
      return (null, err);
    }

    return await GenerateToken(new(
        ClientId: client.ClientId,
        GrantType: "refresh_token",
        ClientSecret: client.ClientSecret,
        Code: authCodeId,
        RedirectUri: null,
        CodeVerifier: null,
        RefreshToken: null
    ));
  }

  public async Task<(TokenResponse?, AuthError?)> GenerateAppToken(TokenRequest request)
  {
    var tokenExpirationInMinutes = 60 * 24 * 36 * 10;

    var (client, err) = await VerifyClientById(request.ClientId, true, request.ClientSecret);
    if (client is null)
    {
      return (null, err);
    }
    var key_at = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(client.ClientSecret));
    var credentials_at = new SigningCredentials(key_at, SecurityAlgorithms.HmacSha256);
    int iat = (int)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalSeconds;
    Claim[] claims_at = [
        new("iss", client.ClientUri),
            new("iat", iat.ToString(), ClaimValueTypes.Integer), // time stamp
            new("scopes", string.Join(' ', client.AllowedScopes)),
            new("exp", EpochTime.GetIntDate(DateTime.Now.AddMinutes(tokenExpirationInMinutes)).ToString(), ClaimValueTypes.Integer64),
        ];
    var accessToken = new JwtSecurityToken(jwtOptions.Issuer, request.ClientId, claims_at, signingCredentials: credentials_at,
        expires: DateTime.UtcNow.AddMinutes(tokenExpirationInMinutes));

    var since = EpochTime.GetIntDate(DateTime.Now);
    var expiresIn = long.Parse(accessToken.Claims.First(claim => claim.Type.Equals("exp")).Value);

    return (new(
        access_token: new JwtSecurityTokenHandler().WriteToken(accessToken),
        id_token: null,
        refresh_token: null,
        code: request.Code ?? string.Empty,
        token_type: "app_token",
        expires_in: $"{expiresIn - since}"
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
        OpenId: string.Empty,
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

  private async Task<(Client?, AuthError?)> VerifyClientById(string clientId, bool checkWithSecret = false, string? clientSecret = null)
  {
    if (string.IsNullOrWhiteSpace(clientId))
    {
      return (null, new(AccessDenied, "ClientId is null"));
    }

    var (client, err) = await accountService.GetClient(clientId);

    if (client is null)
    {
      return (null, new(AccessDenied, $"Can't find the client identified by '{clientId}'"));
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

  private JwtSecurityToken GenerateIdToken(AuthorizationCode authorizationCode, User user)
  {
    var tokenExpirationInMinutes = 5;
    string[] amrs = ["pwd"];
    var iat = (int)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalSeconds;

    var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(authorizationCode.ClientSecret));
    var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

    var claims = new List<Claim>()
        {
            new(ClaimTypes.Name, user.UserName),
            new(ClaimTypes.GivenName, user.Name),
            new(ClaimTypes.Role, user.Role),
            new(ClaimTypes.Email, user.UserName),
            new("sub", user.UserName),
            new("iat", iat.ToString(), ClaimValueTypes.Integer), // time stamp
            new("nonce", authorizationCode.Nonce),
            new("scopes", string.Join(' ', authorizationCode.RequestedScopes)),
            new("exp", EpochTime.GetIntDate(DateTime.Now.AddMinutes(tokenExpirationInMinutes)).ToString(), ClaimValueTypes.Integer64),
        };
    foreach (var amr in amrs)
    {
      claims.Add(new Claim("amr", amr)); // authentication method reference
    }

    return new JwtSecurityToken(jwtOptions.Issuer, authorizationCode.ClientId, claims,
        signingCredentials: credentials,
        expires: DateTime.UtcNow.AddMinutes(tokenExpirationInMinutes)
    );
  }

  private JwtSecurityToken GenerateAccessToken(AuthorizationCode authorizationCode, string clientUri)
  {
    var tokenExpirationInMinutes = 60;
    var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(authorizationCode.ClientSecret));
    var clientCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
    var iat = (int)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalSeconds;

    Claim[] userClaims = [
        new("oid", authorizationCode.OpenId),
            new("iss", clientUri),
            new("iat", iat.ToString(), ClaimValueTypes.Integer), // time stamp
            new("scopes", string.Join(' ', authorizationCode.RequestedScopes)),
            new("exp", EpochTime.GetIntDate(DateTime.Now.AddMinutes(tokenExpirationInMinutes)).ToString(), ClaimValueTypes.Integer64),
        ];
    return new JwtSecurityToken(jwtOptions.Issuer, authorizationCode.ClientId, userClaims, signingCredentials: clientCredentials,
        expires: DateTime.UtcNow.AddMinutes(tokenExpirationInMinutes));
  }

  private JwtSecurityToken GenerateRefreshToken(AuthorizationCode authorizationCode, string userName)
  {
    var tokenExpirationInMinutes = 2 * 25 * 60;
    var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(authorizationCode.ClientSecret));
    var clientCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
    var iat = (int)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalSeconds;

    Claim[] userClaims = [
        new(ClaimTypes.Name, userName),
            new("sub", authorizationCode.UserId ?? userName),
            new("scopes", string.Join(' ', authorizationCode.RequestedScopes)),
            new("iat", iat.ToString(), ClaimValueTypes.Integer), // time stamp
            new("exp", EpochTime.GetIntDate(DateTime.Now.AddMinutes(tokenExpirationInMinutes)).ToString(), ClaimValueTypes.Integer64),
        ];

    return new JwtSecurityToken(jwtOptions.Issuer, authorizationCode.ClientId, userClaims,
        signingCredentials: clientCredentials,
        expires: DateTime.UtcNow.AddMinutes(tokenExpirationInMinutes));
  }

  private ClaimsPrincipal GetPrincipalFromExpiredToken(string token, string clientSecret)
  {
    var tokenValidationParameters = new TokenValidationParameters
    {
      ValidateAudience = false,
      ValidateIssuer = false,
      ValidateIssuerSigningKey = true,
      IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(clientSecret)),
      ValidateLifetime = false
    };

    var tokenHandler = new JwtSecurityTokenHandler();
    var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
    if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
      throw new SecurityTokenException("Invalid token");

    return principal;
  }

  private void EnsureSecurityGroup(User user)
  {
    if (user.SecurityGroupId is not null)
    {
      return;
    }

    var group = new SecurityGroup
    {
      GroupName = user.UserName,
    };
    dbContext.SecurityGroups.Add(group);
    dbContext.SaveChanges();
    user.SecurityGroupId = group.Id;
    dbContext.SaveChanges();
  }
}
