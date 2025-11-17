using Auth.Db;
using Auth.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Idm.Models;
using Microsoft.EntityFrameworkCore;
using AppConfiguration;
using Auth.Errors;
using Idm.Common;
using Idm.OauthRequest;
using Idm.OauthResponse;

namespace Auth;

using BCrypt.Net;

using static Idm.OauthResponse.ErrorTypeEnum;

public class AuthService : IAuthService
{
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

    await this.EnsureSecurityGroup(user);

    var tokenHandler = new JwtSecurityTokenHandler();
    var key = Encoding.ASCII.GetBytes(jwtOptions.SecretKey);

    var tokenDescriptor = new SecurityTokenDescriptor
    {
      Subject = new ClaimsIdentity([
        new ("sub", user.Id.ToString()),
        new ("oid", user.SecurityGroupId.ToString() ?? ""),
        new ("roles", user.Role),
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

  public async Task<(User?, AuthError?)> Register(User user)
  {
    var group = new SecurityGroup
    {
      GroupName = user.UserName,
    };
    var password = BCrypt.HashPassword(user.Password);
    var existing = await dbContext.Users.FirstOrDefaultAsync(u => u.UserName == user.UserName);
    if (existing is not null)
    {
      return (null, new AuthError(UserExists, "User already exists"));
    }
    user.Password = password;
    await dbContext.Users.AddAsync(user);
    await dbContext.SecurityGroups.AddAsync(group);

    await dbContext.SaveChangesAsync();

    var createdUser = await dbContext.Users.FirstOrDefaultAsync(u => u.UserName == user.UserName);
    if (createdUser is null)
    {
      return (null, new AuthError(ErrorCreatingUser, "User was not created"));
    }

    await this.EnsureSecurityGroup(createdUser);

    return (createdUser, null);
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

    var code = await GenerateAuthorizationCode(client, clientScopes.ToArray(), authorizationRequest.nonce);
    if (code == null)
    {
      return (null, new(TemporarilyUnAvailable));
    }

    return (new(
        RedirectUri: client.RedirectUri + "?response_type=code&state=" + authorizationRequest.state,
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
    var oldValue = await GetClientDataByCode(key);

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

    var existing = await dbContext.AuthCodes.FindAsync(Guid.Parse(key));

    if (existing is null)
    {
      return (null, new(InvalidCode));
    }

    existing.IsOpenId = true;
    existing.RequestedScopes = requestdScopes.ToArray();
    existing.Nonce = nonce;
    existing.UserId = user.UserName;
    existing.OpenId = user.SecurityGroupId.ToString() ?? "";

    dbContext.AuthCodes.Update(existing);
    await dbContext.SaveChangesAsync();

    return (AuthorizationCode.FromModel(existing), null);
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
    var clientCodeChecker = await GetClientDataByCode(request.Code);
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

    var accessToken = GenerateAccessToken(clientCodeChecker, client.ClientUri, user.Role);
    var refreshToken = GenerateRefreshToken(clientCodeChecker, user.UserName);

    // toDO: find how to here remove the code from the Concurrent Dictionary
    // and use for google token renew another approach
    //RemoveClientDataByCode(request.Code);

    var since = EpochTime.GetIntDate(DateTime.Now);
    var expiresAt = long.Parse(accessToken.Claims.First(claim => claim.Type.Equals("exp")).Value);

    return (new(
        access_token: new JwtSecurityTokenHandler().WriteToken(accessToken),
        id_token: idToken != null ? new JwtSecurityTokenHandler().WriteToken(idToken) : null,
        refresh_token: new JwtSecurityTokenHandler().WriteToken(refreshToken),
        code: request.Code,
        expires_in: $"{expiresAt - since}"
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
    var authCodeId = await GenerateAuthorizationCode(client, scopesClaim.Value.Split(' '), refreshToken);
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
    var expiresAt = long.Parse(accessToken.Claims.First(claim => claim.Type.Equals("exp")).Value);

    return (new(
      access_token: new JwtSecurityTokenHandler().WriteToken(accessToken),
      id_token: null,
      refresh_token: null,
      code: request.Code ?? string.Empty,
      token_type: "app_token",
      expires_in: $"{expiresAt - since}"
    ), null);
  }

  private async Task<string> GenerateAuthorizationCode(Client client, IEnumerable<string> requestedScope, string nonce)
  {
    var code = Guid.NewGuid();

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

    var record = authoCode.ToModel();
    record.Id = code;
    await dbContext.AuthCodes.AddAsync(record);
    await dbContext.SaveChangesAsync();

    return code.ToString();
  }

  private async Task<AuthorizationCode?> GetClientDataByCode(string key)
  {
    var existing = await dbContext.AuthCodes.FindAsync(Guid.Parse(key));
    if (existing is not null)
    {
      return AuthorizationCode.FromModel(existing);
    }

    return null;
  }

  private AuthorizationCode? RemoveClientDataByCode(string key)
  {
    var existing = dbContext.AuthCodes.Find(Guid.Parse(key));
    if (existing is null)
    {
      return null;
    }

    var authorizationCode = AuthorizationCode.FromModel(existing);
    dbContext.AuthCodes.Remove(existing);
    dbContext.SaveChanges();

    return authorizationCode;
  }

  private async Task<(Client?, AuthError?)> VerifyClientById(string clientId, bool checkWithSecret = false, string? clientSecret = null)
  {
    if (string.IsNullOrWhiteSpace(clientId))
    {
      return (null, new(AccessDenied, "ClientId is null"));
    }

    var (client, err) = await accountService.GetClient(clientId);

    if (err?.Error == ServerError)
    {
      return (null, new(TemporarilyUnAvailable, err?.Message));
    }

    if (client is null)
    {
      return (null, new(AccessDenied, $"Can't find the client identified by '{clientId}'"));
    }

    if (checkWithSecret && !string.IsNullOrEmpty(clientSecret))
    {
      bool hasSamesecretId = client.ClientSecret.Equals(clientSecret, StringComparison.InvariantCulture);
      if (!hasSamesecretId)
      {
        return (null, new(InvalidClient, "Client secret is not valid"));
      }
    }

    if (client.IsActive)
    {
      return (client, null);
    }

    return (null, new(UnAuthoriazedClient, "Client is not active"));
  }

  private JwtSecurityToken GenerateIdToken(AuthorizationCode authorizationCode, User user)
  {
    var tokenExpirationInMinutes = 60;
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

  private JwtSecurityToken GenerateAccessToken(AuthorizationCode authorizationCode, string clientUri, string userRole)
  {
    var tokenExpirationInMinutes = 60;
    var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(authorizationCode.ClientSecret));
    var clientCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
    var iat = (int)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalSeconds;

    Claim[] userClaims = [
      new("jti", Guid.NewGuid().ToString()),
      new("oid", authorizationCode.OpenId),
      new("roles", userRole),
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
      new("jti", Guid.NewGuid().ToString()),
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

  private async Task EnsureSecurityGroup(User user)
  {
    if (user.SecurityGroupId is null)
    {
      var group = new SecurityGroup
      {
        GroupName = user.UserName,
      };
      await dbContext.SecurityGroups.AddAsync(group);
      await dbContext.SaveChangesAsync();
      user.SecurityGroupId = group.Id;
      await dbContext.SaveChangesAsync();
    }

    var webSite = await dbContext.WebSites.FirstOrDefaultAsync(ws => ws.UserId == user.Id);
    if (webSite is null)
    {
      var newWebSite = new WebSite
      {
        UserId = user.Id,
        HostName = $"{user.UserName.ToLower().Replace(" ", "-")}.local"
      };
      await dbContext.WebSites.AddAsync(newWebSite);
      await dbContext.SaveChangesAsync();
    }
  }
}
