using System.Text.Json;
using System.Text.Json.Serialization;
using AppConfiguration;
using Auth.Models.Google;
using Idm.OauthRequest;

namespace Auth.Services;

record PersonResponse(string ResourceName, string ETag, List<Name> Names);

record Name(
  Metadata Metadata,
  string DisplayName,
  string FamilyName,
  string GivenName,
  string DisplayNameLastFirst,
  string UnstructuredName
);

record Metadata(bool Primary, Source Source);

record Source(string Type, string Id);

public class GoogleService
{
  private readonly HttpClient httpClient;
  private readonly MainSettings settings;

  public GoogleService(HttpClient httpClient, MainSettings settings)
  {
    this.httpClient = httpClient;
    this.settings = settings;
  }

  public string BuildAuthUrl(OpenIdConnectLoginRequest options)
  {
    const string baseAuthUri = "https://accounts.google.com/o/oauth2/v2/auth";
    var authUriQueryParams = new Dictionary<string, string>
    {
      ["client_id"] = settings.Google.ClientId,
      ["redirect_uri"] = settings.Google.RedirectUri,
      ["response_type"] = "code",
      ["scope"] = "https://www.googleapis.com/auth/youtube.readonly https://www.googleapis.com/auth/userinfo.profile", // add the scopes you need
      ["access_type"] = "offline" // request a refresh token
    };

    var authUri = $"{baseAuthUri}?{string.Join("&", authUriQueryParams.Select(kvp => $"{kvp.Key}={Uri.EscapeDataString(kvp.Value)}"))}";

    return authUri;
  }

  public async Task<(TokenResponse? response, string? error)> GetAccessTokenAsync(string code)
  {
    const string tokenUri = "https://oauth2.googleapis.com/token";
    var tokenRequestParams = new Dictionary<string, string>
    {
      ["code"] = code,
      ["client_id"] = settings.Google.ClientId,
      ["client_secret"] = settings.Google.ClientSecret,
      ["redirect_uri"] = settings.Google.RedirectUri,
      ["grant_type"] = "authorization_code"
    };

    var tokenRequest = new HttpRequestMessage(HttpMethod.Post, tokenUri)
    {
      Content = new FormUrlEncodedContent(tokenRequestParams)
    };

    var tokenResponse = await httpClient.SendAsync(tokenRequest);
    var tokenResponseContent = await tokenResponse.Content.ReadAsStringAsync();

    if (tokenResponse.IsSuccessStatusCode is false)
    {
      return (null, "Failed to get access token.");
    }

    var token = JsonSerializer.Deserialize<TokenResponse>(tokenResponseContent);

    if (token is null)
    {
      return (null, "Failed to parse access token response.");
    }

    return (token, null);
  }

  public async Task<(string? result, string? error)> ListYoutubeSubscriptions(TokenResponse token)
  {
    const string subscriptionsUri = "https://www.googleapis.com/youtube/v3/subscriptions?part=snippet&mine=true";
    var subscriptionsRequest = new HttpRequestMessage(HttpMethod.Get, subscriptionsUri);
    subscriptionsRequest.Headers.Add("Authorization", $"Bearer {token.AccessToken}");

    var subscriptionsResponse = await httpClient.SendAsync(subscriptionsRequest);
    var subscriptionsResponseContent = await subscriptionsResponse.Content.ReadAsStringAsync();

    if (subscriptionsResponse.IsSuccessStatusCode is false)
    {
      return (null, $"Failed to get YouTube subscriptions: {subscriptionsResponseContent}");
    }

    return (subscriptionsResponseContent, null);
  }

  public async Task<(string? result, string? error)> GetUsersNameAsync(TokenResponse token)
  {
    const string userInfoUri = "https://people.googleapis.com/v1/people/me?personFields=names";
    var userInfoRequest = new HttpRequestMessage(HttpMethod.Get, userInfoUri);
    userInfoRequest.Headers.Add("Authorization", $"Bearer {token.AccessToken}");

    using var httpClient = new HttpClient();
    var userInfoResponse = await httpClient.SendAsync(userInfoRequest);
    var userInfoResponseContent = await userInfoResponse.Content.ReadAsStringAsync();

    if (userInfoResponse.IsSuccessStatusCode is false)
    {
      return (null, $"Failed to get user info: {userInfoResponseContent}");
    }

    if (string.IsNullOrEmpty(userInfoResponseContent))
    {
      return (null, $"User info response is empty.");
    }

    var userInfo = JsonSerializer.Deserialize<PersonResponse>(userInfoResponseContent, new JsonSerializerOptions
    {
      PropertyNameCaseInsensitive = true
    });

    if (userInfo is null)
    {
      return (null, $"Failed to parse user info response.");
    }

    return (userInfo.Names[0].DisplayName, null);
  }

}
