using System.Net.Http.Headers;
using Account.Models;
using Auth.Errors;
using Auth.Models;
using Idm.Common;
using Idm.OauthResponse;
using Microsoft.Extensions.Logging;
using MongoDB.Bson;

namespace Auth.Services;

public class AccountService : IAccountService
{
  private readonly HttpClient httpClient;
  private readonly ILogger logger;
  private readonly AccountOptions accountOptions;

  private string ListClientsUrl => $"{accountOptions.ApiUri}/home/list-clients";
  private string GetClientUrl(string id)
  {
    if (string.IsNullOrEmpty(accountOptions.ApiIp))
    {
      return $"{accountOptions.ApiUri}/home/client/{id}";
    }
    else
    {
      var uri = new Uri(accountOptions.ApiUri);
      var apiIpUri = new UriBuilder(uri.Scheme, accountOptions.ApiIp, uri.Port).Uri;

      return $"{apiIpUri}/home/client/{id}";
    }
  }
  private string GetClientHost() => new Uri(accountOptions.ApiUri).Host;

  public AccountService(HttpClient httpClient, AccountOptions accountOptions, ILogger<AccountService> logger)
  {
    this.httpClient = httpClient;
    this.accountOptions = accountOptions;
    this.logger = logger;
  }

  public async Task<(Client[]?, AuthError?)> ListClients()
  {
    var bearerToken = accountOptions.AccessToken;
    var request = new HttpRequestMessage(HttpMethod.Get, ListClientsUrl);
    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);

    try
    {
      var response = await httpClient.SendAsync(request);
      response.EnsureSuccessStatusCode();

      var jsonResponse = await response.Content.ReadAsStreamAsync();
      var result = jsonResponse.ToJson<ListClientsResponse>();
      if (result is null)
      {
        return (null, new(Error: ErrorTypeEnum.ServerError, Message: "Can't fetch clients. The response result is null"));
      }

      return (result.authClients, null);
    }
    catch (Exception ex)
    {
      logger.LogError("Error while fetching client list. Message:: {message}", ex.Message);

      return (null, new(Error: ErrorTypeEnum.ServerError, Message: "Error fetching client list"));
    }
  }

  public async Task<(Client?, AuthError?)> GetClient(string clientId)
  {
    var bearerToken = accountOptions.AccessToken;
    var request = new HttpRequestMessage(HttpMethod.Get, GetClientUrl(clientId));
    request.Headers.Host = GetClientHost();
    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);

    try
    {
      var response = await httpClient.SendAsync(request);
      response.EnsureSuccessStatusCode();

      var jsonResponse = await response.Content.ReadAsStreamAsync();
      var result = jsonResponse.ToJson<Client>();
      if (result is null)
      {
        return (null, new(Error: ErrorTypeEnum.ServerError, Message: "Can't fetch clients. The response result is null"));
      }

      return (result, null);
    }
    catch (Exception ex)
    {
      logger.LogError("Error while fetching client by id. Message:: {message}", ex.Message);
      return (null, new(Error: ErrorTypeEnum.ServerError, Message: $"Error fetching client '${clientId}'"));
    }
  }
}