using System.ComponentModel;
using System.Text.Json;

namespace Idm.Common;

public static class ExtensionMethods
{
  public static string GetEnumDescription(this Enum value)
  {
    var fi = value.GetType().GetField(value.ToString());

    var attributes = fi?.GetCustomAttributes(typeof(DescriptionAttribute), false) as DescriptionAttribute[];

    if (attributes != null && attributes.Length != 0)
    {
      return attributes.First().Description;
    }

    return value.ToString();
  }

  public static bool IsRedirectUriStartWithHttps(this string redirectUri)
  {
    if (redirectUri != null && redirectUri.StartsWith("https")) return true;

    return false;
  }

  public static T? ToJson<T>(this Stream? value)
  {
    if (value is null)
    {
      return default;
    }

    return JsonSerializer.Deserialize<T>(value, new JsonSerializerOptions
    {
      PropertyNameCaseInsensitive = true
    });
  }
}