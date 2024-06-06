using System;
using System.ComponentModel;
using System.Linq;

namespace Idm.Common;

public static class ExtensionMethods
{
  public static string GetEnumDescription(this Enum value)
  {
    var fi = value.GetType().GetField(value.ToString());

    var attributes = fi?.GetCustomAttributes(typeof(DescriptionAttribute), false) as DescriptionAttribute[];

    if (attributes != null && attributes.Any())
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
}