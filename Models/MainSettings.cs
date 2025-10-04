namespace AppConfiguration;

public record GoogleOptions
(
   string ClientId,
   string ClientSecret,
    string RedirectUri
);

public record MainSettings
(
  JwtOptions Jwt,
  AccountOptions Account,
  GoogleOptions Google
);
