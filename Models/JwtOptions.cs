namespace AppConfiguration;

public record JwtOptions
(
   string SecretKey,
   string Issuer,
   string Audience
);
