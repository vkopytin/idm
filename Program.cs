using AppConfiguration;
using Auth;
using Auth.Db;
using Auth.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;

IdentityModelEventSource.ShowPII = true;

var builder = WebApplication.CreateBuilder(args);

var jwtSecretKey = builder.Configuration["JWT:SecretKey"] ?? throw new Exception("appsettings config error: JWT secret key is null");
var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? throw new Exception("appsettings config error: JWT issues is not specified");
var apiCorsPolicy = "ApiCorsPolicy";

builder.Services.AddSingleton(p => p.GetRequiredService<IConfiguration>().GetSection("Jwt")
  .Get<JwtOptions>() ?? throw new Exception("appsetings missing JWT section")
);
builder.Services.AddSingleton(p => p.GetRequiredService<IConfiguration>().GetSection("Account")
  .Get<AccountOptions>() ?? throw new Exception("appsettings missing Account:AccessToken"));
builder.Services.AddHttpClient();
builder.Services.AddHttpContextAccessor();
builder.Services.AddCors(options =>
{
  options.AddPolicy(name: apiCorsPolicy,
  builder =>
  {
    builder.AllowCredentials()
      .WithOrigins(
        "http://local-dev.azurewebsites.net:4200", "http://localhost:4200", "http://dev.local:4200",
        "https://local-dev.azurewebsites.net:4200", "https://localhost:4200", "https://dev.local:4200",
        "https://local-dev.azurewebsites.net", "https://localhost", "https://dev.local",
        "https://vko-idm.azurewebsites.net"
      )
      .AllowAnyHeader()
      .AllowAnyMethod()
      .WithExposedHeaders("Authorization")
      ;
  });
});

//builder.Services.AddDbContext<ApplicationDbContext>(opt => opt.UseInMemoryDatabase("UsersList"));
var client = builder.Configuration.CreateMongoClient("MongoDBConnection");
builder.Services.AddTransient(o =>
{
  return new MongoDbContext(client);
});
builder.Services.AddSingleton<IAuthService, AuthService>();
builder.Services.AddTransient<IAccountService, AccountService>();
builder.Services.AddAuthorization(options =>
{
  var scopes = new[] {
    "read:user-info",
    "update:billing_settings",
    "read:customers",
    "read:files"
  };

  Array.ForEach(scopes, scope =>
    options.AddPolicy(scope,
      policy => policy.Requirements.Add(
        new ScopeRequirement(jwtIssuer, scope)
      )
    )
  );
}).AddAuthentication(opt =>
{
  opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
  opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(opt =>
{
  // for development only
  opt.Audience = builder.Configuration["JWT:Audience"];
  opt.RequireHttpsMetadata = false;
  opt.SaveToken = true;
  opt.TokenValidationParameters = new TokenValidationParameters
  {
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(jwtSecretKey)),
    ValidateIssuer = true,
    ValidIssuers = [jwtIssuer],
    ValidIssuer = jwtIssuer,
    ValidateAudience = true,
    ValidAudiences = [builder.Configuration["JWT:Audience"]],
  };
  opt.Events = new JwtBearerEvents
  {
    OnMessageReceived = context =>
    {
      var authToken = $"{context.Request.Headers["Authorization"]}";
      if (authToken.StartsWith("Bearer"))
      {
        context.Token = authToken.Substring("Bearer ".Length).Trim();
        return Task.CompletedTask;
      }
      context.Token = context.Request.Cookies["token"];
      return Task.CompletedTask;
    }
  };
});
builder.Services.AddHealthChecks();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
  c.SwaggerDoc("v1", new OpenApiInfo
  {
    Title = "JWT Auth Sample",
    Version = "v1"
  });
  c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme()
  {
    Name = "Authorization",
    Type = SecuritySchemeType.ApiKey,
    Scheme = "Bearer",
    BearerFormat = "JWT",
    In = ParameterLocation.Header,
    Description = "JWT Authorization header using the Bearer scheme. \r\n\r\n Enter 'Bearer' [space] and then your token in the text input below.\r\n\r\nExample: \"Bearer jhfdkj.jkdsakjdsa.jkdsajk\"",
  });
  c.AddSecurityRequirement(new OpenApiSecurityRequirement {
        {
            new OpenApiSecurityScheme {
                Reference = new OpenApiReference {
                    Type = ReferenceType.SecurityScheme,
                        Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});

builder.Services.AddSingleton<IAuthorizationHandler, RequireScopeHandler>();
builder.Services.AddControllersWithViews().AddRazorRuntimeCompilation();
var app = builder.Build();

app.UsePathBase("/api");

app.UseCors(apiCorsPolicy);

app.UseSwagger();

app.UseSwaggerUI();

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.MapHealthChecks("/health");

app.Run();