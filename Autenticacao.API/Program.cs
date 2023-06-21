

using Autenticacao.API.Configuration;
using Autenticacao.API.Data;
using Autenticacao.API.Model;
using Autenticacao.API.Settings;
using Core.Util.Email;
using Core.Util.Email.Interface;
using Core.Util.Email.Service;
using Core.Util.Jwt;
using Microsoft.AspNetCore.Identity;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.


builder.Services.AddMvc();

builder.Services.AddControllers()
    .AddJsonOptions(
        options => options.JsonSerializerOptions.PropertyNamingPolicy = null);

builder.Services.AddJwtConfiguration(builder.Configuration);

builder.Services.AddSwaggerConfiguration();

builder.Services.Configure<EmailSettings>(builder.Configuration.GetSection("EmailSettings"));

builder.Services.AddControllers();
builder.Services.AddCors(options =>
{
    options.AddPolicy("Total",
        builder =>
            builder
                .AllowAnyOrigin()
                .AllowAnyMethod()
                .AllowAnyHeader());
});
var mongoDbSettings = builder.Configuration.GetSection(nameof(MongoDbConfig)).Get<MongoDbConfig>();


builder.Services.AddIdentity<ApplicationUser, ApplicationRole>(
        identity =>
        {
            // Password settings.
            identity.Password.RequiredLength = 6;
            identity.Password.RequireLowercase = true;
            identity.Password.RequireUppercase = true;
            identity.Password.RequireNonAlphanumeric = false;
            identity.Password.RequireDigit = true;

            // Lockout settings.
            identity.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
            identity.Lockout.MaxFailedAccessAttempts = 5;
            identity.Lockout.AllowedForNewUsers = true;

            // User settings.
            identity.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._";
            identity.User.RequireUniqueEmail = true;
        }
    )
    .AddErrorDescriber<IdentityPortugueseMessages>()
    .AddMongoDbStores<ApplicationUser, ApplicationRole, Guid>
    (
        mongoDbSettings.ConnectionString, mongoDbSettings.Name
    )
    .AddDefaultTokenProviders();

//builder.Services.AddAuthentication()
//        .AddGoogle(opts =>
//        {
//            opts.ClientId = "717469225962-3vk00r8tglnbts1cgc4j1afqb358o8nj.apps.googleusercontent.com";
//            opts.ClientSecret = "babQzWPLGwfOQVi0EYR-7Fbb";
//            opts.SignInScheme = IdentityConstants.ExternalScheme;
//        })
//        .AddFacebook(options =>
//        {
//            IConfigurationSection FBAuthNSection =
//            builder.Configuration.GetSection("Authentication:FB");
//            options.ClientId = FBAuthNSection["ClientId"];
//            options.ClientSecret = FBAuthNSection["ClientSecret"];
//        })
//       .AddMicrosoftAccount(microsoftOptions =>
//       {
//           microsoftOptions.ClientId = builder.Configuration["Authentication:Microsoft:ClientId"];
//           microsoftOptions.ClientSecret = builder.Configuration["Authentication:Microsoft:ClientSecret"];
//       })
//       .AddTwitter(twitterOptions =>
//       {
//           twitterOptions.ConsumerKey = builder.Configuration["Authentication:Twitter:ConsumerAPIKey"];
//           twitterOptions.ConsumerSecret = builder.Configuration["Authentication:Twitter:ConsumerSecret"];
//           twitterOptions.RetrieveUserDetails = true;
//       });


builder.Services.AddSingleton<IPasswordHasher<ApplicationUser>, UserPasswordHasher>();
builder.Services.AddSingleton<IEmailHelper, EmailHelper>();

builder.Services.AddSingleton<IdentityServerService>();
builder.Services.AddSingleton<JwtService>();

var app = builder.Build();


app.UseHttpsRedirection();

app.UseSwaggerConfiguration();

app.MapControllers();

app.UseRouting();

app.UseCors("Total");
app.UseAuthConfiguration();

app.UseEndpoints(endpoints =>
{
    endpoints.MapControllers();
});

app.Run();
