using AzureADB2CWeb.Data;
using AzureADB2CWeb.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AzureADB2CWeb
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public static string AzureADB2CHostName = "badrazureadb2c.b2clogin.com";
        public static string Tanent = "BadrAzureADB2C.onmicrosoft.com";
        public static string ClientId = "423cc6e8-1aff-46bf-a9d4-868b0e5a5fc1";
        public static string PolicySignUpSignIn = "B2C_1_SignIn_Up";
        public static string PolicyEditProfile = "B2C_1_Edit";
        public static string Scope = "https://BadrAzureADB2C.onmicrosoft.com/AzureADB2CAPI/fullAccess";
        public static string ClientSecret = "QmOMu6qM4Q4mhA9E--Omm-JuEj3G43FVf-";

        public static string AuthotiryBase = $"https://{AzureADB2CHostName}/{Tanent}/";
        public static string AuthotirySainUpSignIn = $"{AuthotiryBase}{PolicySignUpSignIn}/v2.0";
        public static string AuthotiryEditProfile = $"{AuthotiryBase}{PolicyEditProfile}/v2.0";

        

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {

            services.AddHttpContextAccessor();

            services.AddDbContext<ApplicationDbContext>(options=>
            
                options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection"))
            );

            services.AddHttpClient();

            // clint secret value : QmOMu6qM4Q4mhA9E--Omm-JuEj3G43FVf-
            //Application ClientId : 423cc6e8-1aff-46bf-a9d4-868b0e5a5fc1

            services.AddControllersWithViews();
            services.AddScoped<IUserService, UserService>();
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            }
            ).AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options => {
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.Authority = Startup.AuthotirySainUpSignIn;
                options.ClientId = Startup.ClientId;
                options.ResponseType = "code";
                options.SaveTokens = true;
                options.Scope.Add(Startup.Scope);
                options.ClientSecret = Startup.ClientSecret;
                options.TokenValidationParameters = new TokenValidationParameters()
                {
                    NameClaimType = "name"

                    // if you want givnName
                    //NameClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
                };
                // to use [Authorize(Roles="")] with my custome role
                options.Events = new OpenIdConnectEvents
                {
                    OnTokenValidated = async opt =>
                    {
                        string role = opt.Principal.FindFirstValue("extension_UserRole");
                        var claims = new List<Claim>
                        {
                            new Claim(ClaimTypes.Role , role)
                        };
                        var appIdentity = new ClaimsIdentity(claims);
                        opt.Principal.AddIdentity(appIdentity);
                    }
                };
            }).AddOpenIdConnect("B2C_1_Edit",GetOpenIdConnectOptions("B2C_1_Edit"));
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }

        private Action<OpenIdConnectOptions> GetOpenIdConnectOptions(string policy) => options =>
        {
            options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.Authority = Startup.AuthotiryEditProfile;
            options.ClientId = Startup.ClientId;
            options.ResponseType = "code";
            options.SaveTokens = true;
            options.Scope.Add(Startup.Scope);
            options.ClientSecret = Startup.ClientSecret;
            options.CallbackPath = "/signin-oidc-" + policy;
            options.TokenValidationParameters = new TokenValidationParameters()
            {
                NameClaimType = "name"

                // if you want givnName
                //NameClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
            };
            // to use [Authorize(Roles="")] with my custome role
            options.Events = new OpenIdConnectEvents
            {
                OnTokenValidated = async opt =>
                {
                    string role = opt.Principal.FindFirstValue("extension_UserRole");
                    var claims = new List<Claim>
                        {
                            new Claim(ClaimTypes.Role , role)
                        };
                    var appIdentity = new ClaimsIdentity(claims);
                    opt.Principal.AddIdentity(appIdentity);
                },

                OnMessageReceived = context =>
                {
                    if (!string.IsNullOrEmpty(context.ProtocolMessage.Error) && !string.IsNullOrEmpty(context.ProtocolMessage.ErrorDescription))
                    {
                        if (context.ProtocolMessage.Error.Contains("access_denied"))
                        {
                            context.HandleResponse();
                            context.Response.Redirect("/");
                        }
                    }
                    return Task.FromResult(0);
                }

                
            };
        };
    }
}
