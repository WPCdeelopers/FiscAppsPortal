using System;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.OAuth;
using Owin;
using AuthModule.Models;
using AuthModule.Providers;
using System.Configuration;
using Microsoft.Owin.Security.Notifications;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security;

namespace AuthModule
{
    public partial class Startup
    {
        // Enable the application to use OAuthAuthorization. You can then secure your Web APIs
        static Startup()
        {
            PublicClientId = "web";

            OAuthOptions = new OAuthAuthorizationServerOptions
            {
                TokenEndpointPath = new PathString("/Token"),
                AuthorizeEndpointPath = new PathString("/Account/Authorize"),
                Provider = new ApplicationOAuthProvider(PublicClientId),
                AccessTokenExpireTimeSpan = TimeSpan.FromDays(14),
                AllowInsecureHttp = true
            };
        }

        public static OAuthAuthorizationServerOptions OAuthOptions { get; private set; }

        public static string PublicClientId { get; private set; }

        // For more information on configuring authentication, please visit https://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            // Configure the db context, user manager and signin manager to use a single instance per request
            app.CreatePerOwinContext(ApplicationDbContext.Create);
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
            app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);


            

            // Enable the application to use a cookie to store information for the signed in user
            app.UseKentorOwinCookieSaver();
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                // AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                AuthenticationType = "ApplicationCookie",
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider
                {
                    // Enables the application to validate the security stamp when the user logs in.
                    // This is a security feature which is used when you change a password or add an external login to your account.  
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, ApplicationUser>(
                        validateInterval: TimeSpan.FromMinutes(20),
                        regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
                }
            });


            // Use a cookie to temporarily store information about a user logging in with a third party login provider
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            // Enables the application to temporarily store user information when they are verifying the second factor in the two-factor authentication process.
             app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));

            // Enables the application to remember the second login verification factor such as phone or email.
            // Once you check this option, your second step of verification during the login process will be remembered on the device where you logged in from.
            // This is similar to the RememberMe option when you log in.
            app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

            // Enable the application to use bearer tokens to authenticate users
            app.UseOAuthBearerTokens(OAuthOptions);



            // Uncomment the following lines to enable logging in with third party login providers
            app.UseMicrosoftAccountAuthentication(
                clientId: ConfigurationManager.AppSettings["MicrosoftAppId"].ToString(),
                clientSecret: ConfigurationManager.AppSettings["MicrosoftAppSecret"].ToString());

            //app.UseTwitterAuthentication(
            //    consumerKey: "",
            //    consumerSecret: "");

            //app.UseFacebookAuthentication(
            //    appId: ConfigurationManager.AppSettings["FacebookAppId"].ToString(),
            //    appSecret: ConfigurationManager.AppSettings["FacebookAppSecret"].ToString());

            app.UseGoogleAuthentication(new GoogleOAuth2AuthenticationOptions()
            {
                ClientId = ConfigurationManager.AppSettings["GoogleAppId"].ToString(),
                ClientSecret = ConfigurationManager.AppSettings["GoogleAppSecret"].ToString()
            });

            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    // Sets the ClientId, authority, RedirectUri as obtained from web.configure
                    ClientId = ConfigurationManager.AppSettings["WpcClientId"].ToString(),
                    Authority = ConfigurationManager.AppSettings["WpcAuthority"].ToString(),
                    //RedirectUri = ConfigurationManager.AppSettings["WpcPostLogoutRedirectUri"].ToString(),

                    // PostLogoutRedirectUri is the page that users will be redirected to after sign-out. In this case, it is using the home page
                    //PostLogoutRedirectUri = ConfigurationManager.AppSettings["WpcPostLogoutRedirectUri"].ToString(),

                    //Scope is the requested scope: OpenIdConnectScopes.OpenIdProfileis equivalent to the string 'openid profile': in the consent screen, this will result in 'Sign you in and read your profile'
                    Scope = OpenIdConnectScope.OpenIdProfile,

                    // ResponseType is set to request the id_token - which contains basic information about the signed-in user
                    ResponseType = OpenIdConnectResponseType.IdToken,

                    // ValidateIssuer set to false to allow work accounts from any organization to sign in to your application
                    // To only allow users from a single organizations, set ValidateIssuer to true and 'tenant' setting in web.config to the tenant name or Id (example: contoso.onmicrosoft.com)
                    // To allow users from only a list of specific organizations, set ValidateIssuer to true and use ValidIssuers parameter
                    TokenValidationParameters = new TokenValidationParameters()
                    {
                        ValidateIssuer = true
                    },

                    // OpenIdConnectAuthenticationNotifications configures OWIN to send notification of failed authentications to OnAuthenticationFailed method
                    Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        AuthenticationFailed = OnAuthenticationFailed
                    }
                }
            );

            //app.UseOpenIdConnectAuthentication(
            //new OpenIdConnectAuthenticationOptions
            //{
            //    ClientId = ConfigurationManager.AppSettings["WpcClientId"].ToString(),
            //    Authority = ConfigurationManager.AppSettings["WpcAuthority"].ToString(),
            //    PostLogoutRedirectUri = ConfigurationManager.AppSettings["WpcPostLogoutRedirectUri"].ToString(),
            //    RefreshOnIssuerKeyNotFound = true,

            //    AuthenticationMode = Microsoft.Owin.Security.AuthenticationMode.Active,
            //    AuthenticationType = OpenIdConnectAuthenticationDefaults.AuthenticationType,

            //    Notifications = new OpenIdConnectAuthenticationNotifications
            //    {
            //        RedirectToIdentityProvider = ctx =>
            //        {
            //            bool isAjaxRequest = (ctx.Request.Headers != null && ctx.Request.Headers["X-Requested-With"] == "XMLHttpRequest");

            //            if (isAjaxRequest)
            //            {
            //                ctx.Response.Headers.Remove("Set-Cookie");
            //                ctx.State = NotificationResultState.HandledResponse;
            //            }

            //            return Task.FromResult(0);
            //        },

            //        AuthenticationFailed = async n =>
            //        {
            //            if (n.Exception != null && n.Exception.Message != null && n.Exception.Message.Contains("IDX10301"))
            //            {
            //                // nonce bug (when already have cookie generated in other tab or computer)

            //                n.OwinContext.Response.Redirect("/account/AlreadySignedIn");
            //                n.HandleResponse();
            //            }
            //        }
            //    }



            //});
        }

        private Task OnAuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> context)
        {
            //throw new NotImplementedException();
            context.HandleResponse();
            context.Response.Redirect("/?errormessage=" + context.Exception.Message);
            return Task.FromResult(0);
        }
    }
}
