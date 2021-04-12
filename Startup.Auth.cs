using System;
using System.Collections.Generic;
using System.Configuration;
using System.Threading;
using System.Threading.Tasks;
using BCG.PSG.WebAPIService.Provider;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Cors;
using Microsoft.Owin.Security.OAuth;
using Owin;
using Serilog;

namespace BCG.PSG.WebAPIService
{


    public partial class Startup
    {
        public static OAuthAuthorizationServerOptions OAuthOptions { get; private set; }
        static Startup()
        {
            OAuthOptions = new OAuthAuthorizationServerOptions
            {
                TokenEndpointPath = new PathString("/token"),
                Provider = new ApplicationOAuthProvider(),
                AccessTokenExpireTimeSpan = TimeSpan.FromDays(1),
                AllowInsecureHttp = true
            };
        }

        public void ConfigureAuth(IAppBuilder app)
        {

            app.CreatePerOwinContext<TokenValidationConfig>(TokenValidationConfig.GetOpenIdConfig);
            app.UseOAuthAuthorizationServer(OAuthOptions);
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());
            //app.UseOAuthBearerTokens(OAuthOptions);
        }
    }

    public class TokenValidationConfig : IDisposable
    {
        private static TokenValidationParameters _tokenParameters;
        private static  ILogger _iLogger;

        public TokenValidationConfig(ILogger iLogger)
        {
            _iLogger = iLogger;
        }
        //public TokenValidationConfig()
        //{

        //}
        public static TokenValidationConfig GetOpenIdConfig()
        {
            return new TokenValidationConfig(_iLogger);
        }

        public ILogger GetSerilogConfig()
        {
            return _iLogger;
        }

        public TokenValidationParameters GetTokenValidationParameters()
        {
            if (_tokenParameters == null)
            {
                string _authority = ConfigurationManager.AppSettings["OpenIDConnect_Authority"];
                CancellationToken ct = default(CancellationToken);

                var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(_authority + "/.well-known/oauth-authorization-server", new OpenIdConnectConfigurationRetriever(), new HttpDocumentRetriever());
                var task = Task.Run(async () => await configurationManager.GetConfigurationAsync(ct));
                task.Wait();
                var discoveryDocument = task.Result;
                var signingKeys = discoveryDocument.SigningKeys;

                var validationParameters = new TokenValidationParameters
                {
                    RequireExpirationTime = true,
                    RequireSignedTokens = true,
                    ValidateIssuer = true,
                    ValidIssuer = _authority,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKeys = signingKeys,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromMinutes(1),
                    ValidateAudience = true,
                    ValidAudiences = GetAudiences()

                };

                _tokenParameters = validationParameters;
            }
            return _tokenParameters;
        }
        private IEnumerable<string> GetAudiences()
        {
            List<string> validaudiencesList = new List<string>();
            validaudiencesList.Add("mdp360default");

            return validaudiencesList;
        }
        public void Dispose() { }

    }
}