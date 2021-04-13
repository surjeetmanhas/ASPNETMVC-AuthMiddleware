using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Formatting;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using System.Web.Http.Controllers;
using Newtonsoft.Json;
using BCG.PSG.Common.APIAccess.Helpers;
using BCG.PSG.Common.Exceptions;
using System.Web.Http;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Threading;
using System.Web;
using Microsoft.AspNet.Identity.Owin;

namespace BCG.PSG.WebAPIService
{
    public class CustomAuthorizeAttribute : System.Web.Http.AuthorizeAttribute
    {
        public bool RequireSSL { get; set; } //when true - will reject any http request. Must use https
        public string ClaimType { get; set; }
        public string ClaimValue { get; set; }
        public string _tokenValidationErrorMessage;
        public override void OnAuthorization(HttpActionContext actionContext)
        {
            if (RequireSSL && actionContext.Request.RequestUri.Scheme != Uri.UriSchemeHttps)
            {
                HandleNonHttpsRequest(actionContext);
            }
            else
            {
                base.OnAuthorization(actionContext);
            }

        }
        public override Task OnAuthorizationAsync(HttpActionContext actionContext, System.Threading.CancellationToken cancellationToken)
        {
            ApiErrorDetails apierrordetails = new ApiErrorDetails();

            try
            {
                var validatedToken = IsBearertokenValid(actionContext);
                if(validatedToken!=null)
                return Task.FromResult<object>(null);
            }
            catch (Exception ex)
            {
                //var userClaims = HttpContext.Current.GetOwinContext().Authentication.User.Claims;
                Stream requestBodyStream = actionContext.Request.Content.ReadAsStreamAsync().Result;
                requestBodyStream.Position = 0;
                string requestBody = string.Empty;
                using (StreamReader sr = new StreamReader(requestBodyStream))
                {
                    requestBody = sr.ReadToEnd();
                }

                apierrordetails.ExceptionMessage = "Unable to " + actionContext.Request.Method.ToString() +
                                          " data to API service at URL:" + actionContext.Request.RequestUri.ToString() +
                                          " Server returned an Unauthorized.";
                apierrordetails.CorrelationId = actionContext.Request.Headers.Contains("CorrelationId")
                    ? Convert.ToInt64(actionContext.Request.Headers.GetValues("CorrelationId").FirstOrDefault())
                    : Convert.ToInt64(TraceHelper.GetCorrelationId());
                apierrordetails.ExceptionCode = 401;
                apierrordetails.RequestBody = requestBody;
                apierrordetails.RequestMethod = actionContext.Request.Method.ToString();
                apierrordetails.RequestURL = actionContext.Request.RequestUri.ToString();
                apierrordetails.Message = ex.Message;
                actionContext.Response = new HttpResponseMessage(HttpStatusCode.Forbidden)
                {
                    Content = new ObjectContent(typeof(ApiErrorDetails),
                        apierrordetails,
                        GlobalConfiguration.Configuration.Formatters.JsonFormatter)
                };
                return Task.FromResult<object>(actionContext);
            }

            return Task.FromResult<object>(null);
        }

        protected override void HandleUnauthorizedRequest(HttpActionContext actionContext)
        {

            actionContext.Response = new AuthenticationFailureMessage("unauthorized", actionContext.Request,
                        new
                        {
                            error = "validation_error",
                            error_message = "Unable to validate access token. The token may have expired or is invalid."
                        });
        }

        private JwtSecurityToken IsBearertokenValid(HttpActionContext actionContext)
        {
            if (actionContext.Request.Headers.Contains("Authorization"))
            {
                var authToken = Convert.ToString(actionContext.Request.Headers.GetValues("Authorization").FirstOrDefault());
                OktaTokenValidator tokenValidator = new OktaTokenValidator();
                var validatedToken = tokenValidator.ValidateToken(authToken.Replace("Bearer", "").Trim());
                return validatedToken;
            }

            return null;
        }


        protected virtual void HandleNonHttpsRequest(HttpActionContext actionContext)
        {
            actionContext.Response = new HttpResponseMessage(System.Net.HttpStatusCode.Forbidden);
            actionContext.Response.ReasonPhrase = "SSL Required. Please use HTTPS instead of HTTP.";
        }
    }

    public class AuthenticationFailureMessage : HttpResponseMessage
    {
        public AuthenticationFailureMessage(string reasonPhrase, HttpRequestMessage request, object responseMessage)
            : base(HttpStatusCode.Unauthorized)
        {
            MediaTypeFormatter jsonFormatter = new JsonMediaTypeFormatter();

            Content = new ObjectContent<object>(responseMessage, jsonFormatter);
            RequestMessage = request;
            ReasonPhrase = reasonPhrase;
        }
    }

    public class OktaTokenValidator
    {
        private readonly string _clientId = ConfigurationManager.AppSettings["OpenIDConnect_ClientId"];
        private readonly string _authority = ConfigurationManager.AppSettings["OpenIDConnect_Authority"];
        private readonly string _clientSecret = ConfigurationManager.AppSettings["OpenIDConnect_ClientSecret"];

        public TokenValidationResponse ValidateAccessTokenValue(string authorizationHeaderValue)
        {

            using (var client = new HttpClient())
            {
                var clientCreds = System.Text.Encoding.UTF8.GetBytes($"{_clientId}:{_clientSecret}");
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", System.Convert.ToBase64String(clientCreds));

                var form = new Dictionary<string,
                    string> {
                        {
                            "token",
                            authorizationHeaderValue.Replace("Bearer", "").Trim()
                        },
                         {
                            "token_type_hint",
                            "access_token"
                        },
                        };

                var tokenResponse = client.PostAsync(_authority + "/v1/introspect ", new FormUrlEncodedContent(form)).Result;
                var token = tokenResponse.Content.ReadAsAsync<TokenValidationResponse>(new[] { new JsonMediaTypeFormatter() }).Result;
                return token;
            }

            #region get token

            //if (!string.IsNullOrEmpty(authorizationHeaderValue) && authorizationHeaderValue.StartsWith("Bearer"))
            //{
            //    OIDCTokenValidationParameters validationParam = new OIDCTokenValidationParameters()
            //    {
            //        Token = authorizationHeaderValue.Replace("Bearer", "").Trim(),
            //        ClientId = "XXXXX",//WebConfigurationManager.AppSettings["okta:ClientId"],
            //        ClientSecret = "xxxxxx",//WebConfigurationManager.AppSettings["okta:ClientSecret"],
            //        OIDCIssuer = "",//WebConfigurationManager.AppSettings["okta:OIDC_Issuer"],
            //        OAuthIssuer = "https://xxxx.oktapreview.com/oauth2/auswz1ramoF7z1W840h7/",//WebConfigurationManager.AppSettings["okta:OAuth_Issuer"],
            //        TokenTypeHint = "access_token"
            //    };
            //    OIDCClient client = new OIDCClient();
            //    var task = Task.Run(async () =>
            //    {
            //        return await client.ValidateAccessToken(validationParam);
            //    });
            //    TokenValidationResponse response = task.Result; //validate with Okta's introspect API
            //    return response;
            //}
            #endregion
            return null;
        }

        public JwtSecurityToken ValidateToken(string token,
                                CancellationToken ct = default(CancellationToken))
        {
            SecurityToken rawValidatedToken = null;

            var tokenres = new PFSSecurityTokenValidation();
            var app = HttpContext.Current.GetOwinContext().Get<TokenValidationConfig>();
            var logger = app.GetSerilogConfig();

            var validationParameters = app.GetTokenValidationParameters();

            if (string.IsNullOrEmpty(token)) throw new ArgumentNullException(nameof(token));
            try
            {
                var principal = new JwtSecurityTokenHandler()
                    .ValidateToken(token, validationParameters, out rawValidatedToken);

                var validToken = (JwtSecurityToken)rawValidatedToken;

                var expectedAlg = SecurityAlgorithms.RsaSha256; //Okta uses RS256
                if (validToken.Header?.Alg == null || validToken.Header?.Alg != expectedAlg)
                {
                    //logger.Error("Exception on token Validation: The alg must be RS256.");
                    tokenres.ErrorMessage = "The alg must be RS256.";
                    throw new Exception("The alg must be RS256."); ;
                    return null;
                }
                //logger.Information("ouath token has been validated successfully for user -");
                return validToken;
            }
            catch (SecurityTokenValidationException ex)
            {
                //logger.Error("Exception on token Validation:" + ex.Message);
                throw;
                tokenres.ErrorMessage = ex.Message;
                return null;
            }
        }

        private IEnumerable<string> GetAudiences()
        {
            List<string> validaudiencesList = new List<string>();
            validaudiencesList.Add("mdp360default");
            return validaudiencesList;
        }
    }

}
