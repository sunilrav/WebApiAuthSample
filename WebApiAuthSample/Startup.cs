using Microsoft.Owin;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;
using System.Security.Claims;

namespace WebApiAuthSample
{
    public class Startup
    {
        public static void Configuration(IAppBuilder app)
        {
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());

            app.UseOAuthAuthorizationServer( new OAuthAuthorizationServerOptions
            {
                TokenEndpointPath = new PathString("/Token"),
                Provider = new OAuthAuthorizationServerProvider()
                {
                    OnValidateClientAuthentication = async c =>
                        {
                            c.Validated();
                        },
                    OnGrantResourceOwnerCredentials = async c =>
                        {
                            if (c.UserName == "alice" && c.Password == "supersecret")
                            {
                                Claim claim1 = new Claim(ClaimTypes.Name, c.UserName);
                                Claim[] claims = new Claim[]{ claim1 };
                                ClaimsIdentity claimsIdentity = new ClaimsIdentity(claims,
                                                                        OAuthDefaults.AuthenticationType);
                                c.Validated(claimsIdentity);
                            }
                        }
                },
                AccessTokenExpireTimeSpan = TimeSpan.FromDays(14),
                AllowInsecureHttp = true
            });

            
        }
    }
}