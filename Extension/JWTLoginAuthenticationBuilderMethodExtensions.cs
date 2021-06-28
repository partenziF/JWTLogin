using JWTLogin.AuthenticationHandler;
using Microsoft.AspNetCore.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JWTLogin.Extension {

    public static class JWTLoginAuthenticationBuilderMethodExtensions {

        public static AuthenticationBuilder AddJWTLoginSupport( this AuthenticationBuilder authenticationBuilder , Action<JWTLoginAuthenticateOptions> options ) {

            return authenticationBuilder.AddScheme<JWTLoginAuthenticateOptions , JWTLoginAuthenticationHandler>( JWTLoginAuthenticateOptions.DefaultScheme , options );

        }

    }

}
