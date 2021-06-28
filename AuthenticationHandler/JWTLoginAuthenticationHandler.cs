using JWTLogin.Helpers;
using JWTLogin.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;

namespace JWTLogin.AuthenticationHandler {

    public class JWTLoginAuthenticateOptions : AuthenticationSchemeOptions {

        //AuthenticationScheme = "Basic";
        //    AutomaticAuthenticate = true;

        public const string DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
        public string Scheme => DefaultScheme;
        public string AuthenticationType = DefaultScheme;

    }

    public class JWTLoginAuthenticationHandler : AuthenticationHandler<JWTLoginAuthenticateOptions> {

        private const string ProblemDetailsContentType = "application/problem+json";
        public JWTLoginAuthenticationHandler( IOptionsMonitor<JWTLoginAuthenticateOptions> options , ILoggerFactory logger , UrlEncoder encoder , ISystemClock clock , IOptions<JwtSettings> settings , ITokenService tokenService ) : base( options , logger , encoder , clock ) {
            this.Settings = settings.Value;
            this.tokenService = tokenService;
        }

        public JwtSettings Settings { get; }
        public ITokenService tokenService { get; }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync() {

            if ( !Request.Headers.ContainsKey( Settings.HeaderKey ) )
                return AuthenticateResult.Fail( "Unauthorized" );

            Request.Headers.TryGetValue( Settings.HeaderKey , out var AuthorizationValue );

            if ( string.IsNullOrEmpty( AuthorizationValue ) )
                return AuthenticateResult.NoResult();


            var token = AuthorizationValue.FirstOrDefault()?.Split( " " ).Last();
            

            try {

                var (principal, jwtToken) = tokenService.ValidateToken( token );

                var expiryDateUnix = long.Parse( principal.Claims.Single( x => x.Type == JwtRegisteredClaimNames.Exp ).Value );

                var expiryDateTimeUtc = new DateTime( 1970 , 1 , 1 , 0 , 0 , 0 , DateTimeKind.Utc ).AddSeconds( expiryDateUnix );

                if ( expiryDateTimeUtc < DateTime.UtcNow ) {
                    return AuthenticateResult.Fail( "Expired token.");
                }
                            
                var ticket = new AuthenticationTicket( principal , Options.Scheme );

                //await Context.SignInAsync( principal );
                //JWTLoginIdentity identity = new JWTLoginIdentity( "JWTLogin" );
                //identity.UserID = user.UserID;
                //Request.HttpContext.User = new ClaimsPrincipal( identity );


                return AuthenticateResult.Success( ticket );

                //return x;
                //return AuthenticateResult.NoResult();
                



                /*ClaimsIdentity.IsAuthenticated returns false when ClaimsIdentity.AuthenticationType is null or empty.
                 * To avoid that, stop using the parameterless ClaimsIdentity constructor and use the overload accepting 
                 * an authenticationType parameter:
                */
                //    var claims = new[] {
                //    new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                //    new Claim(ClaimTypes.Name, user.Username),
                //};
                //    var identity = new ClaimsIdentity( claims , Scheme.Name );
                //    var principal = new ClaimsPrincipal( identity );
                //    var ticket = new AuthenticationTicket( principal , Scheme.Name );
                //    return AuthenticateResult.Success( ticket );

            } catch ( SecurityTokenExpiredException) {
                return AuthenticateResult.Fail( "Expired token." );
            } catch ( SecurityTokenException ) {
                return AuthenticateResult.Fail( "Can't validate token." );
            } catch ( Exception e ) {
                return AuthenticateResult.Fail( "Can't validate token." );
            }

            //} catch {
            //return AuthenticateResult.Fail( "Can't validate token." );
            ////context.Response.Headers.Add( "Token-Expired" , "true" );
            ////context.Response.StatusCode = 401; //UnAuthorized
            ////await context.Response.WriteAsync( "Expired token" );                    
            ////return;
            //}

            //return AuthenticateResult.NoResult();


        }

        protected override async Task HandleChallengeAsync( AuthenticationProperties properties ) {
            Response.StatusCode = 403;
            Response.ContentType = ProblemDetailsContentType;
            var problemDetails = new UnauthorizedProblemDetails();
            await Response.WriteAsync( JsonSerializer.Serialize( problemDetails , new JsonSerializerOptions {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase ,
                IgnoreNullValues = true
            } ) );

        }

        protected override async Task HandleForbiddenAsync( AuthenticationProperties properties ) {
            Response.StatusCode = 403;
            Response.ContentType = ProblemDetailsContentType;
            var problemDetails = new ForbiddenProblemDetails();
            await Response.WriteAsync( JsonSerializer.Serialize( problemDetails , new JsonSerializerOptions {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase ,
                IgnoreNullValues = true
            } ) );

        }
        private AuthenticateResult ValidateToken( string token ) {
            throw new NotImplementedException();
        }
    }

    public class UnauthorizedProblemDetails : ProblemDetails {
        public UnauthorizedProblemDetails( string text = null ) {
            Title = "Unauthorized";
            Detail = text;
            Status = 401;
            Type = "https://httpstatuses.com/401";

        }
    }

    public class ForbiddenProblemDetails : ProblemDetails {
        public ForbiddenProblemDetails( string text = null ) {
            Title = "Forbidden";
            Detail = text;
            Status = 403;
            Type = "https://httpstatuses.com/403";
        }
    }


    //public class JWTAuthenticationOptions : AuthenticationSchemeOptions {
    //    public const string DefaultScheme = "JWT Bearer";
    //    public string DefaultAuthenticateScheme => DefaultScheme;
    //    public string DefaultChallengeScheme => DefaultScheme;

    //}

    //public class JWTRequirement : IAuthorizationRequirement { }
    //public class JWTAuthenticationRequirement : AuthorizationHandler<JWTRequirement> {
    //    protected override Task HandleRequirementAsync( AuthorizationHandlerContext context , JWTRequirement requirement ) {
    //        throw new NotImplementedException();
    //    }
    //}



    //public class JWTAuthenticationHandler : AuthenticationHandler<JWTAuthenticationOptions> {
    //    public JWTAuthenticationHandler( IOptionsMonitor<JWTAuthenticationOptions> options , ILoggerFactory logger , UrlEncoder encoder , ISystemClock clock ) : base( options , logger , encoder , clock ) {
    //        //            this.customAuthenticationManager = customAuthenticationManager;
    //    }

    //    protected override Task<AuthenticateResult> HandleAuthenticateAsync() {
    //        throw new NotImplementedException();
    //    }
    //    protected override async Task HandleChallengeAsync( AuthenticationProperties properties ) {
    //        throw new NotImplementedException();
    //    }

    //    protected override async Task HandleForbiddenAsync( AuthenticationProperties properties ) {
    //        throw new NotImplementedException();
    //    }
    //}



    //public interface IJWTAuthenticationManager {
    //    string Authenticate( string username , string password );

    //    IDictionary<string , string> Tokens { get; }
    //}

    //public class JWTAuthenticationManager : IJWTAuthenticationManager {
    //    public IDictionary<string , string> Tokens => throw new NotImplementedException();

    //    public string Authenticate( string username , string password ) {
    //        throw new NotImplementedException();
    //    }
    //}

}
