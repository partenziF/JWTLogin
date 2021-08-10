using JWTLogin.Helpers;
using JWTLogin.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;

//dotnet add package Microsoft.AspNetCore.Http.Abstractions --version 2.2.0

namespace JWTLogin.Middleware {

    public class JWTAuthMiddleware {

        private readonly RequestDelegate next;
        private readonly JwtSettings JwtSettings;
        public JWTAuthMiddleware( RequestDelegate next , IOptions<JwtSettings> settings ) {
            this.next = next;
            this.JwtSettings = settings.Value;
        }

        public async Task Invoke( HttpContext context , ITokenService tokenService ) {

            //var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split( " " ).Last();

            if ( context.User.Identity.IsAuthenticated ) {

                try {
                    //var (principal, jwtToken) = tokenService.ValidateToken( token );
                    ClaimsPrincipal principal = context.User as ClaimsPrincipal;

                    var SessionID = principal.FindFirstValue( "Session" );
                    var user = await tokenService.GetAuthenticatedUserBySessionAsync( SessionID );

                    if ( user is not null ) {

                        JWTLoginIdentity identity = new JWTLoginIdentity( "JWTLogin" );
                        identity.AccountID = user.UserID;
                        identity.Session = SessionID;
                        identity.LoginId = user.LoginID;
                        
                        context.User.AddIdentity( identity );

                    } else {

                        //context.Response.Headers.Add( "Token-Expired" , "true" );
                        context.Response.StatusCode = 401; //UnAuthorized
                        await context.Response.WriteAsync( "Invalid session." );
                        return;
                    }

                } catch {
                    context.Response.Headers.Add( "Invalid authentication." , "true" );
                    context.Response.StatusCode = 401; //UnAuthorized
                    await context.Response.WriteAsync( "Expired token" );
                    return;
                }


                //var xx = new GenericPrincipal( new ClaimsIdentity( "" ) , new string[] { "" } );
                //context.User = xx;
                //if ( user is not null ) {

                    //var identity = new ClaimsIdentity( new List<Claim> { new Claim( "UserId" , "123" , ClaimValueTypes.Integer32 ) } , "Custom" );
                    //var identity = new ClaimsIdentity( "Custom" );
                    //identity.AddClaim( new Claim() )

                   // var claims = new[] {
                   // new Claim(JwtRegisteredClaimNames.Sub, _configuration["Jwt:Subject"]),
                   // new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                   // new Claim(JwtRegisteredClaimNames.Iat, DateTime.UtcNow.ToString()),
                   // new Claim("Id", user.UserId.ToString()),
                   // new Claim("FirstName", user.FirstName),
                   // new Claim("LastName", user.LastName),
                   // new Claim("UserName", user.UserName),
                   // new Claim("Email", user.Email)
                   //};

                    //JWTLoginIdentity identity = new JWTLoginIdentity( "JWTLogin" );
                    //identity.UserID = user.UserID;
                    //context.User = new ClaimsPrincipal( identity );

                //}

            //} else {
                

                //return new AuthenticationResult { Errors = new[] { "Invalid Token" } };

            }

            await next( context );
        }


    }


}