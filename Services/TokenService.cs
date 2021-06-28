using JWTLogin.Model;
using System;
using System.Linq;
using System.Text;

//dotnet add package Microsoft.IdentityModel.Tokens --version 6.11.1
using Microsoft.IdentityModel.Tokens;
using JWTLogin.Helpers;
//dotnet add package System.IdentityModel.Tokens.Jwt --version 6.11.1
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
//dotnet add package Microsoft.Extensions.Options --version 5.0.0
using Microsoft.Extensions.Options;
using System.Threading.Tasks;

namespace JWTLogin.Services {


    public class TokenService : ITokenService {

        private readonly JwtSettings JWTSettings;

        public TokenService( IOptions<JwtSettings> settings ) {
            this.JWTSettings = settings.Value;
        }

        public string BuildToken( AuthenticatedUserModel userLoggedModel ) {

            //Create token handler
            var TokenHandler = new JwtSecurityTokenHandler();

            //Read Secret Key and create security Key
            var SecretKey = Encoding.ASCII.GetBytes( JWTSettings.SecretKey );

            //Generate SecurityKey from secret key
            var SecurityKey = new SymmetricSecurityKey( SecretKey );

            //Create claims
            var claims = new ClaimsIdentity();
            claims.AddClaim( new Claim( ClaimTypes.Name , userLoggedModel.Username ) );
            claims.AddClaim( new Claim( ClaimTypes.Email , userLoggedModel.Email ) );
            //var roles = await _userManager.GetRolesAsync( user );
            //claims.AddClaims( roles.Select( role => new Claim( ClaimTypes.Role , role ) ) );
            claims.AddClaim( new Claim( ClaimTypes.Role , userLoggedModel.Role ) );
            claims.AddClaim( new Claim( nameof( userLoggedModel.Session ) , userLoggedModel.Session ) );

            var TokenDescriptor = new SecurityTokenDescriptor {

                Issuer = JWTSettings.Issuer ,
                Audience = JWTSettings.Audience ,
                NotBefore = DateTime.Now ,
                IssuedAt = DateTime.Now ,

                Subject = claims ,
                Expires = DateTime.Now.AddMinutes( JWTSettings.ExpireMinutes ) ,
                SigningCredentials = new SigningCredentials( SecurityKey , SecurityAlgorithms.HmacSha256Signature )

            };

            var SecurityToken = TokenHandler.CreateToken( TokenDescriptor );
            return TokenHandler.WriteToken( SecurityToken );

        }

        public virtual async Task<AuthenticatedUserModel> GetAuthenticatedUserBySessionAsync( string session ) {
            return null;
        }

        private string GenerateRandomTokenString() {
            var randomNumber = new byte[32];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes( randomNumber );
            return Convert.ToBase64String( randomNumber );
        }


        public (ClaimsPrincipal, JwtSecurityToken) ValidateToken( string token ) {

            //if ( string.IsNullOrWhiteSpace( token ) ) {
            //    throw new SecurityTokenException( "Invalid token" );
            //}

            //try {

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes( JWTSettings.SecretKey );

            var principal = tokenHandler.ValidateToken( token ,
                new TokenValidationParameters {
                    ValidateIssuerSigningKey = true ,
                    IssuerSigningKey = new SymmetricSecurityKey( key ) ,
                    ValidateIssuer = false ,
                    ValidateAudience = false ,
                    ValidateLifetime = false ,

                        // set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
                        ClockSkew = TimeSpan.FromMinutes( 1 )
                } ,
                out SecurityToken validatedToken );

            //var jwtToken = ( JwtSecurityToken ) validatedToken;

            return (principal, ( JwtSecurityToken ) validatedToken);


            //var SessionID = ( jwtToken.Claims.First( x => x.Type == "Session" ).Value );


            //var x = jwtToken.Claims
            //var userId = int.Parse( jwtToken.Claims.First( x => x.Type == "id" ).Value );
            // attach user to context on successful jwt validation

            //                return GetAuthenticatedUserBySessionAsync( SessionID ).GetAwaiter().GetResult();

            //        ValidateIssuerSigningKey = true ,

            //        //Same Secret key will be used while creating the token
            //        IssuerSigningKey = new SymmetricSecurityKey( Encoding.ASCII.GetBytes( jwtSettings.SecretKey ) ) ,

            //        //Usually, this is your application base URL
            //        ValidateIssuer = false ,
            //        //ValidIssuer = jwtTokenConfig.Issuer,
            //        // Here , we are creating and using JWT within the same application.
            //        //In this case, base URL is fine.
            //        //If the JWT is created using a web service, then this would be the consumer URL.
            //        ValidateAudience = false ,
            //        //ValidAudience = jwtTokenConfig.Audience ,
            //        RequireExpirationTime = true ,
            //        ValidateLifetime = true ,
            //        ClockSkew = TimeSpan.Zero



            //            } catch ( Exception e ) {
            //                // do nothing if jwt validation fails
            //                // user is not attached to context so request won't have access to secure routes


            /////                throw new SecurityTokenException( "Exception invalid token." );
            //            }


        }

        public void Refresh( string refreshToken , string accessToken , DateTime now ) {
            throw new NotImplementedException();
        }
    }


}


