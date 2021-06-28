using JWTLogin.Model;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;

namespace JWTLogin.Services {
    public interface ITokenService {
        string BuildToken( AuthenticatedUserModel userLoggedModel );

        //AuthenticatedUserModel GetAuthenticatedUserBySessionAsync( string session );
        Task<AuthenticatedUserModel> GetAuthenticatedUserBySessionAsync( string session );

        //AuthenticatedUserModel ValidateToken( string token );
        (ClaimsPrincipal, JwtSecurityToken) ValidateToken( string token );

        void Refresh( string refreshToken , string accessToken , DateTime now );


    }
}