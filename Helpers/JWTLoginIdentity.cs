using System.Security.Claims;
using System.Security.Principal;

//dotnet add package Microsoft.AspNetCore.Http.Abstractions --version 2.2.0

namespace JWTLogin.Helpers {

    public class JWTLoginIdentity : ClaimsIdentity, IIdentity {
        public JWTLoginIdentity( string authenticationType ) : base( authenticationType ) {
        }

        public uint AccountID { get; set; }

        public uint LoginId { get; set; }

        public string Session { get; set; }

    }


}