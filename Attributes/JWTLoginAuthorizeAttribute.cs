using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System;

//using IAuthorizationFilter = Microsoft.AspNetCore.Mvc.Filters.IAuthorizationFilter;


//dotnet add package Microsoft.AspNet.Mvc --version 5.2.7
//dotnet add package Microsoft.AspNetCore.Mvc.Abstractions --version 2.2.0

namespace JWTLogin.Attributes {

    [AttributeUsage( AttributeTargets.Class | AttributeTargets.Method )]
    public class JWTLoginAuthorizeAttribute : TypeFilterAttribute {
        public JWTLoginAuthorizeAttribute( params string[] claim ) : base( typeof( JWTLoginAuthorizeFilter ) ) {
            Arguments = new object[] { claim };
        }
    }

    public class JWTLoginAuthorizeFilter : IAuthorizationFilter {
        readonly string[] _claim;

        public JWTLoginAuthorizeFilter( params string[] claim ) {
            _claim = claim;
        }

        public void OnAuthorization( AuthorizationFilterContext context ) {

            var IsAuthenticated = context.HttpContext.User.Identity.IsAuthenticated;
            if ( !IsAuthenticated ) {
                context.Result = new UnauthorizedResult();
            }

            //var claimsIndentity = context.HttpContext.User.Identity as ClaimsIdentity;
            //if ( IsAuthenticated ) {
            //    bool flagClaim = false;
            //    foreach ( var item in _claim ) {
            //        if ( context.HttpContext.User.HasClaim( item , item ) )
            //            flagClaim = true;
            //    }
            //    if ( !flagClaim )
            //        context.Result = new RedirectResult( "~/Dashboard/NoPermission" );
            //} else {
            //    context.Result = new RedirectResult( "~/Home/Index" );
            //}
            //return;
        }
    }
    /*    public class LoginAuthorizeAttribute : ActionFilterAttribute { //Attribute, IAuthorizationFilter {

            public override async System.Threading.Tasks.Task OnActionExecutionAsync( ActionExecutingContext context , ActionExecutionDelegate next ) {
                await next();
            }
            //    public void OnAuthorization( AuthorizationFilterContext context ) {   

            //    var user = context.HttpContext.User;

            //    if ( !user.Identity.IsAuthenticated ) {

            //        context.Result = new JsonResult( new { message = "Unauthorized" } ) { StatusCode = StatusCodes.Status401Unauthorized };
            //        //context.Result = new UnauthorizedResult();

            //    }
            //}
        }
    */
    //https://www.codeproject.com/Articles/5247609/ASP-NET-CORE-Token-Authentication-and-Authorizat-2
    /*
     
        public class AuthorizeAttribute : TypeFilterAttribute
    {
        public AuthorizeAttribute(params string[] claim) : base(typeof(AuthorizeFilter))
        {
            Arguments = new object[] { claim };
        }
    }

    public class AuthorizeFilter : IAuthorizationFilter
    {
        readonly string[] _claim;

        public AuthorizeFilter(params string[] claim)
        {
            _claim = claim;
        }

        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var IsAuthenticated = context.HttpContext.User.Identity.IsAuthenticated;
            var claimsIndentity = context.HttpContext.User.Identity as ClaimsIdentity;

            if (IsAuthenticated)
            {
                bool flagClaim = false;
                foreach (var item in _claim)
                {
                    if (context.HttpContext.User.HasClaim(item, item))
                        flagClaim = true;
                }
                if (!flagClaim)
                    context.Result = new RedirectResult("~/Dashboard/NoPermission");
            }
            else
            {
                context.Result = new RedirectResult("~/Home/Index");
            }
            return;
        }
    }*/

}