using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System.Runtime.CompilerServices;

namespace SecurityApiKey
{
    public class ApiKeyAttribute : Attribute, IAsyncActionFilter
    {
        public string APIKEYNAME = "ApiKey";
        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            if (!context.HttpContext.Request.Headers.TryGetValue(APIKEYNAME, out var value))
            {
                context.Result = new ContentResult()
                {
                    StatusCode = 401,
                    Content = "Api key not provided,Please enter the security key and retry again"
                };
                return;
            }

            var appsettings = context.HttpContext.RequestServices.GetRequiredService<IConfiguration>();
            var apiKey = appsettings.GetValue<string>(APIKEYNAME);
            if (!apiKey.Equals(value))
            {
                context.Result = new ContentResult()
                {
                    StatusCode = 401,
                    Content = "API KEY IS INVALID"
                };

            }

            await next();
        }
    }
}
