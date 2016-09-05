using System;

namespace Owin.Security.Providers.TrtId
{
    public static class TrtIdAuthenticationExtensions
    {
        public static IAppBuilder UseTrtIdAuthentication(this IAppBuilder app,
            TrtIdAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(TrtIdAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseTrtIdAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseTrtIdAuthentication(new TrtIdAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}