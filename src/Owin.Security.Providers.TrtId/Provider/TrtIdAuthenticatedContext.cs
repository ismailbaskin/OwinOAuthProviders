using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using System;
using System.Globalization;
using System.Security.Claims;

namespace Owin.Security.Providers.TrtId.Provider
{
    public class TrtIdAuthenticatedContext: BaseContext
    {
        public TrtIdAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string refreshToken, string expiresIn)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;
            RefreshToken = refreshToken;

            int expiresValue;
            if (int.TryParse(expiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }

            Id = TryGetValue(user, "id");
            Name = TryGetValue(user, "fullName");
            UserName = TryGetValue(user, "username");
            Email = TryGetValue(user, "email");
            Gsm = TryGetValue(user, "gsm");

            ProfilePicture = TryGetValue(user, "photo");
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the TrtId user obtained from token ednpoint
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the TrtId access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets TrtId refresh token
        /// </summary>
        public string RefreshToken { get; private set; }

        /// <summary>
        /// Gets TrtId access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn { get; set; }

        /// <summary>
        /// Gets the TrtId user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Gets the user's username
        /// </summary>
        public string UserName { get; private set; }

        /// <summary>
        /// Gets the user's email
        /// </summary>
        public string Email { get; private set; }

        /// <summary>
        /// Gets the user's gsm
        /// </summary>
        public string Gsm { get; private set; }

        /// <summary>
        /// Gets the TrtId users profile picture
        /// </summary>
        public string ProfilePicture { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }

        private static string TryGetListValue(JObject user, string listPropertyName, int listPosition, string listEntryPropertyName)
        {
            JToken listValue;
            var valueExists = user.TryGetValue(listPropertyName, out listValue);
            if (!valueExists) return null;
            var list = (JArray)listValue;
            
            if (list.Count <= listPosition) return null;
            var entry = list[listPosition];

            return entry.Value<string>(listEntryPropertyName);
        }
    }
}