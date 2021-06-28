using System;
using System.Text.Json.Serialization;

namespace JWTLogin.Model {


    public class AuthenticatedUserModel {

        [JsonIgnore]
        public uint UserID { get; set; }
        [JsonIgnore]
        public uint LoginID { get; set; }

        [JsonIgnore]
        public string Username { get; set; }

        public string Name { get; set; }
        public string LastName { get; set; }
        public string Session { get; set; }

        [JsonIgnore]
        public string Email { get; set; }

        public DateTime LastLogin { get; set; }

        [JsonIgnore]
        public string Role { get; set; }
        [JsonIgnore]
        public string Password { get; set; }

    }
}
