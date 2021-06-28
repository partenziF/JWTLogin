namespace JWTLogin.Helpers {
    public class JwtSettings {
        public string SecretKey { get; set; } = "";
        public string Issuer { get; set; } = "";
        public string Audience { get; set; } = "";
        public double ExpireMinutes { get; set; } = 5;

        public string HeaderKey { get; set; } = "Authorization";
    }

}
