package utils

const (
	DefaultAlphabet        = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	DefaultMaxSecretLength = 12
	ExitCodeSuccess        = 0
	ExitCodeFailure        = 1
)

// Supported algorithms
const (
	AlgHS256 = "HS256"
	AlgHS384 = "HS384"
	AlgHS512 = "HS512"
	AlgRS256 = "RS256"
	AlgRS384 = "RS384"
	AlgRS512 = "RS512"
	AlgES256 = "ES256"
	AlgES384 = "ES384"
	AlgES512 = "ES512"
	AlgNone  = "none"
)

// Common JWT patterns
const (
	PatternBase64 = "base64"
	PatternHex    = "hex"
	PatternUUID   = "uuid"
	PatternEmail  = "email"
	PatternDate   = "date"
	PatternIP     = "ip"
)

// Common JWT claims
const (
	ClaimIssuer  = "iss"
	ClaimSubject = "sub"
	ClaimAudience = "aud"
	ClaimExpiration = "exp"
	ClaimNotBefore = "nbf"
	ClaimIssuedAt = "iat"
	ClaimJWTID = "jti"
)

// Common JWT headers
const (
	HeaderAlgorithm = "alg"
	HeaderType = "typ"
	HeaderContentType = "cty"
	HeaderKeyID = "kid"
)

// Common weak secrets
var CommonWeakSecrets = []string{
	"secret", "password", "admin", "123456",
	"qwerty", "letmein", "welcome", "monkey",
	"football", "baseball", "superman", "trustno1",
	"jwt", "token", "key", "master",
	"admin123", "password123", "secret123",
	"jwtsecret", "jwtkey", "jwtpassword",
}

// Common secret patterns
var CommonSecretPatterns = []string{
	"admin%d", "password%d", "secret%d",
	"jwt%d", "token%d", "key%d",
	"admin_%d", "password_%d", "secret_%d",
	"jwt_%d", "token_%d", "key_%d",
	"admin-%d", "password-%d", "secret-%d",
	"jwt-%d", "token-%d", "key-%d",
}

// Common secret suffixes
var CommonSecretSuffixes = []string{
	"123", "456", "789", "!",
	"@", "#", "$", "%", "^", "&", "*",
	"_", "-", "+", "=", ".",
}

// Common secret prefixes
var CommonSecretPrefixes = []string{
	"jwt_", "token_", "key_", "secret_",
	"admin_", "password_", "master_",
	"jwt-", "token-", "key-", "secret-",
	"admin-", "password-", "master-",
}
