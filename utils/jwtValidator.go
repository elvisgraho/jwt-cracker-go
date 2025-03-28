package utils

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// SupportedAlgorithms defines the list of supported algorithms for the JWT.
var SupportedAlgorithms = []string{
	"HS256", "HS384", "HS512",
	"RS256", "RS384", "RS512",
	"ES256", "ES384", "ES512",
	"none",
}

// DecodeHeader decodes the header part of a JWT token.
func DecodeHeader(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 1 {
		return nil, fmt.Errorf("invalid token format: header part missing")
	}

	// Add padding if needed
	headerStr := parts[0]
	if l := len(headerStr) % 4; l > 0 {
		headerStr += strings.Repeat("=", 4-l)
	}

	headerData, err := base64.StdEncoding.DecodeString(headerStr)
	if err != nil {
		return nil, fmt.Errorf("invalid token format: failed to decode header")
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerData, &header); err != nil {
		return nil, fmt.Errorf("invalid token format: failed to parse header")
	}

	return header, nil
}

// ValidateToken checks if the token is valid based on its format and header's algorithm.
func ValidateToken(token string) (bool, string) {
	isTokenValid := validateGeneralJwtFormat(token)
	var algorithm string
	if isTokenValid {
		header, err := DecodeHeader(token)
		if err == nil {
			algorithm, _ = header["alg"].(string)
		}
	}

	return isTokenValid, algorithm
}

// validateGeneralJwtFormat checks the general format of a JWT token.
func validateGeneralJwtFormat(token string) bool {
	if len(token) == 0 {
		fmt.Println("Missing token")
		return false
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		fmt.Println("Invalid token format. Invalid number of parts.")
		return false
	}

	for _, part := range parts {
		if len(part) == 0 {
			fmt.Println("Invalid token format. Parts should not be empty.")
			return false
		}
	}

	return true
}

// IsSupportedAlgorithm checks if the given algorithm is in the list of supported algorithms.
func IsSupportedAlgorithm(alg string) bool {
	for _, a := range SupportedAlgorithms {
		if alg == a {
			return true
		}
	}
	return false
}
