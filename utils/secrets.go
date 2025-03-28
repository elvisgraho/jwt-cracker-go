package utils

import (
	"fmt"
	"strings"
	"time"
)

// GenerateCommonSecrets generates common JWT secrets based on patterns
func GenerateCommonSecrets() []string {
	var secrets []string

	// Prefixes for combinations
	prefixes := []string{
		// Environment prefixes
		"dev_", "prod_", "staging_", "qa_", "uat_", "test_",
		"local_", "development_", "production_", "staging_",
		// Service prefixes
		"api_", "web_", "mobile_", "frontend_", "backend_",
		"service_", "app_", "client_", "server_", "db_",
		// Cloud prefixes
		"aws_", "azure_", "gcp_", "cloud_", "k8s_", "docker_",
		// Security prefixes
		"secure_", "private_", "public_", "internal_", "external_",
		// Common prefixes
		"my_", "our_", "company_", "enterprise_", "corp_",
		// Version prefixes
		"v1_", "v2_", "v3_", "beta_", "alpha_",
	}

	// Base words for combinations
	baseWords := []string{
		"jwt", "token", "key", "auth", "secret",
		"api", "test", "dev", "prod", "admin",
		"root", "system", "service", "app", "db", "database", 
		"prod", "qa", "staging", "local", "admin",
		// Adding more realistic base words
		"company", "enterprise", "corp", "inc", "ltd",
		"aws", "azure", "gcp", "cloud", "server",
		"client", "user", "customer", "partner", "vendor",
		"internal", "external", "public", "private", "shared",
	}

	// Suffixes for combinations
	suffixes := []string{
		"", "123", "456", "789", "1", "2", "3",
		"_key", "_secret", "_token", "_auth",
		"_api", "_jwt", "_test", "_dev", "_prod",
		"_admin", "_root", "_system", "_service",
		"_app", "_private", "_public", "_signing",
		"_access", "_refresh", "_bearer", "_oauth",
		"_oauth2", "_env", "_config", "_settings",
		"_security", "_secure", "_password", "_pass",
		// Adding more realistic suffixes
		"_prod", "_dev", "_staging", "_qa", "_uat",
		"_internal", "_external", "_shared", "_common",
		"_default", "_custom", "_legacy", "_new",
		"_v1", "_v2", "_v3", "_beta", "_alpha",
	}

	// Special characters for combinations
	specialChars := []string{
		"", "!", "@", "#", "$", "%", "^", "&", "*",
		"_", "-", ".", ":", ";", "=", "+", "|",
		// Adding more realistic special characters
		"@", "#", "$", "!", "?", "~", "^", "&",
	}

	// Common development environment patterns
	envPatterns := []string{
		"%s_%s_%s",    // word_env_suffix
		"%s-%s-%s",    // word-env-suffix
		"%s.%s.%s",    // word.env.suffix
		"%s%s%s",      // wordenvsuffix
		"%s_%s%s",     // word_envsuffix
		"%s%s_%s",     // wordenv_suffix
	}

	// Generate combinations with prefixes
	for _, prefix := range prefixes {
		for _, word := range baseWords {
			// Add prefix + word combinations
			secrets = append(secrets, prefix+word)
			secrets = append(secrets, prefix+strings.ToUpper(word))
			secrets = append(secrets, prefix+strings.Title(word))

			// Add prefix + word + suffix combinations
			for _, suffix := range suffixes {
				secrets = append(secrets, prefix+word+suffix)
				secrets = append(secrets, prefix+strings.ToUpper(word)+suffix)
				secrets = append(secrets, prefix+strings.Title(word)+suffix)

				// Add prefix + word + special char + suffix combinations
				for _, char := range specialChars {
					secrets = append(secrets, prefix+word+char+suffix)
					secrets = append(secrets, prefix+strings.ToUpper(word)+char+suffix)
					secrets = append(secrets, prefix+strings.Title(word)+char+suffix)
				}
			}
		}
	}

	// Generate combinations without prefixes (original logic)
	for _, word := range baseWords {
		// Add base word
		secrets = append(secrets, word)
		secrets = append(secrets, strings.ToUpper(word))
		secrets = append(secrets, strings.Title(word))

		// Add combinations with suffixes
		for _, suffix := range suffixes {
			secrets = append(secrets, word+suffix)
			secrets = append(secrets, strings.ToUpper(word)+suffix)
			secrets = append(secrets, strings.Title(word)+suffix)

			// Add combinations with special characters
			for _, char := range specialChars {
				secrets = append(secrets, word+char+suffix)
				secrets = append(secrets, strings.ToUpper(word)+char+suffix)
				secrets = append(secrets, strings.Title(word)+char+suffix)
			}
		}

		// Add numeric combinations
		for i := 1; i <= 20; i++ {
			secrets = append(secrets, fmt.Sprintf("%s%d", word, i))
			secrets = append(secrets, fmt.Sprintf("%s_%d", word, i))
			secrets = append(secrets, fmt.Sprintf("%s-%d", word, i))
			secrets = append(secrets, fmt.Sprintf("%s.%d", word, i))
		}
	}

	// Generate environment-based combinations
	environments := []string{"dev", "prod", "staging", "qa", "uat", "test"}
	for _, word := range baseWords {
		for _, env := range environments {
			for _, pattern := range envPatterns {
				secrets = append(secrets, fmt.Sprintf(pattern, word, env, "key"))
				secrets = append(secrets, fmt.Sprintf(pattern, word, env, "secret"))
				secrets = append(secrets, fmt.Sprintf(pattern, word, env, "token"))
				secrets = append(secrets, fmt.Sprintf(pattern, word, env, "jwt"))
			}
		}
	}

	// Add date-based patterns
	currentYear := time.Now().Year()
	for year := currentYear - 5; year <= currentYear; year++ {
		for _, word := range baseWords {
			secrets = append(secrets, fmt.Sprintf("%s_%d", word, year))
			secrets = append(secrets, fmt.Sprintf("%s-%d", word, year))
			secrets = append(secrets, fmt.Sprintf("%s.%d", word, year))
			secrets = append(secrets, fmt.Sprintf("%s%d", word, year))
		}
	}

	// Add common cloud service patterns
	cloudServices := []string{"aws", "azure", "gcp", "cloud"}
	for _, service := range cloudServices {
		for _, word := range baseWords {
			secrets = append(secrets, fmt.Sprintf("%s_%s_key", service, word))
			secrets = append(secrets, fmt.Sprintf("%s_%s_secret", service, word))
			secrets = append(secrets, fmt.Sprintf("%s_%s_token", service, word))
			secrets = append(secrets, fmt.Sprintf("%s_%s_jwt", service, word))
		}
	}

	return secrets
} 