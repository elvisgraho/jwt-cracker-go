// Package argsparser provides functionality for parsing command-line arguments.
package utils

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"runtime"
)

// Args holds the values of the command-line arguments.
type Args struct {
	Token              string
	Alphabet           string
	MaxLength          int
	DictionaryFilePath string
	Force              bool
	Analyze            bool
	GenerateSecrets    bool
	Pattern           string
	Algorithm         string
	Verbose           bool
	OutputFile        string
	Concurrent        int
	BatchSize         int
}

// NewArgsParser parses command-line arguments and returns an Args struct.
func NewArgsParser(defaultAlphabet string, defaultMaxSecretLength int) *Args {
	args := &Args{}
	
	// Required arguments
	flag.StringVar(&args.Token, "t", "", "JWT token to crack (required)")
	
	// Optional arguments
	flag.StringVar(&args.Alphabet, "a", defaultAlphabet, "Alphabet to use for brute force")
	flag.IntVar(&args.MaxLength, "max", defaultMaxSecretLength, "Maximum length of the secret")
	flag.StringVar(&args.DictionaryFilePath, "f", "", "Password file to use instead of brute force")
	flag.StringVar(&args.Pattern, "p", "", "Pattern to use for secret generation (base64, hex, uuid, email, date, ip)")
	flag.StringVar(&args.Algorithm, "alg", "", "JWT algorithm to use (HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512)")
	flag.StringVar(&args.OutputFile, "o", "", "Output file for results")
	flag.BoolVar(&args.Force, "force", false, "Force cracking even if token is invalid")
	flag.BoolVar(&args.Analyze, "analyze", false, "Analyze token for potential weaknesses")
	flag.BoolVar(&args.GenerateSecrets, "generate", false, "Generate common JWT secrets")
	flag.BoolVar(&args.Verbose, "v", false, "Enable verbose output")
	flag.IntVar(&args.Concurrent, "c", 0, "Number of concurrent workers (0 = CPU count)")
	flag.IntVar(&args.BatchSize, "batch", 0, "Batch size for processing (0 = auto)")

	// Parse flags
	flag.Parse()

	// Validate required arguments
	if args.Token == "" && !args.GenerateSecrets {
		fmt.Println("Error: Token (-t) is required unless generating secrets (-generate)")
		flag.Usage()
		os.Exit(ExitCodeFailure)
	}

	// Validate pattern if specified
	if args.Pattern != "" {
		validPatterns := []string{PatternBase64, PatternHex, PatternUUID, PatternEmail, PatternDate, PatternIP}
		valid := false
		for _, p := range validPatterns {
			if args.Pattern == p {
				valid = true
				break
			}
		}
		if !valid {
			fmt.Printf("Error: Invalid pattern. Must be one of: %s\n", strings.Join(validPatterns, ", "))
			os.Exit(ExitCodeFailure)
		}
	}

	// Validate algorithm if specified
	if args.Algorithm != "" {
		validAlgorithms := []string{AlgHS256, AlgHS384, AlgHS512, AlgRS256, AlgRS384, AlgRS512, AlgES256, AlgES384, AlgES512, AlgNone}
		valid := false
		for _, a := range validAlgorithms {
			if args.Algorithm == a {
				valid = true
				break
			}
		}
		if !valid {
			fmt.Printf("Error: Invalid algorithm. Must be one of: %s\n", strings.Join(validAlgorithms, ", "))
			os.Exit(ExitCodeFailure)
		}
	}

	// Set default concurrent workers if not specified
	if args.Concurrent <= 0 {
		args.Concurrent = runtime.NumCPU()
	}

	// Set default batch size if not specified
	if args.BatchSize <= 0 {
		args.BatchSize = args.Concurrent * 100
	}

	return args
}
