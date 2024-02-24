// Package argsparser provides functionality for parsing command-line arguments.
package utils

import (
	"flag"
	"fmt"
	"os"
)

// Args holds the values of the command-line arguments.
type Args struct {
	Token              string
	Alphabet           string
	MaxLength          int
	DictionaryFilePath string
	Force              bool
}

// NewArgsParser parses command-line arguments and returns an Args struct.
func NewArgsParser(defaultAlphabet string, defaultMaxSecretLength int) *Args {
	args := &Args{}
	flag.StringVar(&args.Token, "t", "", "HMAC-SHA JWT token to crack (required)")
	flag.StringVar(&args.Alphabet, "a", defaultAlphabet, "Alphabet to use for the brute force")
	flag.IntVar(&args.MaxLength, "max", defaultMaxSecretLength, "Maximum length of the secret")
	flag.StringVar(&args.DictionaryFilePath, "f", "", "Password file to use instead of the brute force")
	flag.Parse()

	if args.Token == "" {
		fmt.Println("Error: Token -t is required")
		flag.Usage()
		os.Exit(1)
	}

	return args
}
