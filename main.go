package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/elvisgraho/jwt-cracker-go/utils"
)

func main() {
	args := utils.NewArgsParser(utils.DefaultAlphabet, utils.DefaultMaxSecretLength)

	isTokenValid, algorithm := utils.ValidateToken(args.Token)

	if !isTokenValid && args.Token == "" {
		os.Exit(utils.ExitCodeFailure)
	}

	startTime := time.Now()

	// Split token to get content
	jwtParts := strings.Split(args.Token, ".")
	if len(jwtParts) < 3 {
		fmt.Println("Invalid token format")
		os.Exit(utils.ExitCodeFailure)
	}

	var secret string

	if args.DictionaryFilePath != "" {
		secret = utils.BruteList(args.Alphabet, utils.DefaultMaxSecretLength, algorithm, jwtParts, args.DictionaryFilePath)
	} else {
		secret = utils.Brute(args.Alphabet, utils.DefaultMaxSecretLength, algorithm, jwtParts)
	}

	// Check if all work is done and print result
	printResult(startTime, secret)
}

func printResult(startTime time.Time, result string) {
	duration := time.Since(startTime).Seconds()
	if result != "" {
		fmt.Printf("SECRET FOUND: %s\n", result)
	} else {
		fmt.Println("SECRET NOT FOUND")
	}
	fmt.Printf("Time taken (sec): %f\n", duration)
}
