package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/elvisgraho/jwt-cracker-go/utils"
)

func main() {
	args := utils.NewArgsParser(utils.DefaultAlphabet, utils.DefaultMaxSecretLength)

	// Handle secret generation mode
	if args.GenerateSecrets {
		secrets := utils.GenerateCommonSecrets()
		if args.OutputFile != "" {
			file, err := os.Create(args.OutputFile)
			if err != nil {
				log.Fatalf("Failed to create output file: %v", err)
			}
			defer file.Close()

			writer := bufio.NewWriter(file)
			for _, secret := range secrets {
				_, err := writer.WriteString(secret + "\n")
				if err != nil {
					log.Fatalf("Failed to write secret: %v", err)
				}
			}
			writer.Flush()
			fmt.Printf("Generated %d secrets to %s\n", len(secrets), args.OutputFile)
		} else {
			for _, secret := range secrets {
				fmt.Println(secret)
			}
		}
		return
	}

	// Split token to get content
	jwtParts := strings.Split(args.Token, ".")
	if len(jwtParts) < 3 {
		fmt.Println("Error: Invalid token format")
		os.Exit(utils.ExitCodeFailure)
	}

	// Get algorithm from token header
	header, err := utils.DecodeHeader(args.Token)
	if err != nil {
		fmt.Printf("Error decoding header: %v\n", err)
		os.Exit(utils.ExitCodeFailure)
	}

	algorithm, ok := header["alg"].(string)
	if !ok {
		fmt.Println("Error: No algorithm specified in token header")
		os.Exit(utils.ExitCodeFailure)
	}

	// Validate algorithm
	if !utils.IsSupportedAlgorithm(algorithm) {
		fmt.Printf("Error: Unsupported algorithm %s\n", algorithm)
		os.Exit(utils.ExitCodeFailure)
	}

	// Analyze token if requested
	if args.Analyze {
		analyzer, err := utils.NewTokenAnalyzer(args.Token)
		if err != nil {
			fmt.Printf("Error analyzing token: %v\n", err)
			os.Exit(utils.ExitCodeFailure)
		}
		findings := analyzer.Analyze()
		if len(findings) > 0 {
			fmt.Println("\nToken Analysis Findings:")
			for _, finding := range findings {
				fmt.Printf("- %s\n", finding)
			}
		} 
	}

	startTime := time.Now()
	var secret string

	// Determine cracking method
	if args.DictionaryFilePath != "" {
		secret = utils.BruteList(args.Alphabet, args.MaxLength, algorithm, jwtParts, args.DictionaryFilePath)
	} else {
		secret = utils.Brute(args.Alphabet, args.MaxLength, algorithm, jwtParts)
	}

	// Print results
	printResult(startTime, secret, args.OutputFile)
}

func printResult(startTime time.Time, result string, outputFile string) {
	duration := time.Since(startTime).Seconds()
	output := fmt.Sprintf("Time taken (sec): %.2f\n", duration)

	if result != "" {
		output = fmt.Sprintf("SECRET FOUND: %s\n%s", result, output)
	} else {
		output = "SECRET NOT FOUND\n" + output
	}

	if outputFile != "" {
		utils.SaveToFile(outputFile, []string{output})
		fmt.Printf("Results saved to %s\n", outputFile)
	} else {
		fmt.Println(output)
	}
}
