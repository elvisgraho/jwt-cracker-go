package utils

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

// DigestAlgorithm maps algorithm names to corresponding hash functions
var DigestAlgorithm = map[string]func() hash.Hash{
	"HS256": sha256.New,
	"HS384": sha512.New384,
	"HS512": sha512.New,
}

// SignatureGenerator creates a function to generate HMAC signatures based on the provided algorithm and content.
func SignatureGenerator(algorithm string, jwtParts []string) func(secret string) string {
	return func(secret string) string {
		// Concatenate the first two parts of the JWT with a period
		dataToSign := strings.Join(jwtParts[:2], ".")

		if hashFunc, ok := DigestAlgorithm[algorithm]; ok {
			h := hmac.New(hashFunc, []byte(secret))
			h.Write([]byte(dataToSign)) // The data to sign is the concatenated header and payload
			signature := base64.StdEncoding.EncodeToString(h.Sum(nil))
			signature = strings.ReplaceAll(signature, "=", "")
			signature = strings.ReplaceAll(signature, "+", "-")
			signature = strings.ReplaceAll(signature, "/", "_")
			return signature
		}
		// Handle error or unsupported algorithm
		return ""
	}
}

func IncrementByte(c byte, charSet string) (byte, bool) {
	for i := 0; i < len(charSet)-1; i++ {
		if charSet[i] == c {
			return charSet[i+1], false // Next character in the set
		}
	}
	if charSet[len(charSet)-1] == c {
		return charSet[0], true // Wrap around to the first character
	}
	return c, false // Character not found or no need to wrap
}

func NextCombination(s string, charSet string) string {
	byteStr := []byte(s) // Convert to byte slice once

	for i := len(byteStr) - 1; i >= 0; i-- {
		nextChar, wrap := IncrementByte(byteStr[i], charSet)
		byteStr[i] = nextChar
		if !wrap {
			return string(byteStr) // Early return if no wrap needed
		}
		// Handle wrap and check if it's the first character
		if i == 0 {
			return string(charSet[0]) + string(byteStr)
		}
	}
	return s
}

func Brute(charSet string, maxLen int, algorithm string, jwtParts []string) string {
	signatureFunc := SignatureGenerator(algorithm, jwtParts)
	targetSignature := jwtParts[2]
	workerCount := runtime.NumCPU()
	chunkSize := 240 // how many combinations each worker will process

	fmt.Printf("Worker count: %v\n", workerCount)

	for length := 1; length <= maxLen; length++ {
		lastChar := string(charSet[len(charSet)-1])
		lastCombination := lastChar + strings.Repeat(lastChar, length-1)

		startTime := time.Now()
		combination := string(charSet[0]) // Start with the first character for each length

		for {
			var chunkList [][]string
			var endOfCombinations bool

			// generate combinations to brute
			for worker := 0; worker < workerCount; worker++ {
				var chunks []string
				for ch := 0; ch < chunkSize; ch++ {
					chunks = append(chunks, combination)
					combination = NextCombination(combination, charSet)
					if combination == lastCombination {
						endOfCombinations = true
						break
					}
				}
				chunkList = append(chunkList, chunks)
				if endOfCombinations {
					break
				}
			}

			// brute combinations with workers
			var wg sync.WaitGroup
			guessedCombination := make(chan string, 1)

			for i := range chunkList {
				wg.Add(1)
				go func(chunk *[]string) {
					defer wg.Done()
					for _, candidate := range *chunk {
						if signatureFunc(candidate) == targetSignature {
							guessedCombination <- candidate
							close(guessedCombination)
							break
						} else if len(guessedCombination) > 0 {
							break
						}
					}
				}(&chunkList[i])
			}

			wg.Wait()

			if len(guessedCombination) > 0 {
				return <-guessedCombination
			} else {
				close(guessedCombination)
				if endOfCombinations {
					break
				}
			}
		}
		duration := time.Since(startTime).Seconds()
		if duration > 0 {
			fmt.Printf("%v letter combinations took %v seconds\n", length, duration)
		}
	}

	return "" // Return an empty string if no match is found
}

func BruteList(charSet string, maxLen int, algorithm string, jwtParts []string, filePath string) string {
	passList := LoadFile(filePath)
	signatureFunc := SignatureGenerator(algorithm, jwtParts)
	targetSignature := jwtParts[2]
	for _, pass := range passList {
		if signatureFunc(pass) == targetSignature {
			return pass
		}
	}
	return "" // Return an empty string if no match is found
}

func LoadFile(filePath string) []string {
	// Initialize passList
	var passList []string

	// Open the dictionary file
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Failed to open dictionary file: %v", err)
	}
	defer file.Close()

	// Create a new scanner to read the file line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// Append each line (password) to passList
		passList = append(passList, scanner.Text())
	}

	// Check for errors during scanning
	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading dictionary file: %v", err)
	}

	return passList
}
