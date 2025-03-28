package utils

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"log"
	"os"
	"regexp"
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

// Common JWT patterns and their corresponding regex
var CommonPatterns = map[string]*regexp.Regexp{
	"base64": regexp.MustCompile(`^[A-Za-z0-9+/=]+$`),
	"hex":    regexp.MustCompile(`^[0-9a-fA-F]+$`),
	"uuid":   regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`),
}

// ProgressTracker tracks and displays progress
type ProgressTracker struct {
	mu            sync.Mutex
	total         int64
	current       int64
	startTime     time.Time
	lastUpdate    time.Time
	updateInterval time.Duration
	lastRate      float64
	lastETA       time.Duration
}

func NewProgressTracker(total int64) *ProgressTracker {
	return &ProgressTracker{
		total:         total,
		startTime:     time.Now(),
		lastUpdate:    time.Now(),
		updateInterval: time.Second,
	}
}

func (p *ProgressTracker) Update(increment int64) {
	p.mu.Lock()
	p.current += increment
	now := time.Now()
	p.mu.Unlock()

	// Only update display if enough time has passed
	if now.Sub(p.lastUpdate) >= p.updateInterval {
		p.mu.Lock()
		elapsed := now.Sub(p.startTime).Seconds()
		rate := float64(p.current) / elapsed
		remaining := float64(p.total-p.current) / rate
		
		// Always update time display
		remainingDuration := time.Duration(remaining * float64(time.Second))
		elapsedDuration := time.Duration(elapsed * float64(time.Second))
		
		// Format times
		elapsedHours := int(elapsedDuration.Hours())
		elapsedMinutes := int(elapsedDuration.Minutes()) % 60
		elapsedSeconds := int(elapsedDuration.Seconds()) % 60
		
		remainingHours := int(remainingDuration.Hours())
		remainingMinutes := int(remainingDuration.Minutes()) % 60
		remainingSeconds := int(remainingDuration.Seconds()) % 60
		
		// Update display with current rate
		fmt.Printf("\rProgress: %.2f%% (%d/%d) - Rate: %.2f/sec - Time: %02d:%02d:%02d - ETA: %02d:%02d:%02d", 
			float64(p.current)*100/float64(p.total),
			p.current,
			p.total,
			rate,
			elapsedHours,
			elapsedMinutes,
			elapsedSeconds,
			remainingHours,
			remainingMinutes,
			remainingSeconds)
		
		p.lastRate = rate
		p.lastETA = remainingDuration
		p.lastUpdate = now
		p.mu.Unlock()
	}
}

// SignatureGenerator creates a function to generate HMAC signatures
func SignatureGenerator(algorithm string, jwtParts []string) func(secret string) string {
	dataToSign := strings.Join(jwtParts[:2], ".")
	
	hashFunc, ok := DigestAlgorithm[algorithm]
	if !ok {
		return nil
	}

	return func(secret string) string {
		h := hmac.New(hashFunc, []byte(secret))
		h.Write([]byte(dataToSign))
		return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	}
}

// TokenAnalyzer analyzes JWT tokens for patterns and potential weaknesses
type TokenAnalyzer struct {
	Header  map[string]interface{}
	Payload map[string]interface{}
}

func NewTokenAnalyzer(token string) (*TokenAnalyzer, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	header, err := decodeBase64(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid header: %v", err)
	}

	payload, err := decodeBase64(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid payload: %v", err)
	}

	return &TokenAnalyzer{
		Header:  header,
		Payload: payload,
	}, nil
}

func (ta *TokenAnalyzer) Analyze() []string {
	var findings []string

	// Check for common weak algorithms
	if alg, ok := ta.Header["alg"].(string); ok {
		if alg == "none" {
			findings = append(findings, "Token uses 'none' algorithm - potential security risk")
		}
	}

	// Check for common weak claims
	if exp, ok := ta.Payload["exp"].(float64); ok {
		if time.Unix(int64(exp), 0).Before(time.Now()) {
			findings = append(findings, "Token has expired")
		}
	}

	// Check for sensitive data in payload
	sensitiveKeys := []string{"password", "secret", "key", "token", "api", "api_key", "api-key", "access_token", "refresh_token", "session_id"}
	for _, key := range sensitiveKeys {
		if _, exists := ta.Payload[key]; exists {
			findings = append(findings, fmt.Sprintf("Sensitive data found in payload: %s", key))
		}
	}

	return findings
}

func Brute(charSet string, maxLen int, algorithm string, jwtParts []string) string {
	signatureFunc := SignatureGenerator(algorithm, jwtParts)
	if signatureFunc == nil {
		return ""
	}
	
	targetSignature := jwtParts[2]
	workerCount := runtime.NumCPU()
	
	// Calculate total combinations for progress tracking
	var totalCombinations int64
	for i := 1; i <= maxLen; i++ {
		totalCombinations += int64(pow(len(charSet), i))
	}
	
	progress := NewProgressTracker(totalCombinations)
	done := make(chan struct{})
	found := make(chan string, 1) // Buffer the channel to prevent blocking

	// Process each length sequentially
	for length := 1; length <= maxLen; length++ {
		// Calculate combinations for this length
		combinations := pow(len(charSet), length)
		
		// Process combinations in batches
		batchSize := workerCount * 100
		if batchSize > combinations {
			batchSize = combinations
		}
		
		// Initialize first combination for this length
		combination := make([]byte, length)
		for i := range combination {
			combination[i] = charSet[0]
		}

		// Process all combinations for current length
		for processed := 0; processed < combinations; processed += batchSize {
			// Calculate actual batch size for this iteration
			currentBatchSize := batchSize
			if processed+batchSize > combinations {
				currentBatchSize = combinations - processed
			}
			
			batch := make([]string, 0, currentBatchSize)
			
			// Fill batch with combinations
			for i := 0; i < currentBatchSize; i++ {
				batch = append(batch, string(combination))
				
				// Generate next combination
				carry := true
				for j := length - 1; j >= 0; j-- {
					if !carry {
						break
					}
					pos := strings.IndexByte(charSet, combination[j])
					if pos == len(charSet)-1 {
						combination[j] = charSet[0]
						carry = true
					} else {
						combination[j] = charSet[pos+1]
						carry = false
					}
				}
			}

			// Process batch in parallel
			var wg sync.WaitGroup
			chunkSize := currentBatchSize / workerCount
			if chunkSize == 0 {
				chunkSize = 1
			}
			
			for i := 0; i < workerCount; i++ {
				wg.Add(1)
				start := i * chunkSize
				end := start + chunkSize
				if i == workerCount-1 {
					end = currentBatchSize
				}
				if start >= currentBatchSize {
					wg.Done()
					continue
				}
				go func(start, end int) {
					defer wg.Done()
					for j := start; j < end; j++ {
						select {
						case <-done:
							return
						default:
							if signatureFunc(batch[j]) == targetSignature {
								select {
								case found <- batch[j]:
									close(done)
								case <-done:
								}
							}
							progress.Update(1)
						}
					}
				}(start, end)
			}

			wg.Wait()
			select {
			case result := <-found:
				fmt.Println() // Clear progress line
				return result
			default:
				continue
			}
		}
	}

	fmt.Println() // Clear progress line
	return ""
}

func BruteList(charSet string, maxLen int, algorithm string, jwtParts []string, filePath string) string {
	signatureFunc := SignatureGenerator(algorithm, jwtParts)
	if signatureFunc == nil {
		return ""
	}

	targetSignature := jwtParts[2]
	workerCount := runtime.NumCPU()
	
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Failed to open dictionary file: %v", err)
	}
	defer file.Close()

	// Count total lines for progress tracking
	scanner := bufio.NewScanner(file)
	var totalLines int64
	for scanner.Scan() {
		totalLines++
	}
	file.Seek(0, 0)
	
	progress := NewProgressTracker(totalLines)
	done := make(chan struct{})
	found := make(chan string, 1) // Buffer the channel to prevent blocking

	scanner = bufio.NewScanner(file)
	batchSize := workerCount * 100
	batch := make([]string, 0, batchSize)

	for scanner.Scan() {
		batch = append(batch, scanner.Text())
		
		if len(batch) >= batchSize {
			var wg sync.WaitGroup
			chunkSize := batchSize / workerCount
			
			for i := 0; i < workerCount; i++ {
				wg.Add(1)
				start := i * chunkSize
				end := start + chunkSize
				if i == workerCount-1 {
					end = len(batch)
				}
				go func(start, end int) {
					defer wg.Done()
					for j := start; j < end; j++ {
						select {
						case <-done:
							return
						default:
							if signatureFunc(batch[j]) == targetSignature {
								select {
								case found <- batch[j]:
									close(done)
								case <-done:
								}
							}
							progress.Update(1)
						}
					}
				}(start, end)
			}

			wg.Wait()
			select {
			case result := <-found:
				fmt.Println() // Clear progress line
				return result
			default:
				batch = batch[:0]
				continue
			}
		}
	}

	// Process the final batch
	if len(batch) > 0 {
		var wg sync.WaitGroup
		chunkSize := len(batch) / workerCount
		if chunkSize == 0 {
			chunkSize = 1
		}
		
		for i := 0; i < workerCount; i++ {
			wg.Add(1)
			start := i * chunkSize
			end := start + chunkSize
			if i == workerCount-1 {
				end = len(batch)
			}
			if start >= len(batch) {
				wg.Done()
				continue
			}
			go func(start, end int) {
				defer wg.Done()
				for j := start; j < end; j++ {
					select {
					case <-done:
						return
					default:
						if signatureFunc(batch[j]) == targetSignature {
							select {
							case found <- batch[j]:
								close(done)
							case <-done:
							}
						}
						progress.Update(1)
					}
				}
			}(start, end)
		}

		wg.Wait()
		select {
		case result := <-found:
			fmt.Println() // Clear progress line
			return result
		default:
		}
	}

	fmt.Println() // Clear progress line
	return ""
}

// Helper functions
func decodeBase64(s string) (map[string]interface{}, error) {
	// Add padding if needed
	if l := len(s) % 4; l > 0 {
		s += strings.Repeat("=", 4-l)
	}
	
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	
	var result map[string]interface{}
	if err := json.Unmarshal(decoded, &result); err != nil {
		return nil, err
	}
	
	return result, nil
}

func pow(base, exp int) int {
	result := 1
	for i := 0; i < exp; i++ {
		result *= base
	}
	return result
}
