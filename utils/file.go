package utils

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SaveToFile saves a slice of strings to a file
func SaveToFile(filepath string, lines []string) error {
	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		if _, err := writer.WriteString(line); err != nil {
			return fmt.Errorf("failed to write to file: %v", err)
		}
	}
	return writer.Flush()
}

// LoadFile loads a file into a slice of strings
func LoadFile(filepath string) ([]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}
	return lines, nil
}

// EnsureDirectory creates a directory if it doesn't exist
func EnsureDirectory(path string) error {
	if err := os.MkdirAll(path, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}
	return nil
}

// GetFileExtension returns the file extension without the dot
func GetFileExtension(path string) string {
	return strings.TrimPrefix(filepath.Ext(path), ".")
}

// IsFileExists checks if a file exists
func IsFileExists(filepath string) bool {
	_, err := os.Stat(filepath)
	return !os.IsNotExist(err)
}

// GetFileSize returns the size of a file in bytes
func GetFileSize(filepath string) (int64, error) {
	fileInfo, err := os.Stat(filepath)
	if err != nil {
		return 0, fmt.Errorf("failed to get file info: %v", err)
	}
	return fileInfo.Size(), nil
}

// CreateTempFile creates a temporary file with the given content
func CreateTempFile(content []string) (string, error) {
	tmpfile, err := os.CreateTemp("", "jwt-cracker-*.tmp")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %v", err)
	}

	writer := bufio.NewWriter(tmpfile)
	for _, line := range content {
		if _, err := writer.WriteString(line); err != nil {
			tmpfile.Close()
			os.Remove(tmpfile.Name())
			return "", fmt.Errorf("failed to write to temp file: %v", err)
		}
	}
	if err := writer.Flush(); err != nil {
		tmpfile.Close()
		os.Remove(tmpfile.Name())
		return "", fmt.Errorf("failed to flush temp file: %v", err)
	}
	tmpfile.Close()

	return tmpfile.Name(), nil
}

// CleanupTempFile removes a temporary file
func CleanupTempFile(filepath string) error {
	return os.Remove(filepath)
}

// AppendToFile appends content to an existing file
func AppendToFile(filepath string, content []string) error {
	file, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file for appending: %v", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range content {
		if _, err := writer.WriteString(line); err != nil {
			return fmt.Errorf("failed to write to file: %v", err)
		}
	}
	return writer.Flush()
} 