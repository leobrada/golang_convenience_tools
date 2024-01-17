package convenience_tools

import (
	"io"
	"os"
	"strings"
)

// GetWriter takes a string and returns an io.Writer and an error.
// If the input is "stdout", it returns os.Stdout.
// If the input is "stderr", it returns os.Stderr.
// If the input is a file path, it returns a file writer.
// If the input is invalid, it returns an error.
func GetWriter(s string) (io.Writer, error) {
	switch strings.ToLower(s) {
	case "stdout":
		return os.Stdout, nil
	case "stderr":
		return os.Stderr, nil
	default:
		// Check if the path is valid and writable
		file, err := os.OpenFile(s, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			return nil, err
		}
		return file, nil
	}
}

// ReadStringFromFile reads up to numBytes bytes from a file and returns them as a string.
// If numBytes is larger than the file size, it reads the entire file.
//
// Arguments:
// - filePath: Path to the file to be read.
// - numBytes: Maximum number of bytes to read.
//
// Returns:
// - A string containing the read bytes.
// - An error if the file cannot be opened or read.
//
// Note: For large files, this function is more memory-efficient as it dynamically allocates buffer size.
func ReadStringFromFile(filePath string, numBytes int) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Get the file size to prevent over-allocation
	stat, err := file.Stat()
	if err != nil {
		return "", err
	}

	fileSize := stat.Size()
	if fileSize < int64(numBytes) {
		numBytes = int(fileSize)
	}

	buffer := make([]byte, numBytes)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		return "", err
	}

	return string(buffer[:n]), nil
}

// Deprecated
// Use ReadStringFromFile() instead
func ReadBytesFromFileAsString(filePath string, numBytes int) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	buffer := make([]byte, numBytes)
	n, err := file.Read(buffer)
	if err != nil {
		return "", err
	}

	return string(buffer[:n]), nil
}
