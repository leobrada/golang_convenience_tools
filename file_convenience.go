package convience_tools

import (
    "os"
)

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
