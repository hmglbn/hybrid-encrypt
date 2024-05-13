package rsa_keys

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func ParsePrivateKeyFromFileWithoutLogs(path string) (*rsa.PrivateKey, error) {
	const op = "rsa.ParsePrivateKeyFromFile"

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w, %s", err, op)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get file information: %w, %s", err, op)
	}

	fileSize := fileInfo.Size()
	fileContent := make([]byte, fileSize)

	_, err = file.Read(fileContent)
	if err != nil {
		return nil, fmt.Errorf("failed to read file content: %w, %s", err, op)
	}

	block, _ := pem.Decode(fileContent)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w, %s", err, op)
	}

	return privateKey, nil
}
