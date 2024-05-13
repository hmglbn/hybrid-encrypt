package rsa_keys

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
)

func ParsePrivateKeyFromFile(path string, sl *slog.Logger) (*rsa.PrivateKey, error) {
	const op = "rsa.ParsePrivateKeyFromFile"

	sl.Debug("starting ParsePrivateKeyFromFile...")

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w, %s", err, op)
	}
	defer file.Close()

	sl.Debug("pem file opened successfully")

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get file information: %w, %s", err, op)
	}

	fileSize := fileInfo.Size()
	fileContent := make([]byte, fileSize)

	sl.Debug("successfully received information from the pem file")

	_, err = file.Read(fileContent)
	if err != nil {
		return nil, fmt.Errorf("failed to read file content: %w, %s", err, op)
	}

	sl.Debug("successfully read information from pem file")

	block, _ := pem.Decode(fileContent)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	sl.Debug("information from the pem file was successfully decrypted")

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w, %s", err, op)
	}

	sl.Debug("successfully parse private key")

	return privateKey, nil
}
