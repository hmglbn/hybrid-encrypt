package rsa_keys

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

func GeneratePrivetKeyWithoutLogs(key_size int) (*rsa.PrivateKey, error) {
	const op = "rsa.GeneratePrivetKey"

	// Generate an RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, key_size)
	if err != nil {
		return nil, fmt.Errorf("error generating RSA private key: %w, %s", err, op)
	}

	return privateKey, nil
}
