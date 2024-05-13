package rsa_keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func GeneratePrivetKey(key_size int) (*rsa.PrivateKey, error) {
	const op = "rsa.GeneratePrivetKey"

	// Generate an RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, key_size)
	if err != nil {
		return nil, fmt.Errorf("error generating RSA private key: %w, %s", err, op)
	}

	// Encode the private key in PEM format
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	// Create or overwrite the PEM file
	pemFile, err := os.Create("pkg/rsarecipient_private_key.pem")
	if err != nil {
		return nil, fmt.Errorf("error creating PEM file: %w, %s", err, op)
	}
	defer pemFile.Close()

	// Write the PEM data to the file
	if err := pem.Encode(pemFile, pemBlock); err != nil {
		return nil, fmt.Errorf("error writing PEM data: %w, %s", err, op)
	}

	return privateKey, nil
}
