package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

func Encrypt(data []byte, pk *rsa.PublicKey) ([]byte, error) {
	const op = "rsa.encrypt.Encrypt"

	hash := sha256.New()

	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pk, data, nil)
	if err != nil {
		return nil, fmt.Errorf("error when encrypting using rsa public key: %w, %s", err, op)
	}

	return ciphertext, err
}
