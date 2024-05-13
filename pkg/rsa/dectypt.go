package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

func Dencrypt(data []byte, pk *rsa.PrivateKey) ([]byte, error) {
	const op = "rsa.dencrypt.Dencrypt"

	hash := sha256.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, pk, data, nil)
	if err != nil {
		return nil, fmt.Errorf("error decrypting rsa: %w, %s", err, op)
	}
	return plaintext, nil
}
