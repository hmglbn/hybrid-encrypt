package hybrid

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

func Encrypt(data []byte, pk *rsa.PublicKey) ([]byte, error) {
	const op = "encrypt.Encrypt"

	// SHA256 hash
	h := sha256.New()
	_, err := h.Write(data)
	if err != nil {
		return nil, fmt.Errorf("sha256 encryption error: %w, %s", err, op)
	}

	// Generate a symmetric key for data encryption
	symmetricKey := make([]byte, 32)
	_, err = rand.Read(symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("error generating symmetric key: %w, %s", err, op)
	}

	// SHA256 is concatenated with a symmetric key
	concData := append(symmetricKey, h.Sum(nil)...)

	cipherRSA, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pk, concData, nil)
	if err != nil {
		return nil, fmt.Errorf("error when encrypting using rsa public key: %w, %s, sha256 size = %d, pk size = %d, msg size = %d, k-2*hash.Size()-2 = %d",
			err, op, sha256.New().Size(), pk.Size(), len(concData), pk.Size()-2*sha256.New().Size()-2)
	}

	// Encrypt data using symmetric encryption
	cipherAES, err := encryptWithSymmetricKey(data, symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("error encrypting data: %w, %s", err, op)
	}

	concRSAandAES := append(cipherAES, cipherRSA...)

	return concRSAandAES, nil
}

func encryptWithSymmetricKey(data []byte, key []byte) ([]byte, error) {
	// Creates new cipher block 32 bytes (depending on the symmetric key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// The AES block size in bytes + data size in bytes
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}
