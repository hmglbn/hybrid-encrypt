package hybrid

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

func Dencrypt(data []byte, pk *rsa.PrivateKey) ([]byte, error) {
	const op = "dencrypt.Dencrypt"

	cipherAES := data[:len(data)-256]
	cipherRSA := data[len(data)-256:]

	// Decrypt the symmetric key using the recipient's private key
	decryptedSymmetricKeyAndSHA256, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, pk, cipherRSA, nil)
	if err != nil {
		return nil, fmt.Errorf("error decrypting symmetric key: %w, %s", err, op)
	}

	decryptedSymmetricKey := decryptedSymmetricKeyAndSHA256[:32]
	h := decryptedSymmetricKeyAndSHA256[32:]

	// Decrypt data using the decrypted symmetric key
	decryptedDataWithSymmetricKey, err := decryptWithSymmetricKey(cipherAES, decryptedSymmetricKey)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %w, %s", err, op)
	}

	securityСheck := sha256.New()
	_, err = securityСheck.Write(decryptedDataWithSymmetricKey)
	if err != nil {
		return nil, fmt.Errorf("sha256 encryption error: %w, %s", err, op)
	}

	if !bytes.Equal(securityСheck.Sum(nil), h) {
		return nil, fmt.Errorf("data received from rsa and aes do not match: %s", op)
	}

	return decryptedDataWithSymmetricKey, nil
}

func decryptWithSymmetricKey(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}
