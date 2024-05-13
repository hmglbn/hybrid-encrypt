package main

import (
	"crypto/rand"
	"fmt"
	"hybrid-encrypt/pkg/hybrid"
	"hybrid-encrypt/pkg/rsa_keys"
)

func main() {
	pk, err := rsa_keys.GeneratePK(256)
	if err != nil {
		panic(err)
	}

	data := make([]byte, 14)
	rand.Read(data)

	data = []byte("hello")

	cipher, err := hybrid.Encrypt(data, &pk.PublicKey)
	if err != nil {
		panic(err)
	}

	decryptText, err := hybrid.Dencrypt(cipher, pk)
	if err != nil {
		panic(err)
	}

	fmt.Println("Расшифрованный текст:", string(decryptText))
}
