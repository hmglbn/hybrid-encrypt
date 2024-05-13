package main

import (
	"crypto/rand"
	"fmt"
	"hybrid-encrypt/pkg/rsa"
	"hybrid-encrypt/pkg/rsa_keys"
)

func main() {
	pk, err := rsa_keys.GeneratePK(128)
	if err != nil {
		panic(err)
	}

	data := make([]byte, 32)
	rand.Read(data)

	cipher, err := rsa.Encrypt(data, &pk.PublicKey)
	if err != nil {
		panic(err)
	}

	decryptText, err := rsa.Dencrypt(cipher, pk)
	if err != nil {
		panic(err)
	}

	fmt.Println(data)
	fmt.Println(decryptText)
}
