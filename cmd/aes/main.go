package main

import (
	"crypto/rand"
	"fmt"
	"hybrid-encrypt/pkg/aes"
)

func main() {
	//text := "Hello world!"
	data := make([]byte, 64)
	rand.Read(data)

	fmt.Println("Зашифрованный текст:", data)

	symmetricKey := make([]byte, 32)
	_, err := rand.Read(symmetricKey)
	if err != nil {
		panic(err)
	}

	cipher, err := aes.EncryptMessage(string(data), symmetricKey)
	if err != nil {
		panic(err)
	}

	decryptText, err := aes.DecryptMessage(symmetricKey, cipher)
	if err != nil {
		panic(err)
	}

	fmt.Println("Расшифрованный текст:", string(decryptText))
}
