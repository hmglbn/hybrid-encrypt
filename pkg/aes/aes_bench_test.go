package aes

import (
	"crypto/rand"
	"fmt"

	"testing"
)

func Benchmark(b *testing.B) {
	symmetricKey := make([]byte, 32)
	_, err := rand.Read(symmetricKey)
	if err != nil {
		b.Fatalf("error generate symmetric key: %v", err)
	}

	mess := []int{256}

	for _, m := range mess {
		data := make([]byte, m)
		rand.Read(data)

		b.Run(fmt.Sprintf("mess_length=%d", m), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				cipher, err := EncryptMessage(string(data), symmetricKey)
				if err != nil {
					b.Fatalf("error encrypt text: %v", err)
				}
				_, err = DecryptMessage(symmetricKey, cipher)
				if err != nil {
					b.Fatalf("error dencrypt text: %v", err)
				}
			}
		})
	}
}
