package rsa

import (
	"crypto/rand"
	"fmt"
	"hybrid-encrypt/pkg/rsa_keys"
	"testing"
)

func Benchmark(b *testing.B) {
	pk, err := rsa_keys.GeneratePK(256*1.5)
	if err != nil {
		b.Fatalf("error generate rsa pk: %v", err)
	}

	mess := []int{128, 214, 256}

	for _, m := range mess {
		data := make([]byte, m)	
		rand.Read(data)

		b.Run(fmt.Sprintf("mess_length=%d", m), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				cipher, err := Encrypt(data, &pk.PublicKey)
				if err != nil {
					b.Fatalf("error encrypt text: %v", err)
				}
				_, err = Dencrypt(cipher, pk)
				if err != nil {
					b.Fatalf("error dencrypt text: %v", err)
				}
			}
		})
	}
}
