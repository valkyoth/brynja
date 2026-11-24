// Host-only differential oracle. Inputs are deterministic, public test fixtures.
package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"os"
)

func field(id int, label string, n int) []byte {
	out := make([]byte, n)
	for offset := 0; offset < len(out); offset += sha256.Size {
		block := sha256.Sum256([]byte(fmt.Sprintf("brynja/gmac/v1/%d/%s/%d", id, label, offset)))
		copy(out[offset:], block[:])
	}
	return out
}

// GMAC is GCM with no payload. Go permits a custom nonce size; compute a full
// tag and take its leftmost t bytes, including for non-default nonce widths.
func tag(key, iv, aad []byte, t int) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		panic(err)
	}
	return aead.Seal(nil, iv, nil, aad)[:t]
}

func emit(w *bufio.Writer, id, k, n, a, t int) {
	key, iv, aad := field(id, "key", k), field(id, "iv", n), field(id, "aad", a)
	expected := tag(key, iv, aad, t)
	row := func(kind string) {
		fmt.Fprintf(w, "%s\t%x\t%x\t%x\t%x\n", kind, key, iv, aad, expected)
	}
	row("seal")
	row("open")
	switch id % 4 {
	case 0:
		key[len(key)-1] ^= 1
	case 1:
		iv[len(iv)-1] ^= 1
	case 2:
		aad = append(aad, 1)
	case 3:
		expected[len(expected)-1] ^= 1
	}
	if bytes.Equal(tag(key, iv, aad, t), expected) {
		panic("negative fixture still authenticates")
	}
	row("reject")
}

func main() {
	w := bufio.NewWriter(os.Stdout)
	id := 0
	for _, k := range []int{16, 24, 32} {
		for t := 12; t <= 16; t++ {
			for _, n := range []int{1, 3, 4, 5, 8, 11, 12, 13, 15, 16, 17, 128, 129} {
				for _, a := range []int{0, 1, 15, 16, 17, 31, 32, 33, 255, 256, 257, 4095, 4096, 4097} {
					emit(w, id, k, n, a, t)
					id++
				}
			}
		}
	}
	if err := w.Flush(); err != nil {
		panic(err)
	}
}
