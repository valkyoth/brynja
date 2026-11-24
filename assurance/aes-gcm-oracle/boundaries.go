// Standalone host test generator. No Brynja imports, external modules or secrets.
package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
)

func field(id int, label string, size int) []byte {
	b := make([]byte, size)
	for offset := 0; offset < size; offset += sha256.Size {
		d := sha256.Sum256([]byte(fmt.Sprintf("brynja/gcm-boundary/v1/%d/%s/%d", id, label, offset)))
		copy(b[offset:], d[:])
	}
	return b
}

func oracle(key []byte, n int) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	g, err := cipher.NewGCMWithNonceSize(block, n)
	if err != nil {
		panic(err)
	}
	return g
}

func changed(b []byte) []byte {
	if len(b) == 0 {
		return []byte{1}
	}
	c := bytes.Clone(b)
	c[len(c)-1] ^= 1
	return c
}

func emit(w *bufio.Writer, id, k, t, a, p int) {
	ivs := [...]int{1, 3, 4, 5, 8, 11, 12, 13, 15, 16, 17, 128, 129}
	key, iv := field(id, "key", k), field(id, "iv", ivs[id%len(ivs)])
	aad, plain := field(id, "aad", a), field(id, "pt", p)
	g := oracle(key, len(iv))
	sealed := g.Seal(nil, iv, plain, aad)
	ct, tag := sealed[:p], sealed[p:p+t] // The AEAD oracle returns the full tag.
	row := func(kind string, iv, aad, ct, pt, tag []byte) {
		fmt.Fprintf(w, "%s\t%x\t%x\t%x\t%x\t%x\t%x\n", kind, key, iv, aad, ct, pt, tag)
	}
	for _, kind := range []string{"seal", "seal-in-place", "open", "open-disjoint"} {
		row(kind, iv, aad, ct, plain, tag)
	}
	switch id % 4 {
	case 0:
		iv = changed(iv)
	case 1:
		aad = changed(aad)
	case 2:
		ct = changed(ct)
	case 3:
		tag = changed(tag)
	}
	row("reject", iv, aad, ct, nil, tag)
	row("reject-disjoint", iv, aad, ct, nil, tag)
}

func main() {
	// Independent guard on the generator itself (published AES-128 empty example).
	if got := oracle(make([]byte, 16), 12).Seal(nil, make([]byte, 12), nil, nil); hex.EncodeToString(got) != "58e2fccefa7e3061367f1d57a4e7455a" {
		panic("oracle preflight failed")
	}
	lengths := []int{}
	for i := 0; i <= 17; i++ {
		lengths = append(lengths, i)
	}
	lengths = append(lengths, 31, 32, 33, 63, 64, 65, 255, 256, 257)
	w := bufio.NewWriter(os.Stdout)
	id := 0
	for _, k := range []int{16, 24, 32} {
		for t := 12; t <= 16; t++ {
			for _, a := range lengths {
				for _, p := range lengths {
					emit(w, id, k, t, a, p)
					id++
				}
			}
			for _, n := range []int{4095, 4096, 4097} {
				emit(w, id, k, t, n, 1)
				emit(w, id+1, k, t, 1, n)
				id += 2
			}
		}
	}
	if err := w.Flush(); err != nil {
		panic(err)
	}
}
