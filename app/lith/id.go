package lith

import (
	"crypto/rand"
	"encoding/hex"
)

// GenerateID returns a random 16 bytes of data, hex encoded.
func GenerateID() string {
	return <-nextID
}

func init() {
	nextID = make(chan string, 8)

	go func() {
		b := make([]byte, 16)
		for {
			if _, err := rand.Read(b); err != nil {
				panic(err)
			}
			nextID <- hex.EncodeToString(b)
		}
	}()
}

var nextID chan string
