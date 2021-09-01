package secret

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSecretAESSafe(t *testing.T) {
	safe := AESSafe("top-secret-string")

	data := make([]byte, 123)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	ciphertext, err := safe.Encrypt(data)
	if err != nil {
		t.Fatalf("cannot encrypt: %s", err)
	}

	plain, err := safe.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("cannot decrypt: %s", err)
	}

	if !bytes.Equal(data, plain) {
		t.Fatalf("malformed data: %q != %q", data, plain)
	}
}
