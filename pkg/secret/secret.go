package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"testing"
)

type Safe interface {
	Encrypt(data []byte) ([]byte, error)
	Decrypt(data []byte) (Value, error)
}

func AESSafe(secret string) Safe {
	sum := sha512.New512_256()
	if _, err := io.WriteString(sum, secret); err != nil {
		panic(err)
	}
	return aesSafe{secret: sum.Sum(nil)}
}

type aesSafe struct {
	secret []byte
}

func (s aesSafe) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.secret)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm block: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("read rand: %w", err)
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (s aesSafe) Decrypt(data []byte) (Value, error) {
	block, err := aes.NewCipher(s.secret)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm block: %w", err)
	}
	size := gcm.NonceSize()
	nonce, ciphertext := data[:size], data[size:]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("open seal: %w", err)
	}
	return plain, nil
}

// Generate returns a random secret value of requested size in bytes.
func Generate(size int) Value {
	return generate(size)
}

var generate = func(size int) Value {
	b := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	return b
}

// WithDeterministicGenerate overwrites Generate function to returned fixed
// result until the end of the test.
//
// This function is replacing secure random generator with deterministic
// output.
//
// This function is not safe for concurrent use.
func WithDeterministicGenerate(t testing.TB, v Value) {
	original := generate
	generate = func(int) Value { return v }
	t.Cleanup(func() { generate = original })
}

// Value represents a secret value that must not be exposed.
type Value []byte

// Is returns true if two secrets are equal.
func (v Value) Is(other Value) bool {
	if len(v) == 0 || len(other) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare(v, other) == 1
}

// Forbid certain interface to avoid stupid mistakes.
func (Value) String() string               { return "-secret-" }
func (Value) GoString() string             { return "-secret-" }
func (Value) MarshalJSON() ([]byte, error) { return nil, errors.New("forbidden") }
func (Value) Scan(interface{}) error       { return errors.New("forbidden") }
func (Value) Value() (driver.Value, error) { return nil, errors.New("forbidden") }
