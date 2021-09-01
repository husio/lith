package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Store is implemented by any backend that provides cache functionality.
type Store interface {
	// Get value stored under given key. Returns ErrMiss if key is not
	// used.
	Get(ctx context.Context, key string, dest interface{}) error

	// Set value under given key. If key is already in use, overwrite it's
	// value with given one and set new expiration time.
	Set(ctx context.Context, key string, value interface{}, exp time.Duration) error

	// SetNx set value under given key only if key is not used. It returns
	// ErrConflict if trying to set value for key that is already in use.
	SetNx(ctx context.Context, key string, value interface{}, exp time.Duration) error

	// Del deletes value under given key. It returns ErrCacheMiss if given
	// key is not used.
	Del(ctx context.Context, key string) error
}

var (
	// ErrCache is a generic, root level error of all cache errors.
	ErrCache = errors.New("cache")

	// ErrMiss is returned when performing operation on key is not in use.
	// This is a not found error narrowed to cache cases only.
	ErrMiss = fmt.Errorf("%w miss", ErrCache)

	// ErrMalformed is returned whenever an operation cannot be
	// completed because value cannot be serialized or deserialized.
	ErrMalformed = fmt.Errorf("malformed %w", ErrCache)

	// ErrConflict is returned when an operation cannot be completed
	// because of otherwise conflicting state.
	ErrConflict = fmt.Errorf("%w conflict", ErrCache)
)

func marshal(value interface{}) ([]byte, error) {
	if m, ok := value.(Serializable); ok {
		return m.CacheSerialize()
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrMalformed, err)
	}
	return raw, nil

}

func unmarshal(raw []byte, dest interface{}) error {
	if m, ok := dest.(Serializable); ok {
		return m.CacheDeserialize(raw)
	}
	if err := json.Unmarshal(raw, dest); err != nil {
		return fmt.Errorf("%w: %s", ErrMalformed, err)
	}
	return nil
}

// Serializable interface is implemented by any value that should provide a
// custom way for serialization and deserialization when interacting with cache
// raw byte storage.
type Serializable interface {
	CacheSerialize() ([]byte, error)
	CacheDeserialize([]byte) error
}
