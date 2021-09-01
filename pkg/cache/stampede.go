package cache

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"time"
)

// StampedeProtect wraps any cache storage with additional layer preventing
// from stempede.
func StampedeProtect(s Store) Store {
	return &stampedeProtected{
		store:           s,
		computationLock: 2 * time.Second,
	}
}

type stampedeProtected struct {
	store           Store
	computationLock time.Duration
}

func (s *stampedeProtected) Get(ctx context.Context, key string, dest interface{}) error {
	var it stampedeProtectedItem

readProtectedItem:
	for {
		switch err := s.store.Get(ctx, key, &it); err {
		case nil:
			// All good.
			break readProtectedItem
		case ErrMiss:
			// Acquire lock for a short period to avoid multiple
			// clients computing the same task. If we get the lock,
			// return cache miss - we are allowed to recompute. If
			// we don't get the lock, wait and retry until value is
			// in cache again.
			if s.store.SetNx(ctx, key+":stampedelock", 1, s.computationLock) == nil {
				return ErrMiss
			}
			time.Sleep(25 * time.Millisecond)
		default:
			return err
		}
	}

	if it.refreshAt.Before(time.Now()) {
		// Acquire task computation lock. If we get it, return
		// cache miss so that the client will recompute the
		// result. Otherwise return cached value - cached value
		// is still valid and another client is already
		// recomputing the task.
		if s.store.SetNx(ctx, key+":stampedelock", 1, s.computationLock) == nil {
			return ErrMiss
		}
	}

	if err := unmarshal(it.value, dest); err != nil {
		return fmt.Errorf("cannot unmarshal: %w", err)
	}
	return nil
}

func (s *stampedeProtected) Set(ctx context.Context, key string, value interface{}, exp time.Duration) error {
	rawValue, err := marshal(value)
	if err != nil {
		return err
	}

	it := stampedeProtectedItem{
		refreshAt: time.Now().Add(exp).Add(-refreshMargin(exp)),
		value:     rawValue,
	}
	return s.store.Set(ctx, key, &it, exp)
}

func (s *stampedeProtected) SetNx(ctx context.Context, key string, value interface{}, exp time.Duration) error {
	rawValue, err := marshal(value)
	if err != nil {
		return err
	}

	it := stampedeProtectedItem{
		refreshAt: time.Now().Add(exp).Add(-refreshMargin(exp)),
		value:     rawValue,
	}
	return s.store.SetNx(ctx, key, &it, exp)
}

func refreshMargin(exp time.Duration) time.Duration {
	if exp > 10*time.Minute {
		return time.Minute
	}
	if exp > time.Minute {
		return 10 * time.Second
	}
	if exp > 30*time.Second {
		return 3 * time.Second
	}
	if exp > 10*time.Second {
		return time.Second
	}
	if exp > 5*time.Second {
		return 500 * time.Millisecond
	}
	return 0
}

func (s *stampedeProtected) Del(ctx context.Context, key string) error {
	return s.store.Del(ctx, key)
}

type stampedeProtectedItem struct {
	refreshAt time.Time
	value     []byte
}

func (it stampedeProtectedItem) CacheSerialize() ([]byte, error) {
	raw := fmt.Sprintf("%d\n%s", it.refreshAt.UnixNano(), it.value)
	return []byte(raw), nil
}

func (it *stampedeProtectedItem) CacheDeserialize(raw []byte) error {
	chunks := bytes.SplitN(raw, []byte{'\n'}, 2)
	if len(chunks) != 2 {
		return fmt.Errorf("%w: invalid format: %s", ErrMalformed, raw)
	}
	unixNano, err := strconv.ParseInt(string(chunks[0]), 10, 64)
	if err != nil {
		return fmt.Errorf("%w: invalid expiration format: %s", ErrMalformed, err)
	}
	it.refreshAt = time.Unix(0, unixNano)
	it.value = chunks[1]
	return nil
}
