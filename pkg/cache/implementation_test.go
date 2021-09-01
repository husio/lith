package cache_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/husio/lith/pkg/cache"
)

func RunCacheImplementationTest(t *testing.T, c cache.Store) {
	t.Helper()
	ctx := context.Background()

	testCacheSimpleItemSerialization(ctx, t, c)
	testCacheOperations(ctx, t, c)
}

func testCacheOperations(ctx context.Context, t *testing.T, c cache.Store) {
	// ensure basic operations are correct
	if err := c.Set(ctx, "key-1", "abc", time.Second); err != nil {
		t.Fatalf("cannot set: %s", err)
	}
	var val string
	if err := c.Get(ctx, "key-1", &val); err != nil {
		t.Fatalf("cannot get: %s", err)
	} else if val != "abc" {
		t.Fatalf("want abc value, got %q", val)
	}
	if err := c.SetNx(ctx, "key-1", "ABC", 10*time.Second); !errors.Is(err, cache.ErrConflict) {
		t.Fatalf("want ErrConflict, got %+v", err)
	}
	if err := c.Get(ctx, "key-1", &val); err != nil {
		t.Fatalf("cannot get: %s", err)
	} else if val != "abc" {
		t.Fatalf("want abc value, got %q", val)
	}

	// wait for the value to expire and ensure it's gone
	if err := c.Set(ctx, "key-exp", "abc", time.Second); err != nil {
		t.Fatalf("cannot set: %s", err)
	}
	time.Sleep(time.Second + 20*time.Millisecond)
	val = ""
	if err := c.Get(ctx, "key-exp", &val); !errors.Is(err, cache.ErrMiss) {
		t.Fatalf("want ErrMiss, got: %+v (%q)", err, val)
	}

	// deleting a key works
	if err := c.Set(ctx, "key-2", "123", time.Hour); err != nil {
		t.Fatalf("Cannot set: %s", err)
	}
	if err := c.Del(ctx, "key-2"); err != nil {
		t.Fatalf("cannot delete: %s", err)
	}
	if err := c.Get(ctx, "key-2", &val); !errors.Is(err, cache.ErrMiss) {
		t.Fatalf("want ErrMiss, got: %+v (%q)", err, val)
	}
	if err := c.Del(ctx, "key-does-not-exists"); !errors.Is(err, cache.ErrMiss) {
		t.Fatalf("want ErrMiss, got %+v", err)
	}

	// ensure very long keys are supported
	veryLongKey := strings.Repeat("very-long-key", 1000)
	if err := c.Set(ctx, veryLongKey, "123", time.Hour); err != nil {
		t.Fatalf("cannot set: %s", err)
	}
	val = ""
	if err := c.Get(ctx, veryLongKey, &val); err != nil || val != "123" {
		t.Fatalf("want 123, got %+v, %q", err, val)
	}
}

func testCacheSimpleItemSerialization(ctx context.Context, t *testing.T, c cache.Store) {
	item := testCacheItem{A: "foo", B: 42}

	if err := c.Set(ctx, t.Name(), &item, time.Minute); err != nil {
		t.Fatalf("cannot set item: %s", err)
	}

	var res testCacheItem
	if err := c.Get(ctx, t.Name(), &res); err != nil {
		t.Fatalf("cannot get item: %s", err)
	} else if !reflect.DeepEqual(item, res) {
		t.Fatalf("want %#v value, got %#v", item, res)
	}
}

type testCacheItem struct {
	A string
	B int
}
