package cache_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/husio/lith/pkg/cache"
)

func TestLocalMemoryCache(t *testing.T) {
	cache := cache.NewLocalMemCache(1e6)

	RunCacheImplementationTest(t, cache)
}

func TestLocalMemoryCacheMaxSize(t *testing.T) {
	ctx := context.Background()

	c := cache.NewLocalMemCache(10)
	if err := c.Set(ctx, "a", "aaa", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := c.Set(ctx, "b", "bbb", time.Hour); err != nil {
		t.Fatal(err)
	}

	var s string
	if err := c.Get(ctx, "a", &s); err != nil {
		t.Fatal(err)
	} else if s != "aaa" {
		t.Fatalf("want 'aaa', got %q", s)
	}

	if err := c.Get(ctx, "b", &s); err != nil {
		t.Fatal(err)
	} else if s != "bbb" {
		t.Fatalf("want 'bbb', got %q", s)
	}

	// Adding "c" key must evict "a" key.
	if err := c.Set(ctx, "c", "ccc", time.Hour); err != nil {
		t.Fatal(err)
	}

	if err := c.Get(ctx, "a", &s); !errors.Is(err, cache.ErrMiss) {
		t.Fatalf("want ErrMiss, got %+v", err)
	}
	if err := c.Get(ctx, "b", &s); err != nil {
		t.Fatal(err)
	} else if s != "bbb" {
		t.Fatalf("want 'bbb', got %q", s)
	}
	if err := c.Get(ctx, "c", &s); err != nil {
		t.Fatal(err)
	} else if s != "ccc" {
		t.Fatalf("want 'ccc', got %q", s)
	}

	// Adding "d" key must evict all other entries.
	if err := c.Set(ctx, "d", "ddddddd", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, "a", &s); !errors.Is(err, cache.ErrMiss) {
		t.Fatalf("want ErrMiss, got %+v", err)
	}
	if err := c.Get(ctx, "b", &s); !errors.Is(err, cache.ErrMiss) {
		t.Fatalf("want ErrMiss, got %+v", err)
	}
	if err := c.Get(ctx, "c", &s); !errors.Is(err, cache.ErrMiss) {
		t.Fatalf("want ErrMiss, got %+v", err)
	}
	if err := c.Get(ctx, "d", &s); err != nil {
		t.Fatal(err)
	} else if s != "ddddddd" {
		t.Fatalf("want 'ddddddd', got %q", s)
	}
}
