package cache_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/husio/lith/pkg/cache"
)

func TestStampedeCacheProtection(t *testing.T) {
	store := cache.StampedeProtect(cache.NewLocalMemCache(1e6))
	RunCacheImplementationTest(t, store)
}

func TestStampedeCacheProtectionMultipleReaders(t *testing.T) {
	ctx := context.Background()

	store := cache.StampedeProtect(cache.NewLocalMemCache(1e6))
	exp := 250 * time.Millisecond

	for iteration := 0; iteration < 3; iteration++ {
		var cacheHitCnt, computeCnt uint64

		var wg sync.WaitGroup
		start := make(chan struct{})

		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				<-start

				var value string
				if err := store.Get(ctx, "value-1", &value); err == nil {
					atomic.AddUint64(&cacheHitCnt, 1)
					if value != "whatever" {
						t.Errorf("want \"whatever\", got %q", value)
					}
				} else if errors.Is(err, cache.ErrMiss) {
					// Pretend there is some heavy computation happening.
					time.Sleep(10 * time.Millisecond)
					atomic.AddUint64(&computeCnt, 1)
					if err := store.Set(ctx, "value-1", "whatever", exp); err != nil {
						t.Errorf("cannot set: %s", err)
					}
				} else {
					t.Errorf("unexpected error: %s", err)
				}
			}()
		}

		close(start)
		wg.Wait()

		if cacheHitCnt != 99 {
			t.Errorf("want 99 cache hits, got %d", cacheHitCnt)
		}
		if computeCnt != 1 {
			t.Errorf("want 1 computations, got %d", computeCnt)
		}

		time.Sleep(exp)
	}
}
