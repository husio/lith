package totp_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/husio/lith/pkg/cache"
	"github.com/husio/lith/pkg/secret"
	"github.com/husio/lith/pkg/totp"
)

func TestTOTP(t *testing.T) {
	now := time.Now()
	s := secret.Generate(16)

	if a, b := totp.Generate(now, s), totp.Generate(now, s); a != b {
		t.Fatal("the same time and secret must produce the same code")
	}

	code := totp.Generate(now, s)

	t.Run("time sensitive validation", func(t *testing.T) {
		totp.WithCurrentTime(t, now)
		if err := totp.Validate(context.Background(), cache.NewLocalMemCache(1e5), code, s); err != nil {
			t.Fatalf("generated right now code must be valid, got %v", err)
		}
		totp.WithCurrentTime(t, now.Add(25*time.Second))
		if err := totp.Validate(context.Background(), cache.NewLocalMemCache(1e5), code, s); err != nil {
			t.Fatalf("generated less than 30 seconds ago code must be still valid, got %v", err)
		}

		totp.WithCurrentTime(t, now.Add(61*time.Second))
		if err := totp.Validate(context.Background(), cache.NewLocalMemCache(1e5), code, s); !errors.Is(err, totp.ErrInvalid) {
			t.Fatalf("generated more than 60 seconds ago code must no be valid, got %v", err)
		}
	})

	c := cache.NewLocalMemCache(1e5)
	if err := totp.Validate(context.Background(), c, code, s); err != nil {
		t.Fatalf("generated code must be valid, got %v", err)
	}
	if err := totp.Validate(context.Background(), c, code, s); !errors.Is(err, totp.ErrUsed) {
		t.Fatalf("using the same code twice must fail, got %v", err)
	}
}
