package totp

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/husio/lith/pkg/cache"
	"github.com/husio/lith/pkg/secret"
)

// Validate returns no error if given code is currently a valid TOTP code for
// given secret. Each code must be used only once - cache is used to mark code
// as used and prevent further validation.
//
// A code is valid for 1 minute, meaning the current time span and the previous
// one are both accepted.
func Validate(ctx context.Context, c cache.Store, code string, secret secret.Value) error {
	now := currentTime()
	current := Generate(now, secret)
	if code != current {
		previous := Generate(now.Add(-30*time.Second), secret)
		if code != previous {
			return ErrInvalid
		}
	}
	// Hash secret so that it is not stored in cache in plain text.
	key := fmt.Sprintf("totp:%x:%s", sha1.Sum(secret), code)
	switch err := c.SetNx(ctx, key, 1, 2*time.Minute); {
	case err == nil:
		return nil
	case errors.Is(err, cache.ErrConflict):
		return ErrUsed
	default:
		return fmt.Errorf("cache: %w", err)
	}
}

var (
	// ErrInvalid is returned when an invalid TOTP code is validated.
	ErrInvalid = errors.New("invalid")
	// ErrUsed is returned when a valid TOTP is validated second time.
	ErrUsed = errors.New("used")
)

// currentTime is a variable so that it can be overwritten in tests.
var currentTime = func() time.Time {
	return time.Now().UTC().Truncate(time.Second)
}

// WithCurrentTime is changing this package time perception to a fixed value.
// Calling this function alters this package "now" time until the end of the
// test.
// This function is not safe for concurent use as it is affecting package's
// global state.
func WithCurrentTime(t testing.TB, now time.Time) {
	original := currentTime
	currentTime = func() time.Time { return now }
	t.Cleanup(func() { currentTime = original })
}

// Generate returns a 6 digit representation of the TOTP code using 30 seconds
// time interval. Secret must be in raw format (i.e. not base32 encoded).
func Generate(now time.Time, secret []byte) string {
	counter := uint64(math.Floor(float64(now.Unix()) / 30))
	bc := make([]byte, 8)
	binary.BigEndian.PutUint64(bc, counter)

	hash := hmac.New(sha1.New, secret)
	_, _ = hash.Write(bc)
	res := hash.Sum(nil)

	// "Dynamic truncation" in RFC 4226
	// http://tools.ietf.org/html/rfc4226#section-5.4
	offset := res[len(res)-1] & 0xf
	value := int64(((int(res[offset]) & 0x7f) << 24) |
		((int(res[offset+1] & 0xff)) << 16) |
		((int(res[offset+2] & 0xff)) << 8) |
		(int(res[offset+3]) & 0xff))

	mod := int32(value % int64(math.Pow10(digits)))
	return fmt.Sprintf("%06d", mod)
}

// URI returns TOTP representation as URI.
// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
func URI(issuer, account string, secret []byte) string {
	params := make(url.Values)
	params.Set("secret", base32.StdEncoding.EncodeToString(secret))
	params.Set("digits", strconv.Itoa(digits))
	params.Set("algorithm", "SHA1")
	params.Set("issuer", issuer)
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + params.Encode()
}

// 6 digits is the most common configuration.
const digits = 6
