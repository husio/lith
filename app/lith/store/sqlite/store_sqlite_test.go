package sqlite

import (
	"os"
	"testing"
	"time"

	"github.com/husio/lith/app/lith"
	"github.com/husio/lith/pkg/secret"
)

func TestSQLiteStore(t *testing.T) {
	lith.RunTestStoreImplementation(t, func(now func() time.Time, newID func() string) lith.Store {
		return newStore(t, now, newID)
	})
}

func newStore(
	t testing.TB,
	now func() time.Time,
	newID func() string,
) lith.Store {
	// Allow to introspect database by switching into a file for storage.
	dbpath := os.Getenv("TEST_DATABASE")
	if dbpath == "" {
		dbpath = ":memory:?_mode=memory&_fk=on&_txlock=immediate"
	}
	store, err := OpenStore(dbpath, secret.AESSafe("t0p-secret-value"))
	if err != nil {
		t.Fatalf("open new sqlite store: %s", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}
