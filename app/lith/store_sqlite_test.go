package lith

import (
	"os"
	"testing"

	"github.com/husio/lith/pkg/secret"
)

func TestSQLiteStore(t *testing.T) {
	testStoreImplementation(t, func() Store { return newTestSQLiteStore(t) })
}

func newTestSQLiteStore(t testing.TB) Store {
	// Allow to introspect database by switching into a file for storage.
	dbpath := os.Getenv("TEST_DATABASE")
	if dbpath == "" {
		dbpath = ":memory:?_mode=memory&_fk=on&_txlock=immediate"
	}
	store, err := OpenSQLiteStore(dbpath, secret.AESSafe("t0p-secret-value"))
	if err != nil {
		t.Fatalf("open new sqlite store: %s", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}
