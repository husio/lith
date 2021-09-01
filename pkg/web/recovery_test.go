package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/husio/lith/pkg/alert"
)

func TestRecovery(t *testing.T) {
	app := NewRouter()
	app.Add(`GET /.*`, panicingHandler{})
	app.Use(RecoverMiddleware())

	var c collector
	ctx := alert.WithEmitter(context.Background(), &c)

	r := httptest.NewRequest("GET", "/", nil)
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	app.ServeHTTP(w, r)

	if len(c.history) != 1 {
		t.Logf("%+v", c.history)
		t.Fatalf("want one alert entry, got %d", len(c.history))
	}
	got := c.history[0]
	want := []string{
		"msg", "HTTP handler panic recovered.",
		"err", "runtime error: invalid memory address or nil pointer dereference",
		"stack", "-- stack trace, not tested --",
	}

	if !reflect.DeepEqual(want[:len(want)-1], got[:len(want)-1]) {
		t.Logf("want: %q", want[:len(want)-1])
		t.Logf(" got: %q", got[:len(got)-1])
		t.Fatal("unexpecter alert format")
	}
}

type panicingHandler struct{}

func (panicingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Panic one call deeper.
	fire()
}

func fire() {
	var n *int
	*n++
}

type collector struct {
	history [][]string
}

func (c *collector) Emit(pairs ...string) {
	c.history = append(c.history, pairs)
}
