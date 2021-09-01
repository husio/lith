package web_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/husio/lith/pkg/web"
)

func TestRouterPathArgs(t *testing.T) {
	rt := web.NewRouter()
	rt.Add(`GET /users/{company-name}/{user-id:\d+}`, func(w http.ResponseWriter, r *http.Request) {
		if name := web.PathArg(r, "company-name"); name != "megacorp" {
			t.Errorf("want megacorp company name, got %q", name)
		}
		if userID := web.PathArg(r, "user-id"); userID != "12345" {
			t.Errorf("want user ID 12345, got %q", userID)
		}
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/users/megacorp/12345", nil)
	rt.ServeHTTP(w, r)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("unexpected response: %+v", w.Result())
	}
}

func TestRouterMultipleMethods(t *testing.T) {
	rt := web.NewRouter()

	var handlerCalled int
	rt.Add(`GET,POST,PATCH /users/`, func(w http.ResponseWriter, r *http.Request) {
		handlerCalled++
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/users/", nil)
	rt.ServeHTTP(w, r)
	if handlerCalled != 1 {
		t.Fatalf("handler should be called once, called %d times", handlerCalled)
	}

	w = httptest.NewRecorder()
	r = httptest.NewRequest("PATCH", "/users/", nil)
	rt.ServeHTTP(w, r)
	if handlerCalled != 2 {
		t.Fatalf("handler should be called twice, called %d times", handlerCalled)
	}

	w = httptest.NewRecorder()
	r = httptest.NewRequest("DELETE", "/users/", nil)
	rt.ServeHTTP(w, r)
	if handlerCalled != 2 {
		t.Fatalf("handler should be called twice, called %d times", handlerCalled)
	}
}

func TestRouterUnknownPathArg(t *testing.T) {
	rt := web.NewRouter()
	rt.Add(`GET /users/{company-name}/{user-id:\d+} `, func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err == nil {
				t.Fatalf("PathArg must panic")
			}
		}()
		web.PathArg(r, "unknown-argument-name")
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/users/megacorp/12345", nil)
	rt.ServeHTTP(w, r)
}

func TestRouterNoPathArgsDefined(t *testing.T) {
	rt := web.NewRouter()
	rt.Add(`GET /users/`, func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err == nil {
				t.Fatalf("PathArg must panic")
			}
		}()
		web.PathArg(r, "unknown-argument-name")
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/users/", nil)
	rt.ServeHTTP(w, r)
}

func TestRouterPathMatchButNotMethod(t *testing.T) {
	rt := web.NewRouter()
	var methodNotAllowedCalled bool
	rt.MethodNotAllowed = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methodNotAllowedCalled = true
	})
	rt.Add(`POST /users/`, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("must not be called, got %+v", r)
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/users/", nil)
	rt.ServeHTTP(w, r)

	if !methodNotAllowedCalled {
		t.Fatal("method not allowed handler not called")
	}
}

func TestRouterNoPathMatch(t *testing.T) {
	rt := web.NewRouter()
	var notFoundCalled bool
	rt.NotFound = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		notFoundCalled = true
	})
	rt.Add(`GET,POST /users/`, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("must not be called, got %+v", r)
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/users/stuff", nil)
	rt.ServeHTTP(w, r)

	if !notFoundCalled {
		t.Fatal("not found handler not called")
	}
}

func TestRouterMiddleware(t *testing.T) {
	rt := web.NewRouter()
	rt.Use(
		writeMiddleware("a", "A"),
		writeMiddleware("b", "B"),
	)
	rt.Use(
		writeMiddleware("c", "C"),
		writeMiddleware("d", "D"),
	)

	rt.Add(`GET,POST /.*`, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "-x-")
	})
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	rt.ServeHTTP(w, r)
	if body, want := w.Body.String(), "cdab-x-BADC"; body != want {
		t.Fatalf("want %q, got %q", want, body)
	}
}

func writeMiddleware(beforeHandler, afterHandler string) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return bodyWriter{before: beforeHandler, after: afterHandler, next: h}
	}
}

type bodyWriter struct {
	next   http.Handler
	before string
	after  string
}

func (h bodyWriter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.before != "" {
		io.WriteString(w, h.before)
	}

	h.next.ServeHTTP(w, r)

	if h.after != "" {
		io.WriteString(w, h.after)
	}
}
