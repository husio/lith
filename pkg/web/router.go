package web

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

type Router struct {
	routes      []routeHandler
	handler     http.Handler
	middlewares []func(http.Handler) http.Handler

	MethodNotAllowed http.Handler
	NotFound         http.Handler
}

func NewRouter() *Router {
	rt := &Router{
		MethodNotAllowed: stdResponseHandler{code: http.StatusMethodNotAllowed},
		NotFound:         stdResponseHandler{code: http.StatusNotFound},
	}
	rt.handler = routerHandler{rt: rt}
	return rt
}

type routerHandler struct {
	rt *Router
}

func (h routerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var pathMatch bool

	for _, route := range h.rt.routes {
		if !route.rx.MatchString(r.URL.Path) {
			continue
		}
		pathMatch = true
		for _, m := range route.methods {
			if m == r.Method {
				// Only if any names were used, bother to parse once more.
				if len(route.argNames) != 0 {
					values := route.rx.FindAllStringSubmatch(r.URL.Path, -1)[0][1:]
					ctx := WithPathArg(r.Context(), route.argNames, values)
					r = r.WithContext(ctx)
				}
				route.hn.ServeHTTP(w, r)
				return
			}
		}
	}

	if pathMatch {
		h.rt.MethodNotAllowed.ServeHTTP(w, r)
	} else {
		h.rt.NotFound.ServeHTTP(w, r)
	}
}

type stdResponseHandler struct{ code int }

func (h stdResponseHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(h.code)
}

type routeHandler struct {
	rx       *regexp.Regexp
	methods  []string
	argNames []string
	hn       http.Handler
}

// Use registers middlewares to be used for all endpoints. Middlewares are
// executed in order they are provided.
// If Use is called multiple times, middlewares are added in the following
// order:
//   router.Add(A, B, C)
//   router.Add(D, E, F)
//
//   Request >> D E F A B C >> handler >> C B A F E D >>
func (rt *Router) Use(middlewares ...func(http.Handler) http.Handler) {
	for i := len(middlewares) - 1; i >= 0; i-- {
		m := middlewares[i]
		rt.handler = m(rt.handler)
	}
}

func (rt *Router) Add(routeConf string, handler interface{}) {
	var hn http.Handler

	switch h := handler.(type) {
	case http.Handler:
		hn = h
	case http.HandlerFunc:
		hn = h
	case func(w http.ResponseWriter, r *http.Request):
		hn = http.HandlerFunc(h)
	default:
		panic("unknown handler interface for " + routeConf)
	}

	conf := strings.Fields(routeConf)
	if len(conf) != 2 {
		panic("Invalid route configuration format: " + routeConf)

	}
	methods := strings.Split(conf[0], ",")
	urlPath := conf[1]
	if len(urlPath) == 0 || urlPath[0] != '/' {
		panic("Invalid path regexp for " + routeConf + ". A path must start with /")
	}

	var argNames []string
	raw := regexp.MustCompile(`{.*?}`).ReplaceAllStringFunc(urlPath, func(s string) string {
		s = s[1 : len(s)-1]
		// every matching must be a named regexp match
		// definition using notation {<name>:<regexp>}
		// Only {<name>} is also allowed to match until next /
		chunks := strings.SplitN(s, ":", 2)
		if len(chunks) == 1 {
			chunks = append(chunks, `[^/]+`)
		}
		argNames = append(argNames, chunks[0])
		return `(` + chunks[1] + `)`
	})
	// replace {} with regular expressions syntax
	pathRx, err := regexp.Compile(`^` + raw + `$`)
	if err != nil {
		panic(fmt.Sprintf("invalid routing path %s: %s", urlPath, err))
	}

	rt.routes = append(rt.routes, routeHandler{
		rx:       pathRx,
		methods:  methods,
		argNames: argNames,
		hn:       hn,
	})
}

func (rt Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rt.handler.ServeHTTP(w, r)
}

func WithPathArg(ctx context.Context, names []string, values []string) context.Context {
	if len(names) != len(values) {
		panic("Number of names and values must be the same.")
	}
	if len(names) == 0 {
		return ctx
	}
	return context.WithValue(ctx, pathArgContextKey, namedvalues{
		names:  names,
		values: values,
	})
}

type namedvalues struct {
	names  []string
	values []string
}

// PathArg returns the string representation of a named match, extracted from
// the URL path.
//
// This function panics if used for a arg name that is not defined for that
// route.
func PathArg(r *http.Request, name string) string {
	nv, ok := r.Context().Value(pathArgContextKey).(namedvalues)
	if !ok {
		panic("No path arguments defined in " + name)
	}
	for i, n := range nv.names {
		if name == n {
			return nv.values[i]
		}
	}
	panic("Path argument " + name + " not defined in in " + name)
}

type contextKey int

const (
	pathArgContextKey contextKey = iota
)
