package main

import (
	_ "embed"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/husio/lith/lib/lith"
)

func main() {
	authUIFl := flag.String("auth-ui", env("UI_URL", "http://lith:8002"), "Address of the lith auth Public UI server.")
	authAPIFl := flag.String("auth-api", env("API_URL", "http://lith:8001"), "Address of the lith auth API server.")
	prefixFl := flag.String("prefix", env("PREFIX", "/accounts/"), "Reverse proxy Public UI under given prefix.")
	listenFl := flag.String("listen", env("LISTEN", "0.0.0.0:8000"), "Address on which this server should listen.")
	flag.Parse()

	client := lith.NewClient(*authAPIFl, &http.Client{Transport: requestLogger{}})
	withAuth := lith.AuthMiddleware(client)

	http.Handle("/", withAuth(index{prefix: *prefixFl}))
	http.Handle(*prefixFl, revproxy(*authUIFl))
	fmt.Println("running on", *listenFl)
	http.ListenAndServe(*listenFl, nil)
}

type requestLogger struct{}

func (requestLogger) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		log.Printf("request to %q results in error %s", req.URL, err)
	} else {
		log.Printf("request to %q results in status code %d", req.URL, resp.StatusCode)
	}
	return resp, err
}

func env(name, fallback string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return fallback
}

func revproxy(dest string) http.Handler {
	u, err := url.Parse(dest)
	if err != nil {
		panic(err)
	}
	return httputil.NewSingleHostReverseProxy(u)
}

var (
	//go:embed template.html
	templateHTML string
	tmpl         = template.Must(template.New("").Parse(templateHTML))
)

type index struct {
	prefix string
}

func (h index) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	account, _ := lith.CurrentAccount(r.Context())
	tmpl.Execute(w, struct {
		Account *lith.AccountSession
		Prefix  string
	}{
		Account: account,
		Prefix:  h.prefix,
	})
}
