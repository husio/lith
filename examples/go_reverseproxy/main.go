package main

import (
	_ "embed"
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/husio/lith/lib/lith"
)

func main() {
	authUIFl := flag.String("auth-ui", "http://localhost:8002", "Address of the lith auth Public UI server.")
	authAPIFl := flag.String("auth-api", "http://localhost:8001", "Address of the lith auth API server.")
	prefixFl := flag.String("prefix", "/accounts/", "Reverse proxy Public UI under given prefix.")
	listenFl := flag.String("listen", "localhost:12345", "Address on which this server should listen.")
	flag.Parse()

	client := lith.NewClient(*authAPIFl, nil)
	withAuth := lith.AuthMiddleware(client)

	http.Handle("/", withAuth(index{prefix: *prefixFl}))
	http.Handle(*prefixFl, revproxy(*authUIFl))
	fmt.Println("running on", *listenFl)
	http.ListenAndServe(*listenFl, nil)
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
