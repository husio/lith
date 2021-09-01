package translation

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
)

// Renderer returns a renderer with translation functions attached.
func Renderer(
	root *template.Template,
	templatesFS embed.FS,
	templatesPattern string,
	trans *Translations,
) (*LangRenderer, error) {
	tmpl, err := root.Clone()
	if err != nil {
		return nil, fmt.Errorf("clone: %w", err)
	}
	tmpl, err = tmpl.Funcs(translationFns).ParseFS(templatesFS, templatesPattern)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	return &LangRenderer{
		trans: trans,
		tmpl:  tmpl,
	}, nil
}

// LangRenderer is a language aware template renderer.
type LangRenderer struct {
	trans *Translations
	tmpl  *template.Template
}

func (r *LangRenderer) RenderTo(w io.Writer, language string, templateName string, context interface{}) error {
	t := r.tmpl.Funcs(template.FuncMap{
		"translate": func(s string, args ...interface{}) string {
			// Best effort translation function.
			switch len(args) {
			default:
				return s
			case 0:
				return r.trans.Bind(language).T(s)
			case 2: // Two translations strings and the number.
				p, ok := args[0].(string)
				if !ok {
					return s
				}
				var i int
				switch n := args[1].(type) {
				case int:
					i = int(n)
				case int8:
					i = int(n)
				case int16:
					i = int(n)
				case int32:
					i = int(n)
				case int64:
					i = int(n)
				case uint:
					i = int(n)
				case uint8:
					i = int(n)
				case uint16:
					i = int(n)
				case uint32:
					i = int(n)
				case uint64:
					i = int(n)
				default:
					return s
				}
				return r.trans.Bind(language).Tn(s, p, i)
			}
		},
	})

	if err := t.ExecuteTemplate(w, templateName, context); err != nil {
		return fmt.Errorf("execute: %w", err)
	}
	return nil
}

// Render writes an HTML response.
func (r *LangRenderer) Render(w http.ResponseWriter, code int, templateName string, context interface{}) {
	// Requires LanguageMiddleware to be used.
	lang := w.Header().Get("content-language")

	// TODO use buffer pool
	var b bytes.Buffer
	if err := r.RenderTo(&b, lang, templateName, context); err != nil {
		// Logger cannot be accessed here, so write directly to stderr,
		// since this should be captured during local development.
		fmt.Fprintf(os.Stderr, "+++ cannot render template %q +++\n\t%s\n", templateName, err)

		http.Error(w, "Internal Server Error.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "text/html; charset=UTF-8")
	w.WriteHeader(code)
	_, _ = b.WriteTo(w)
}

// translationFns contains placeholder for request dependant functionality, so
// that templates can compile.
var translationFns = template.FuncMap{
	"translate": func(s string, args ...interface{}) string { return s },
}
