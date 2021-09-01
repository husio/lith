package translation

import (
	"bytes"
	"embed"
	"html/template"
	"testing"

	"github.com/husio/lith/pkg/goldenfile"
)

var (
	//go:embed testdata/*.html
	templatesFS embed.FS
)

func TestTemplateRenderer(t *testing.T) {
	translations, err := Load(translationFS, "testdata/po/*.po")
	if err != nil {
		t.Fatalf("cannot load translation PO files: %s", err)
	}

	templateContext := struct {
		Name  string
		Items uint
	}{
		Name:  "Jimmy",
		Items: 5,
	}

	tmpl, err := Renderer(template.New(""), templatesFS, "testdata/*.html", translations)
	if err != nil {
		t.Fatalf("cannot create a renderer: %s", err)
	}
	var b bytes.Buffer
	if err := tmpl.RenderTo(&b, "pl", "page.html", templateContext); err != nil {
		t.Fatalf("cannot render page: %s", err)
	}
	goldenfile.Validate(t, "lang-pl", b.String())

	b.Reset()
	if err := tmpl.RenderTo(&b, "de", "page.html", templateContext); err != nil {
		t.Fatalf("cannot render page: %s", err)
	}
	goldenfile.Validate(t, "lang-de", b.String())

	b.Reset()
	if err := tmpl.RenderTo(&b, "en", "page.html", templateContext); err != nil {
		t.Fatalf("cannot render page: %s", err)
	}
	goldenfile.Validate(t, "lang-en", b.String())
}
