package translation

import (
	"bytes"
	"embed"
	"io"
	"strings"
	"testing"
)

var (
	//go:embed testdata/page.html
	pageFS embed.FS

	//go:embed testdata/page.html
	pageHTML string

	//go:embed testdata/main.go
	mainGo string

	//go:embed testdata/po/*.po
	translationFS embed.FS
)

func TestParseHTML(t *testing.T) {
	rd := PoFromHTML("page.html", strings.NewReader(pageHTML))
	b, err := io.ReadAll(rd)
	if err != nil {
		t.Fatalf("read PO: %s", err)
	}

	lang, _, msgs, err := parsePO(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("parse PO: %s", err)
	}
	if lang != "en" {
		t.Fatalf("expected en language, got %q", lang)
	}

	if n := len(msgs); n != 3 {
		t.Log(string(b))
		t.Fatalf("expected 3 messages, found %d", n)
	}

	b2, err := io.ReadAll(createPo(msgs))
	if err != nil {
		t.Fatalf("read PO: %s", err)
	}

	if !bytes.Equal(b, b2) {
		t.Logf(" first: %s", string(b))
		t.Logf("second: %s", string(b2))
		t.Error("PO file malformed during tranlation")
	}
}

func TestParseGo(t *testing.T) {
	rd := PoFromGo("main.html", strings.NewReader(mainGo))
	b, err := io.ReadAll(rd)
	if err != nil {
		t.Fatalf("read PO: %s", err)
	}

	lang, _, msgs, err := parsePO(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("parse PO: %s", err)
	}
	if lang != "en" {
		t.Fatalf("expected en language, got %q", lang)
	}

	if n := len(msgs); n != 2 {
		t.Log(string(b))
		t.Fatalf("expected 2 messages, found %d", n)
	}

	b2, err := io.ReadAll(createPo(msgs))
	if err != nil {
		t.Fatalf("read PO: %s", err)
	}

	if !bytes.Equal(b, b2) {
		t.Logf(" first: %s", string(b))
		t.Logf("second: %s", string(b2))
		t.Error("PO file malformed during tranlation")
	}
}

func TestTranslateT(t *testing.T) {
	translations, err := Load(translationFS, "testdata/po/*.po")
	if err != nil {
		t.Fatalf("cannot load translation PO files: %s", err)
	}
	pl := translations.Bind("pl")

	if got := pl.T("Good morning"); got != "Dzień dobry" {
		t.Errorf("unexpected greeting translation: %q", got)
	}

	messages := []string{
		0: "0 butelek piwa",
		1: "1 butelka piwa",
		2: "2 butelki piwa",
		3: "3 butelki piwa",
		4: "4 butelki piwa",
		5: "5 butelek piwa",
	}
	for i, want := range messages {
		got := pl.Tn("%d bottle of beer", "%d bottles of beer", i)
		if got != want {
			t.Errorf("for %d: want %q, got %q", i, want, got)
		}
	}
}
