package lith

import (
	"context"
	"embed"
	"html/template"

	"github.com/husio/lith/pkg/translation"
)

// A global variable combining all translations, because they are all embeded.
// How awesome!
var translations *translation.Translations

//go:embed po/*
var translationsFs embed.FS

// A global variable combining all templates, because they are all embeded.
// How awesome!
var tmpl *translation.LangRenderer

//go:embed templates/*.html
var templatesFS embed.FS

func init() {
	t, err := translation.Load(translationsFs, "po/*.po")
	if err != nil {
		panic(err)
	}
	translations = t

	rend, err := translation.Renderer(
		template.New(""),
		templatesFS, "templates/*.html",
		translations,
	)
	if err != nil {
		panic(err)
	}
	tmpl = rend
}

// transFor is a shortcut that returns translation bound to language of the
// current user context. User is determined from the context and rellies on the
// translation.LanguageMiddleware to be called before.
func transFor(ctx context.Context) *translation.Locale {
	return translations.Bind(translation.Language(ctx))
}
