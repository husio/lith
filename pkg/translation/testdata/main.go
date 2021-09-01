package main

import (
	"embed"
	"fmt"
	"os"

	"github.com/husio/lith/pkg/translation"
)

//go:embed po/*.po
var translationsFS embed.FS

func main() {
	translator, err := translation.Load(translationsFS, "po/*.po")
	if err != nil {
		panic(err)
	}

	lang := "en"
	if v := os.Getenv("LANG"); v != "" {
		lang = v
	}

	fmt.Println("LANG = ", lang)
	trans := translator.Bind(lang)
	fmt.Printf("translator: %+v\n", trans)
	fmt.Println(trans.T("Good morning"))

	for i := 0; i < 10; i++ {
		fmt.Println(trans.Tn("%d bottle of beer", "%d bottles of beer", i))
	}
}
