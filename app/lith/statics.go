package lith

import (
	"embed"
	"io/fs"
)

//go:embed statics/*
var staticsFS embed.FS

func publicStaticsFS() fs.FS {
	fs, err := fs.Sub(staticsFS, "statics/public")
	if err != nil {
		panic(err)
	}
	return fs
}

func adminStaticsFS() fs.FS {
	fs, err := fs.Sub(staticsFS, "statics/admin")
	if err != nil {
		panic(err)
	}
	return fs
}
