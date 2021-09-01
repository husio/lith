package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/husio/lith/pkg/translation"
)

func main() {
	if err := run(); err != nil {
		os.Exit(1)
		fmt.Fprintln(os.Stderr, err)
	}
}

func run() error {
	dirFl := flag.String("dir", ".", "Directory to scan for translations.")
	outFl := flag.String("o", "", "Output POT file path. Stdout if not set.")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	var pofiles []io.Reader

	filepath.Walk(*dirFl, func(filename string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		switch filepath.Ext(filename) {
		case ".html":
			body, err := readHTML(filename)
			if err != nil {
				return fmt.Errorf("read %q file: %w", filename, err)
			}
			pofiles = append(pofiles, bytes.NewReader(body))
		case ".go":
			body, err := readGo(filename)
			if err != nil {
				return fmt.Errorf("read %q file: %w", filename, err)
			}
			pofiles = append(pofiles, bytes.NewReader(body))
		}
		return nil
	})

	all := translation.MergePoFiles(pofiles...)

	var out io.Writer
	if *outFl == "" {
		out = os.Stdout
	} else {
		fd, err := os.OpenFile(*outFl, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("cannot open %q output file: %w", *outFl, err)
		}
		defer fd.Close()
		out = fd
	}

	if _, err := io.Copy(out, all); err != nil {
		return fmt.Errorf("write to output file: %w", err)
	}
	return nil
}

func readHTML(filename string) ([]byte, error) {
	fd, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer fd.Close()

	data, err := io.ReadAll(translation.PoFromHTML(filename, fd))
	if err != nil {
		return nil, fmt.Errorf("generate PO: %w", err)
	}
	return data, nil
}

func readGo(filename string) ([]byte, error) {
	fd, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer fd.Close()

	data, err := io.ReadAll(translation.PoFromGo(filename, fd))
	if err != nil {
		return nil, fmt.Errorf("generate PO: %w", err)
	}
	return data, nil
}
