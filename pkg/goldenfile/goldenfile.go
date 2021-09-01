package goldenfile

import (
	"bytes"
	"flag"
	"os"
	"regexp"
	"strings"
	"testing"
)

var updateGoldenFl = flag.Bool("updategolden", false, "If true, each golden file content is updated with given value before comparing.")

func Validate(t testing.TB, fileSuffix string, data interface{}) {
	t.Helper()

	var repr []byte

	switch v := data.(type) {
	case []byte:
		repr = v
	case string:
		repr = []byte(v)
	default:
		t.Fatalf("not implemented for data type %T", data)
	}

	if fileSuffix != "" {
		fileSuffix = "_" + fileSuffix
	}
	goldenPath := toGoldenPath(t.Name() + fileSuffix)

	if *updateGoldenFl {
		_ = os.MkdirAll("testdata/", 0777)
		if err := os.WriteFile(goldenPath, repr, 0644); err != nil {
			t.Fatalf("cannot write %q golden file: %s", goldenPath, err)
		}
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("cannot read %q golden file: %s", goldenPath, err)
	}

	if bytes.Equal(repr, want) {
		return
	}

	// A difflib would be awesome.
	t.Logf("want: %s\n", string(want))
	t.Logf(" got: %s\n", string(repr))
	t.Fatalf("Golden file content differs from given value: %q", goldenPath)
}

func toGoldenPath(s string) string {
	path := regexp.MustCompile(`[^a-zA-Z0-9_]+`).ReplaceAllString(s, "_")
	path = regexp.MustCompile(`_+`).ReplaceAllString(path, "_")
	path = strings.Trim(path, "_")
	return "testdata/" + path + ".golden"
}
