package validation

import (
	"encoding/json"
	"testing"
)

func TestValidation(t *testing.T) {
	var e Errors

	if raw, err := json.Marshal(e); err != nil {
		t.Errorf("cannot marshal: %s", err)
	} else if got, want := string(raw), `{"validation":{}}`; got != want {
		t.Errorf("want %q, got %q", want, got)
	}

	e.Add("foo", "bar")
	if raw, err := json.Marshal(e); err != nil {
		t.Errorf("cannot marshal: %s", err)
	} else if got, want := string(raw), `{"validation":{"foo":["bar"]}}`; got != want {
		t.Errorf("want %q, got %q", want, got)
	}
}
