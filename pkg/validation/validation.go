package validation

import (
	"encoding/json"
	"fmt"
	"testing"
)

type Errors map[string][]string

func (e Errors) Empty() bool {
	return len(e) == 0
}

func (errs Errors) MarshalJSON() ([]byte, error) {
	if len(errs) == 0 {
		return []byte(`{"validation":{}}`), nil
	}
	return json.Marshal(struct {
		Validation map[string][]string `json:"validation"`
	}{
		Validation: errs,
	})
}

func (errs *Errors) Add(fieldName string, message string, args ...interface{}) {
	if *errs == nil {
		*errs = make(Errors)
	}
	(*errs)[fieldName] = append((*errs)[fieldName], fmt.Sprintf(message, args...))
}

func (e Errors) AddRequired(fieldName string) {
	e.Add(fieldName, "Required.")
}

func (e Errors) AddNotFound(fieldName string) {
	e.Add(fieldName, "Not found.")
}

func AssertHas(t testing.TB, jsonEncodedBody []byte, field string) {
	t.Helper()

	var v struct {
		Validation map[string][]string
	}
	if err := json.Unmarshal(jsonEncodedBody, &v); err != nil {
		t.Logf("body: %s", string(jsonEncodedBody))
		t.Fatalf("Cannot unmarshal body: %s", err)
	}
	if len(v.Validation[field]) == 0 {
		t.Fatalf("%s field error was expected, but not found.", field)
	}
}
