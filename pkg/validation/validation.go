package validation

import "fmt"

type Errors map[string][]string

func (errs Errors) With(fieldName string, message string, args ...interface{}) Errors {
	if errs == nil {
		errs = make(map[string][]string)
	}
	errs[fieldName] = append(errs[fieldName], fmt.Sprintf(message, args...))
	return errs
}

func (errs Errors) WithRequired(fieldName string) Errors {
	return errs.With(fieldName, "Required.")
}

func (errs Errors) WithNotFound(fieldName string) Errors {
	return errs.With(fieldName, "Not found.")
}
