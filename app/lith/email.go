package lith

import "strings"

// NormalizeEmail does its best to cleanup an email and return its normalized
// form.
//
// Currently this implementation is more of a placeholder than an actual
// functionality. It would be amazing to unify domains, remove meaningless
// charactes and labels, but maintaining such logic might be beyond the scope
// of this application.
func NormalizeEmail(e string) string {
	return strings.TrimSpace(strings.ToLower(e))
}
