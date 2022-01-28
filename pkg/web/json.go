package web

import (
	"encoding/json"
	"net/http"
)

func WriteJSON(w http.ResponseWriter, code int, content interface{}) {
	if code == http.StatusNoContent {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	b, err := json.MarshalIndent(content, "", "\t")
	if err != nil {
		code = http.StatusInternalServerError
		b = []byte(`{"code":500,"error":"Response serialization failure."}`)
	}
	w.Header().Set("Content-Type", "application/json;charset=utf-8")
	w.WriteHeader(code)

	_, _ = w.Write(b)
	// Be nice to CLI.
	_, _ = w.Write([]byte{'\n'})
}

func WriteJSONErr(w http.ResponseWriter, code int, message string) {
	if message == "" {
		// No message = no payload.
		w.WriteHeader(code)
		return
	}
	WriteJSON(w, code, struct {
		// Repeat the HTTP response status code so that when inspecting
		// the response body alone, so that header inspection is not
		// required to understand the response.
		Code  int    `json:"code"`
		Error string `json:"error"`
	}{
		Code:  code,
		Error: message,
	})
}

func WriteJSONStdErr(w http.ResponseWriter, code int) {
	// This is a bit useless payload, because its the default code, but it
	// looks nice and when using CLI you don't always print out response
	// status code.
	WriteJSONErr(w, code, http.StatusText(code))
}
