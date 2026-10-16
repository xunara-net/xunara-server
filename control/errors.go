// Package control implements Xunara's Compatibility Core: the TS2021 / Noise
// control protocol that official Tailscale clients speak.
//
// Protocol compatibility is the top priority after security (AGENTS.md
// section 18). Code here mirrors upstream tailscale/headscale behaviour; see
// reference/ for the sources it was derived from.
package control

import (
	"encoding/json"
	"errors"
	"net/http"
)

const msgAddressPoolExhausted = "ADDRESS_POOL_EXHAUSTED: no usable device addresses remain; change the network range or ask the platform administrator to reallocate it"

// HTTPError is an error carrying an HTTP status code for the outer (non-Noise)
// router.
type HTTPError struct {
	Code int
	Msg  string
	Err  error
}

func (e HTTPError) Error() string {
	if e.Err != nil {
		return e.Msg + ": " + e.Err.Error()
	}
	return e.Msg
}

func (e HTTPError) Unwrap() error { return e.Err }

// NewHTTPError builds an [HTTPError].
func NewHTTPError(code int, msg string, err error) HTTPError {
	return HTTPError{Code: code, Msg: msg, Err: err}
}

// httpError writes err to w, using the embedded status code when err is an
// [HTTPError] and 500 otherwise. The error's message is never included in the
// response body to avoid leaking internals.
func httpError(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	msg := "internal error"

	var he HTTPError
	if errors.As(err, &he) {
		code = he.Code
		msg = he.Msg
	}
	http.Error(w, msg, code)
}

// writeJSON encodes v as a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
