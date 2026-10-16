package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

func postBrowserDecision(test *testing.T, client *http.Client, endpoint, csrf string, cookie *http.Cookie) *http.Response {
	test.Helper()
	return postBrowserJSON(test, client, endpoint, csrf, map[string]any{}, cookie)
}

func postBrowserJSON(test *testing.T, client *http.Client, endpoint, csrf string, body any, cookie *http.Cookie) *http.Response {
	test.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		test.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		test.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response, err := client.Do(request)
	if err != nil {
		test.Fatal(err)
	}
	test.Cleanup(func() { response.Body.Close() })
	return response
}

func postSetupJSON(test *testing.T, client *http.Client, base string, values url.Values, cookies ...*http.Cookie) *http.Response {
	test.Helper()
	body := map[string]string{}
	for name := range values {
		if name != "_csrf" {
			body[name] = values.Get(name)
		}
	}
	var cookie *http.Cookie
	if len(cookies) > 0 {
		cookie = cookies[0]
	}
	return postBrowserJSON(test, client, base+"/api/v1/auth/setup", values.Get("_csrf"), body, cookie)
}

func authorizationCSRF(test *testing.T, response *http.Response) string {
	test.Helper()
	var payload struct {
		CSRF string `json:"csrf_token"`
	}
	decodeJSONBody(test, response, &payload)
	if payload.CSRF == "" {
		test.Fatal("authorization API omitted CSRF proof")
	}
	return payload.CSRF
}
