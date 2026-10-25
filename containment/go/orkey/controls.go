package orkey

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
)

// controlKey stands in for the owner's key in the controls; it passes CheckKey.
const controlKey = "sk-or-v1-control0123456789"

// recorder is an upstream that records what reaches it and answers 200, in memory.
type recorder struct{ requests []*http.Request }

func (r *recorder) RoundTrip(request *http.Request) (*http.Response, error) {
	r.requests = append(r.requests, request)
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(`{"type":"message"}`)), Request: request}, nil
}

// send serves one request through handler, in memory: no socket is opened.
func send(handler http.Handler, method string, target string, header http.Header) int {
	request := httptest.NewRequest(method, target, strings.NewReader(`{"model":"x","messages":[]}`))
	request.Host = Listen
	for name, values := range header {
		request.Header[name] = values
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response.Code
}

// json is the header set a claude session sends: JSON, its version header, and the placeholder
// token and key it is started with, which must not reach upstream.
func json() http.Header {
	return http.Header{"Content-Type": {"application/json"}, "Anthropic-Version": {"2023-06-01"},
		"Authorization": {"Bearer local"}, "X-Api-Key": {"leak"}, "Cookie": {"leak=1"}}
}

// CheckRoutes sends the one admitted request and requires it forwarded exactly (the positive
// control), then sends requests that must each be refused without reaching upstream. newHandler
// builds the handler under test from a key and an upstream.
func CheckRoutes(newHandler func(string, http.RoundTripper) http.Handler) []string {
	var failures []string
	upstream := &recorder{}
	handler := newHandler(controlKey, upstream)
	status := send(handler, http.MethodPost, "http://"+Listen+Route+"?beta=true", json())
	if status != http.StatusOK || len(upstream.requests) != 1 {
		return append(failures, fmt.Sprintf("forward control: POST %s answered %d with %d upstream requests, want 200 and 1", Route, status, len(upstream.requests)))
	}
	out := upstream.requests[0]
	if got := out.URL.String(); got != "https://"+UpstreamHost+upstreamPath+"?beta=true" {
		failures = append(failures, "forward control: upstream URL "+got)
	}
	if out.Host != UpstreamHost && out.Host != "" {
		failures = append(failures, "forward control: upstream Host "+out.Host)
	}
	if out.Header.Get("Authorization") != "Bearer "+controlKey {
		failures = append(failures, "forward control: upstream Authorization is not the key")
	}
	for _, name := range []string{"X-Api-Key", "Cookie"} {
		if out.Header.Get(name) != "" {
			failures = append(failures, "forward control: "+name+" reached upstream")
		}
	}
	if out.Header.Get("Anthropic-Version") != "2023-06-01" {
		failures = append(failures, "forward control: Anthropic-Version was dropped")
	}
	refused := []struct {
		what   string
		method string
		target string
		header http.Header
	}{
		{"GET " + Route, http.MethodGet, Route, json()},
		{"POST " + Route + "/count_tokens", http.MethodPost, Route + "/count_tokens", json()},
		{"POST /v1/complete", http.MethodPost, "/v1/complete", json()},
		{"POST " + upstreamPath, http.MethodPost, upstreamPath, json()},
		{"POST " + Route + "/", http.MethodPost, Route + "/", json()},
		{"POST /v1/messages encoded", http.MethodPost, "/v1%2Fmessages", json()},
		{"POST /", http.MethodPost, "/", json()},
		{"another Host", http.MethodPost, "http://evil.example" + Route, json()},
		{"an Origin", http.MethodPost, Route, with(json(), "Origin", "https://evil.example")},
		{"a text/plain body", http.MethodPost, Route, with(json(), "Content-Type", "text/plain")},
	}
	for _, request := range refused {
		before := len(upstream.requests)
		header := request.header
		var status int
		if strings.HasPrefix(request.target, "http://evil.example") {
			status = sendHost(handler, request.method, request.target, header, "evil.example")
		} else {
			status = send(handler, request.method, "http://"+Listen+request.target, header)
		}
		if status < 400 || len(upstream.requests) != before {
			failures = append(failures, fmt.Sprintf("%s: answered %d and reached upstream %d times, want refused", request.what, status, len(upstream.requests)-before))
		}
	}
	return failures
}

func with(header http.Header, name string, value string) http.Header {
	header.Set(name, value)
	return header
}

// sendHost is send with another Host header.
func sendHost(handler http.Handler, method string, target string, header http.Header, host string) int {
	request := httptest.NewRequest(method, target, strings.NewReader(`{}`))
	request.Host = host
	for name, values := range header {
		request.Header[name] = values
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response.Code
}

// errDialed is what the stand-in dialer returns, so a guard that let an address through is seen
// without any connection being made.
var errDialed = errors.New("dialed")

// CheckHosts requires guard to refuse every address but upstreamAddress without dialing, and to
// pass upstreamAddress on (the positive control). Nothing is dialed for real.
func CheckHosts(guard func(DialFunc) DialFunc) []string {
	var failures []string
	var dialed []string
	dial := guard(func(_ context.Context, network string, address string) (net.Conn, error) {
		dialed = append(dialed, network+" "+address)
		return nil, errDialed
	})
	_, err := dial(context.Background(), "tcp", upstreamAddress)
	if !errors.Is(err, errDialed) || len(dialed) != 1 {
		failures = append(failures, "host control: tcp "+upstreamAddress+" was not passed on")
	}
	for _, probe := range [][2]string{{"tcp", "evil.example:443"}, {"tcp", "openrouter.ai:80"},
		{"tcp", "openrouter.ai.evil.example:443"}, {"tcp", "104.18.2.115:443"}, {"udp", upstreamAddress},
		{"tcp", "api.anthropic.com:443"}, {"tcp", "OPENROUTER.AI:443"}} {
		before := len(dialed)
		_, err := dial(context.Background(), probe[0], probe[1])
		if !errors.Is(err, ErrHost) || len(dialed) != before {
			failures = append(failures, "host: "+probe[0]+" "+probe[1]+" was not refused")
		}
	}
	return failures
}

// CheckChild requires the key gone from what the launcher hands on: the environment from TakeKey
// (positive control: the other variables stay) and the server's arguments.
func CheckChild(arguments func() []string) []string {
	var failures []string
	environment := []string{KeyVariable + "=" + controlKey, "HOME=/Users/x", "COPY=" + controlKey, "PATH=/usr/bin"}
	kept := WithoutKey(environment, controlKey)
	for _, variable := range kept {
		if strings.Contains(variable, controlKey) {
			failures = append(failures, "child environment holds the key ("+strings.SplitN(variable, "=", 2)[0]+")")
		}
	}
	if len(kept) != 2 {
		failures = append(failures, fmt.Sprintf("child environment control: kept %d of the 2 other variables", len(kept)))
	}
	for _, argument := range arguments() {
		if strings.Contains(argument, controlKey) || strings.Contains(argument, "sk-or-") {
			failures = append(failures, "child arguments hold the key")
		}
	}
	return failures
}

// Controls runs every check against the real handler, guard and environment filter; arguments is
// the server command line the launcher builds. Each check also has a sabotaged twin in the tests,
// which must fail, so a check that passes everything cannot pass here.
func Controls(arguments func() []string) []string {
	failures := CheckRoutes(Handler)
	failures = append(failures, CheckHosts(Guard)...)
	failures = append(failures, CheckChild(arguments)...)
	if Transport().Proxy != nil {
		failures = append(failures, "transport: a proxy function is set, so HTTPS_PROXY could redirect it")
	}
	for _, key := range []string{"", "sk-ant-x", "sk-or-a\r\nX: y", "sk-or-a b"} {
		if CheckKey(key) == nil {
			failures = append(failures, fmt.Sprintf("key check: accepted %q", key))
		}
	}
	if CheckKey(controlKey) != nil {
		failures = append(failures, "key check control: refused a well-formed key")
	}
	return failures
}
