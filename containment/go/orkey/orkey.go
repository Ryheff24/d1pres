// Package orkey is d1-orkey's forwarder: one route, POST /v1/messages on 127.0.0.1, sent to one
// host, openrouter.ai at port 443, with the owner's OpenRouter key as the bearer token. The key
// comes in on a pipe, never in an environment, an argument or a file, and stays in this process's
// memory (spec/09-tools/research/09.22-working-model-decisions-2026-10-24.md §3, "The key stays
// out of every agent process"). Agents start sessions against it holding no secret:
// ANTHROPIC_BASE_URL=http://127.0.0.1:8790 ANTHROPIC_API_KEY= ANTHROPIC_AUTH_TOKEN=local claude.
package orkey

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	// Listen is the only address the helper listens on.
	Listen = "127.0.0.1:8790"
	// Route is the only path it forwards, and POST the only method.
	Route = "/v1/messages"
	// UpstreamHost is the only host it reaches; upstreamPath is OpenRouter's Anthropic Messages
	// route ("Anthropic Skin": base https://openrouter.ai/api, to which claude appends /v1/messages).
	UpstreamHost    = "openrouter.ai"
	upstreamAddress = "openrouter.ai:443"
	upstreamPath    = "/api/v1/messages"
	// KeyVariable is where op run puts the key for the launcher, which takes it out of the
	// environment before anything else starts; KeyDescriptor is the pipe the server reads it from.
	KeyVariable   = "OPENROUTER_API_KEY"
	KeyDescriptor = 3
	// maxBody bounds one request; a long session's context is a few megabytes.
	maxBody = 64 << 20
)

// forwardedHeaders are the request headers sent upstream; every other one, the caller's
// Authorization and x-api-key among them, is dropped.
var forwardedHeaders = []string{"Content-Type", "Accept", "Anthropic-Version", "Anthropic-Beta"}

// ErrHost is the dial refusal for any address but upstreamAddress.
var ErrHost = errors.New("d1-orkey reaches only " + upstreamAddress)

// CheckKey accepts an OpenRouter key: "sk-or-" then letters, digits, "-" and "_", so nothing in
// it can end or add a header line.
func CheckKey(key string) error {
	if !strings.HasPrefix(key, "sk-or-") || len(key) > 200 {
		return errors.New("not an OpenRouter key (sk-or-..., at most 200 characters)")
	}
	for _, character := range key {
		if !(character == '-' || character == '_' || character >= '0' && character <= '9' ||
			character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z') {
			return errors.New("the key holds a character other than a letter, a digit, - or _")
		}
	}
	return nil
}

// TakeKey reads KeyVariable, checks it, removes it from this process's environment, and returns
// it with environment minus every variable that names it or holds it.
func TakeKey(environment []string) (string, []string, error) {
	key := os.Getenv(KeyVariable)
	os.Unsetenv(KeyVariable)
	err := CheckKey(key)
	if err != nil {
		return "", nil, fmt.Errorf("%s: %w (start d1-orkey through op run)", KeyVariable, err)
	}
	return key, WithoutKey(environment, key), nil
}

// WithoutKey is environment minus KeyVariable and any variable whose text holds key.
func WithoutKey(environment []string, key string) []string {
	var kept []string
	for _, variable := range environment {
		if !strings.HasPrefix(variable, KeyVariable+"=") && (key == "" || !strings.Contains(variable, key)) {
			kept = append(kept, variable)
		}
	}
	return kept
}

// ReadKey reads the key from the launcher's pipe to its end and checks it.
func ReadKey(pipe io.Reader) (string, error) {
	text, err := io.ReadAll(io.LimitReader(pipe, 512))
	if err != nil {
		return "", fmt.Errorf("key pipe: %w", err)
	}
	key := strings.TrimSuffix(string(text), "\n")
	return key, CheckKey(key)
}

// DialFunc is net.Dialer.DialContext's shape.
type DialFunc func(ctx context.Context, network string, address string) (net.Conn, error)

// Guard admits only TCP to upstreamAddress, by name and before any lookup, and refuses the rest
// without calling dial. TLS then checks the certificate against UpstreamHost.
func Guard(dial DialFunc) DialFunc {
	return func(ctx context.Context, network string, address string) (net.Conn, error) {
		if address != upstreamAddress || (network != "tcp" && network != "tcp4" && network != "tcp6") {
			return nil, fmt.Errorf("%w: refused %s %s", ErrHost, network, address)
		}
		return dial(ctx, network, address)
	}
}

// Transport reaches upstreamAddress only through Guard, with no proxy (HTTPS_PROXY and the rest
// are ignored) and TLS to UpstreamHost.
func Transport() *http.Transport {
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	return &http.Transport{
		Proxy:               nil,
		DialContext:         Guard(dialer.DialContext),
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 30 * time.Second,
		IdleConnTimeout:     90 * time.Second,
	}
}

// refusal says why a request is not forwarded, or "" when it is. Besides the route: the Host must
// be this helper's own address, so a DNS-rebound web page cannot use it, and a browser request
// (Origin set, or a body that is not JSON, which a page can send without a preflight) is refused.
func refusal(request *http.Request) (int, string) {
	switch {
	case request.Method != http.MethodPost:
		return http.StatusMethodNotAllowed, "only POST " + Route
	case request.URL.Path != Route || request.URL.RawPath != "":
		return http.StatusNotFound, "only POST " + Route
	case request.Host != Listen && request.Host != "localhost:8790":
		return http.StatusForbidden, "Host must be " + Listen
	case request.Header.Get("Origin") != "":
		return http.StatusForbidden, "no browser requests"
	case !strings.HasPrefix(request.Header.Get("Content-Type"), "application/json"):
		return http.StatusUnsupportedMediaType, "the body must be application/json"
	}
	return 0, ""
}

// Handler forwards each admitted request to upstreamPath with key as the bearer token, streaming
// the answer back (server-sent events flush at once), and refuses everything else.
func Handler(key string, transport http.RoundTripper) http.Handler {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(forward *httputil.ProxyRequest) {
			forward.Out.URL = &url.URL{Scheme: "https", Host: UpstreamHost, Path: upstreamPath, RawQuery: forward.In.URL.RawQuery}
			forward.Out.Host = UpstreamHost
			forward.Out.Header = http.Header{}
			for _, name := range forwardedHeaders {
				for _, value := range forward.In.Header.Values(name) {
					forward.Out.Header.Add(name, value)
				}
			}
			forward.Out.Header.Set("Authorization", "Bearer "+key)
		},
		Transport:     transport,
		FlushInterval: -1,
		ErrorHandler: func(writer http.ResponseWriter, _ *http.Request, err error) {
			http.Error(writer, "d1-orkey: upstream: "+strings.ReplaceAll(err.Error(), key, "[key]"), http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		status, why := refusal(request)
		if status != 0 {
			http.Error(writer, "d1-orkey: "+why, status)
			return
		}
		request.Body = http.MaxBytesReader(writer, request.Body, maxBody)
		proxy.ServeHTTP(writer, request)
	})
}
