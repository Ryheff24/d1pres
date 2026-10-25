package orkey

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// serverArguments stands in for the launcher's server command line.
func serverArguments() []string {
	return []string{"/usr/bin/sandbox-exec", "-p", "(version 1)", "--", "/usr/local/libexec/d1-agent/d1-orkey", "--serve"}
}

func TestControls(t *testing.T) {
	for _, failure := range Controls(serverArguments) {
		t.Error(failure)
	}
}

// The sabotaged twins: each check must fail on a broken implementation, or its pass proves nothing.

func TestRoutesCatchAnyPath(t *testing.T) {
	open := func(key string, upstream http.RoundTripper) http.Handler {
		real := Handler(key, upstream)
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			request.URL.Path, request.URL.RawPath, request.Method = Route, "", http.MethodPost
			request.Host = Listen
			request.Header.Del("Origin")
			request.Header.Set("Content-Type", "application/json")
			real.ServeHTTP(writer, request)
		})
	}
	if len(CheckRoutes(open)) == 0 {
		t.Error("CheckRoutes passed a handler that forwards every path, method and Host")
	}
}

func TestRoutesCatchLeakedHeaders(t *testing.T) {
	leaky := func(key string, upstream http.RoundTripper) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if status, why := refusal(request); status != 0 {
				http.Error(writer, why, status)
				return
			}
			out := request.Clone(request.Context())
			out.URL.Scheme, out.URL.Host, out.URL.Path, out.Host = "https", UpstreamHost, upstreamPath, UpstreamHost
			out.Header.Set("Authorization", "Bearer "+key)
			response, _ := upstream.RoundTrip(out)
			writer.WriteHeader(response.StatusCode)
		})
	}
	if len(CheckRoutes(leaky)) == 0 {
		t.Error("CheckRoutes passed a handler that sends the caller's x-api-key and cookies upstream")
	}
}

func TestHostsCatchOpenGuard(t *testing.T) {
	open := func(dial DialFunc) DialFunc { return dial }
	if len(CheckHosts(open)) == 0 {
		t.Error("CheckHosts passed a guard that dials any address")
	}
	shut := func(DialFunc) DialFunc {
		return func(context.Context, string, string) (net.Conn, error) { return nil, ErrHost }
	}
	if len(CheckHosts(shut)) == 0 {
		t.Error("CheckHosts passed a guard that refuses openrouter.ai too")
	}
}

func TestChildCatchesKeyInArguments(t *testing.T) {
	leaky := func() []string { return append(serverArguments(), "--key="+controlKey) }
	if len(CheckChild(leaky)) == 0 {
		t.Error("CheckChild passed arguments that carry the key")
	}
}

func TestTakeKey(t *testing.T) {
	t.Setenv(KeyVariable, controlKey)
	key, environment, err := TakeKey(append(os.Environ(), "COPY="+controlKey))
	if err != nil || key != controlKey {
		t.Fatalf("TakeKey: %q, %v", key, err)
	}
	if os.Getenv(KeyVariable) != "" {
		t.Error("the key is still in this process's environment")
	}
	for _, variable := range environment {
		if strings.Contains(variable, controlKey) {
			t.Errorf("the environment handed on holds the key (%s)", strings.SplitN(variable, "=", 2)[0])
		}
	}
	t.Setenv(KeyVariable, "")
	_, _, err = TakeKey(os.Environ())
	if err == nil {
		t.Error("TakeKey accepted a missing key")
	}
}

func TestReadKey(t *testing.T) {
	key, err := ReadKey(strings.NewReader(controlKey + "\n"))
	if err != nil || key != controlKey {
		t.Errorf("ReadKey: %q, %v", key, err)
	}
	_, err = ReadKey(strings.NewReader("sk-or-a\nInjected: 1"))
	if err == nil {
		t.Error("ReadKey accepted a key with a header line in it")
	}
}

// TestWritesNoFile reads this package's sources: nothing in it creates or writes a file or logs
// (a log line is where a key would land). The tripwire is spelling-based; the profile's
// (deny file-write*) is what stops a write at run time.
func TestWritesNoFile(t *testing.T) {
	sources, err := filepath.Glob("*.go")
	if err != nil || len(sources) == 0 {
		t.Fatalf("no sources: %v", err)
	}
	writes := regexp.MustCompile(`os\.(Create|WriteFile|OpenFile|Mkdir|Rename|Symlink|Link)\b|"log"|"io/ioutil"|"log/slog"`)
	found := 0
	for _, source := range sources {
		text, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(source, "_test.go") {
			found += len(writes.FindAll(text, -1))
			continue
		}
		for _, match := range writes.FindAll(text, -1) {
			t.Errorf("%s: %s", source, match)
		}
	}
	if found == 0 {
		t.Error("control: the pattern finds nothing even in this test file, which spells the names it looks for")
	}
}
