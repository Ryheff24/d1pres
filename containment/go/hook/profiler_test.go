package hook

import (
	"path/filepath"
	"strings"
	"testing"
)

// The refusals TestAccessMatrix cannot reach through Decide: RoutesToProfiler sends ProfilerForm
// only commands with a word in them, and the matrix's root always resolves.
func TestProfilerFormEdges(t *testing.T) {
	if RoutesToProfiler("A=1 ; /usr/bin/true") {
		t.Error("a segment of assignments only routes to ProfilerForm")
	}
	if why := ProfilerForm("", t.TempDir()); why != "no command" {
		t.Errorf("empty command: got %q", why)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if why := inputPath("/usr/bin/true", missing); !strings.Contains(why, "cannot resolve") {
		t.Errorf("unresolvable root: got %q", why)
	}
}

// TestLogicalLineAtEnd: a backslash on the command's last line continues into nothing, and bash
// drops it (bash -c 'printf "[%s]" a \' prints [a]).
func TestLogicalLineAtEnd(t *testing.T) {
	for command, want := range map[string]string{"x \\": "x ", "a \\\nb\\": "a b"} {
		if line, rest := logicalLine(command); line != want || rest != "" {
			t.Errorf("%q: got %q, %q", command, line, rest)
		}
	}
}
