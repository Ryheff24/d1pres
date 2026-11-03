package netguard

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"d1preservation/netguard/gate"
)

// TestTestgateHeader: d1-testgate-header, which install.sh runs to compile the test gate, prints
// the repository root and game.sb normalized exactly as d1-nonet applies it, and refuses a root it
// cannot vouch for. Controls: no argument is a usage error, a root in temporary space is refused,
// and a real root whose name a C string literal would need escaping for is refused.
func TestTestgateHeader(t *testing.T) {
	binary := filepath.Join(controlDirectory, "d1-testgate-header")
	if log, err := buildCommand("-o", binary, "./cmd/d1-testgate-header").CombinedOutput(); err != nil {
		t.Fatalf("build d1-testgate-header: %v\n%s", err, log)
	}
	run := func(arguments ...string) (string, string, int) {
		t.Helper()
		var stdout, stderr strings.Builder
		command := exec.Command(binary, arguments...)
		command.Stdout, command.Stderr = &stdout, &stderr
		err := command.Run()
		var exit *exec.ExitError
		if err != nil && !errors.As(err, &exit) {
			t.Fatal(err)
		}
		return stdout.String(), stderr.String(), command.ProcessState.ExitCode()
	}

	header, _, code := run(repositoryRoot)
	want := "#define D1_REPO " + strconv.Quote(repositoryRoot) + "\n#define D1_NETGATE_PROFILE " +
		strconv.Quote(gate.Normalize(GameProfile, repositoryRoot)) + "\n"
	if code != 0 || header != want {
		t.Errorf("for %s: exit %d, printed %q; want exit 0 and %q", repositoryRoot, code, header, want)
	}

	accented := filepath.Join(controlDirectory, "dépôt")
	for _, name := range []string{"CLAUDE.md", "containment/x"} {
		path := filepath.Join(accented, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("fake\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, refused := range []struct {
		arguments []string
		code      int
		reason    string
	}{
		{nil, 64, "usage: d1-testgate-header ROOT"},
		{[]string{"/private/tmp/repo"}, 2, "where game code may write"},
		{[]string{accented}, 2, "C string literal would need escaping"},
	} {
		printed, why, code := run(refused.arguments...)
		if code != refused.code || printed != "" || !strings.Contains(why, refused.reason) {
			t.Errorf("%q: exit %d, printed %q, said %q; want exit %d, nothing printed, and %q",
				refused.arguments, code, printed, why, refused.code, refused.reason)
		}
	}
}
