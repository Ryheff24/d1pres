package netguard

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"d1preservation/netguard/gate"
)

var nonetPath string

// selectivePort is where the selective-allowance controls listen; the probes aim at port 9.
const selectivePort = "48123"

// selectiveAllowance is the astra review's counterexample: one extra destination that every
// production probe misses.
const selectiveAllowance = "\n(allow network-outbound (remote ip \"localhost:" + selectivePort + "\"))\n"

// fakeRepository builds a repository with every path the prove step probes, the given text as
// its game.sb (which d1-nonet must ignore) and d1-nonet in bin/, so the launcher finds this root
// from its own location. It lives in the control directory: inside this repository, outside
// temporary space.
func fakeRepository(t *testing.T, profile string) (string, string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{"containment/go/profiles", "design", "d1-server/crates", ".git", "runs", "bin"} {
		err = os.MkdirAll(filepath.Join(root, directory), 0700)
		if err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{"CLAUDE.md": "fake\n", "containment/go/profiles/game.sb": profile}
	for name, contents := range files {
		err = os.WriteFile(filepath.Join(root, name), []byte(contents), 0600)
		if err != nil {
			t.Fatal(err)
		}
	}
	contents, err := os.ReadFile(nonetPath)
	if err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(root, "bin", "d1-nonet")
	err = os.WriteFile(launcher, contents, 0700)
	if err != nil {
		t.Fatal(err)
	}
	return root, launcher
}

// run starts a command with a time limit and returns its output and exit status. Standard
// output goes to stdout when given (a socket, for the stdout control), else with stderr.
func run(t *testing.T, stdout *os.File, files []*os.File, arguments ...string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, arguments[0], arguments[1:]...)
	var output bytes.Buffer
	command.Stdout = &output
	if stdout != nil {
		command.Stdout = stdout
	}
	command.Stderr = &output
	command.ExtraFiles = files
	err := command.Run()
	t.Logf("%q\n%s", arguments, output.String())
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Fatalf("could not run %q: %v", arguments, err)
	}
	return output.String(), command.ProcessState.ExitCode()
}

// proveUnder runs the launcher's prove step under policy text, as the launcher itself does.
func proveUnder(t *testing.T, policy string, launcher string, files []*os.File) (string, int) {
	t.Helper()
	return run(t, nil, files, "/usr/bin/sandbox-exec", "-p", policy, "--", launcher, "--prove")
}

// listenSelective opens an unsandboxed loopback listener on selectivePort for this test.
func listenSelective(t *testing.T) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:"+selectivePort)
	if err != nil {
		t.Fatalf("the selective-allowance control needs port %s free: %v", selectivePort, err)
	}
	t.Cleanup(func() {
		listener.Close()
	})
}

// gameProfile reads profiles/game.sb from disk, so a stale embed is noticed.
func gameProfile(t *testing.T) string {
	t.Helper()
	text, err := os.ReadFile("profiles/game.sb")
	if err != nil {
		t.Fatal(err)
	}
	return string(text)
}

// TestNormalize checks gate.Normalize against the readable profile: one line, no comments, the
// root substituted, and the same rules in the same order as game.sb. Pure parsing.
func TestNormalize(t *testing.T) {
	policy := gate.Normalize(GameProfile, "/r")
	if strings.ContainsAny(policy, ";\n") || strings.Contains(policy, "param") || !strings.Contains(policy, `(subpath "/r/runs")`) {
		t.Fatalf("normalized policy is not one comment-free line with the root substituted: %s", policy)
	}
	readable := strings.ReplaceAll(sbplProfile(GameProfile), "@REPO@", "/r")
	if strings.Join(expandRules(t, policy), "\n") != strings.Join(expandRules(t, readable), "\n") {
		t.Fatalf("normalized policy differs from game.sb:\n%s", policy)
	}
	if GameProfile != gameProfile(t) {
		t.Fatal("the embedded profile differs from profiles/game.sb; rebuild")
	}
}

// TestNonetRuns is the positive control: under the embedded profile the command runs, exit 0.
func TestNonetRuns(t *testing.T) {
	requireSeatbelt(t)
	_, launcher := fakeRepository(t, GameProfile)
	output, status := run(t, nil, nil, launcher, "/bin/echo", "contained")
	if status != 0 || !strings.Contains(output, "contained") {
		t.Fatalf("d1-nonet did not run the command under the embedded profile: status %d", status)
	}
}

// TestNonetSabotage runs the prove step under the policy with one block of rules removed; it
// must exit 2 naming the probe that is now open. The unmodified policy passes, in the same test.
func TestNonetSabotage(t *testing.T) {
	requireSeatbelt(t)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	root, launcher := fakeRepository(t, GameProfile)
	_, status := proveUnder(t, gate.Normalize(GameProfile, root), launcher, nil)
	if status != 0 {
		t.Fatalf("the prove step refused the embedded policy: status %d", status)
	}
	cases := []struct {
		name   string
		remove func(line string) bool
		named  []string
	}{
		{"network", prefixed("(deny network*) "), []string{"tcp 127.0.0.1: "}},
		{"socket-options", prefixed("(deny socket-option-set) "), []string{"setsockopt SO_REUSEADDR: succeeded"}},
		{"writes", containing("file-write*"), []string{"write " + filepath.Join(root, "CLAUDE.md") + ": succeeded", "write " + home + ": succeeded"}},
	}
	for _, sabotage := range cases {
		t.Run(sabotage.name, func(t *testing.T) {
			policy := gate.Normalize(removeLines(t, GameProfile, sabotage.remove), root)
			output, status := proveUnder(t, policy, launcher, nil)
			if status != 2 {
				t.Fatalf("sabotaged policy was not refused: status %d", status)
			}
			for _, item := range sabotage.named {
				if !strings.Contains(output, item) {
					t.Fatalf("the refusal does not name %q", item)
				}
			}
		})
	}
}

// TestNonetIgnoresRepositoryProfile is the selective-allowance control for the launcher: a fake
// repository's game.sb that admits one extra port is ignored. The weakening is shown to be real
// first; then a command under d1-nonet in that repository still cannot reach the port.
func TestNonetIgnoresRepositoryProfile(t *testing.T) {
	requireSeatbelt(t)
	listenSelective(t)
	weakened := GameProfile + selectiveAllowance
	root, launcher := fakeRepository(t, weakened)
	requirePolicyProbe(t, gate.Normalize(weakened, root), "network", "connect", "127.0.0.1", selectivePort, "allowed")
	output, status := run(t, nil, nil, launcher, gatePath, "network", "connect", "127.0.0.1", selectivePort, "denied")
	if status != 0 || !strings.Contains(output, "refused by policy") {
		t.Fatalf("d1-nonet applied the repository's profile instead of its embedded one: status %d", status)
	}
}

// prefixed matches a profile line that starts with prefix.
func prefixed(prefix string) func(string) bool {
	return func(line string) bool {
		return strings.HasPrefix(line, prefix)
	}
}

// containing matches a profile line that contains text.
func containing(text string) func(string) bool {
	return func(line string) bool {
		return strings.Contains(line, text)
	}
}

// removeLines drops the matching lines, and fails if none matched, so a renamed rule cannot
// turn a sabotage into a no-op.
func removeLines(t *testing.T, profile string, remove func(string) bool) string {
	t.Helper()
	var kept []string
	for _, line := range strings.Split(profile, "\n") {
		if !remove(line) {
			kept = append(kept, line)
		}
	}
	if len(kept) == len(strings.Split(profile, "\n")) {
		t.Fatal("no profile line matched the sabotage; the profile changed under the test")
	}
	return strings.Join(kept, "\n")
}

// socketFile is one end of a Unix socket pair as a file; the other end is closed by cleanup.
func socketFile(t *testing.T) *os.File {
	t.Helper()
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	syscall.CloseOnExec(pair[0])
	syscall.CloseOnExec(pair[1])
	t.Cleanup(func() {
		syscall.Close(pair[1])
	})
	file := os.NewFile(uintptr(pair[0]), "socket")
	t.Cleanup(func() {
		file.Close()
	})
	return file
}

// TestNonetInheritedSocket (T7): a socket at descriptor 10 refuses the prove step; the launcher
// marks it close-on-exec, so the same launch through d1-nonet runs; a socket on stdout refuses.
func TestNonetInheritedSocket(t *testing.T) {
	requireSeatbelt(t)
	root, launcher := fakeRepository(t, GameProfile)
	files := make([]*os.File, 8)
	files[7] = socketFile(t)
	output, status := proveUnder(t, gate.Normalize(GameProfile, root), launcher, files)
	if status != 2 || !strings.Contains(output, "descriptor 10: socket") {
		t.Fatalf("an inherited socket at descriptor 10 was not refused: status %d", status)
	}
	_, status = run(t, nil, files, launcher, "/usr/bin/true")
	if status != 0 {
		t.Fatalf("the launcher handed an inherited socket on to the prove step: status %d", status)
	}
	output, status = run(t, socketFile(t), nil, launcher, "/usr/bin/true")
	if status != 2 || !strings.Contains(output, "stdout: socket") {
		t.Fatalf("a socket on stdout was not refused: status %d\n%s", status, output)
	}
}

// TestNonetDescriptors (finding 5): a regular file at 3, a socket at 10 and a regular file at 200
// reach the helper when it runs bare (the positive control) and none reach it through d1-nonet.
func TestNonetDescriptors(t *testing.T) {
	requireSeatbelt(t)
	_, launcher := fakeRepository(t, GameProfile)
	regular, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	files := make([]*os.File, 198)
	files[0] = regular
	files[7] = socketFile(t)
	files[197] = regular
	output, status := run(t, nil, files, gatePath, "descriptors")
	if status == 0 || !strings.Contains(output, "200(") || !strings.Contains(output, "10(") || !strings.Contains(output, "3(") {
		t.Fatalf("the bare helper did not see the inherited descriptors, so the control proves nothing: status %d", status)
	}
	output, status = run(t, nil, files, launcher, gatePath, "descriptors")
	if status != 0 || !strings.Contains(output, "descriptors above 2: []") {
		t.Fatalf("descriptors above 2 survived into the command under d1-nonet: status %d", status)
	}
}

// TestProveWithoutProfileRefuses (T8): the prove step run with no profile at all refuses. Inside
// another sandbox it would inherit that sandbox, so it is skipped there.
func TestProveWithoutProfileRefuses(t *testing.T) {
	if seatbeltUnavailable != "" {
		t.Skip("already inside a sandbox, so this would not run the prove step without a profile")
	}
	_, launcher := fakeRepository(t, GameProfile)
	output, status := run(t, nil, nil, launcher, "--prove")
	if status != 2 || !strings.Contains(output, "tcp 127.0.0.1: ") {
		t.Fatalf("the prove step passed with no profile applied: status %d", status)
	}
}
