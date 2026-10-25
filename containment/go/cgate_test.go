package netguard

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"d1preservation/netguard/gate"
)

// cLiteral writes text as a C string literal.
func cLiteral(text string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(text) + `"`
}

// buildCGate compiles the real C gate, with policy as D1_NETGATE_PROFILE and this repository as
// D1_REPO, into a helper that calls d1_netgate("test") and prints "cgate-admitted" (a word the refusal line never contains). Until
// d1netgate.c takes its profile from the build, its own define collides with -D under
// -Werror=macro-redefined, and the test skips saying so.
func buildCGate(t *testing.T, policy string) string {
	t.Helper()
	requireSeatbelt(t)
	directory := t.TempDir()
	mainPath := filepath.Join(directory, "main.c")
	source := "#include <stdio.h>\nvoid d1_netgate(const char *tool);\nint main(void) { d1_netgate(\"test\"); puts(\"cgate-admitted\"); return 0; }\n"
	err := os.WriteFile(mainPath, []byte(source), 0600)
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(directory, "cgate")
	command := exec.Command("clang", "-Werror=macro-redefined", "-DD1_REPO="+cLiteral(repositoryRoot),
		"-DD1_NETGATE_PROFILE="+cLiteral(policy), "-o", helper, mainPath,
		filepath.Join(repositoryRoot, "containment", "c", "d1netgate.c"))
	output, err := command.CombinedOutput()
	if err != nil && strings.Contains(string(output), "macro-redefined") {
		t.Skipf("containment/c/d1netgate.c still defines D1_NETGATE_PROFILE itself; this control "+
			"waits for the build to pass gate.Normalize's text:\n%s", output)
	}
	if err != nil {
		t.Fatalf("cannot compile the C gate: %v\n%s", err, output)
	}
	return helper
}

// TestCGateUnderPolicy: the C gate built with the normalized policy runs under the same text
// (its own apply stacks: the same compiled policy) and refuses under the text plus one extra allowed
// port, whose weakening is shown to be real first. That refusal is the admission mechanism.
func TestCGateUnderPolicy(t *testing.T) {
	policy := gate.Normalize(GameProfile, repositoryRoot)
	helper := buildCGate(t, policy)
	output, status := run(t, nil, nil, "/usr/bin/sandbox-exec", "-p", policy, "--", helper)
	if status != 0 || !strings.Contains(output, "cgate-admitted") {
		t.Fatalf("the C gate refused the policy it was built with: status %d", status)
	}
	listenSelective(t)
	weakened := gate.Normalize(GameProfile+selectiveAllowance, repositoryRoot)
	requirePolicyProbe(t, weakened, "network", "connect", "127.0.0.1", selectivePort, "allowed")
	output, status = run(t, nil, nil, "/usr/bin/sandbox-exec", "-p", weakened, "--", helper)
	if status != 2 || strings.Contains(output, "cgate-admitted") {
		t.Fatalf("the C gate accepted a selectively weakened policy: status %d", status)
	}
}

// TestCGateMach: with one delegate deny removed from the policy (the gate built with and run
// under that same text, so its apply succeeds), the gate's Mach check must name the service.
func TestCGateMach(t *testing.T) {
	service := "com.apple.nehelper"
	policy := gate.Normalize(removeLines(t, GameProfile, containing(`"`+service+`"`)), repositoryRoot)
	helper := buildCGate(t, policy)
	output, status := run(t, nil, nil, "/usr/bin/sandbox-exec", "-p", policy, "--", helper)
	if status != 2 || !strings.Contains(output, service) {
		t.Fatalf("the C gate did not refuse naming %s: status %d", service, status)
	}
}

// TestCGateDescriptors: the C gate under its own policy runs with no extra descriptors and refuses
// naming the socket when one is inherited at descriptor 3.
func TestCGateDescriptors(t *testing.T) {
	policy := gate.Normalize(GameProfile, repositoryRoot)
	helper := buildCGate(t, policy)
	output, status := run(t, nil, nil, "/usr/bin/sandbox-exec", "-p", policy, "--", helper)
	if status != 0 || !strings.Contains(output, "cgate-admitted") {
		t.Fatalf("the C gate refused its own policy with no extra descriptors: status %d", status)
	}
	output, status = run(t, nil, []*os.File{socketFile(t)}, "/usr/bin/sandbox-exec", "-p", policy, "--", helper)
	if status != 2 || !strings.Contains(output, "fd 3: socket") || strings.Contains(output, "cgate-admitted") {
		t.Fatalf("the C gate did not refuse a socket at descriptor 3: status %d", status)
	}
}

// TestCGateWrites: with every file-write* rule removed (the gate built with and run under that
// same text, so its apply succeeds), the write probes must name the repository's CLAUDE.md, and
// their positive control (/private/tmp reads allowed) must not fire. The full policy passes.
func TestCGateWrites(t *testing.T) {
	policy := gate.Normalize(GameProfile, repositoryRoot)
	helper := buildCGate(t, policy)
	output, status := run(t, nil, nil, "/usr/bin/sandbox-exec", "-p", policy, "--", helper)
	if status != 0 || !strings.Contains(output, "cgate-admitted") {
		t.Fatalf("the C gate refused the full policy: status %d", status)
	}
	writable := gate.Normalize(removeLines(t, GameProfile, containing("file-write*")), repositoryRoot)
	helper = buildCGate(t, writable)
	output, status = run(t, nil, nil, "/usr/bin/sandbox-exec", "-p", writable, "--", helper)
	named := "write " + filepath.Join(repositoryRoot, "CLAUDE.md") + ": allowed"
	if status != 2 || !strings.Contains(output, named) || strings.Contains(output, "write control") {
		t.Fatalf("the C gate did not refuse naming %q with its write control quiet: status %d", named, status)
	}
}

// TestBuiltGateStacks (M3): the built d1-oracle and d1-recomp carry the policy the Rust
// normalizer (netgate_profile.rs) made. Each must run under the Go normalizer's text, since their
// apply stacks only on the same compiled policy, and refuse under that text plus one allow. A
// binary not built is not a pass: with neither built the test fails.
func TestBuiltGateStacks(t *testing.T) {
	requireSeatbelt(t)
	var binaries []string
	for _, name := range []string{"d1-oracle", "d1-recomp"} {
		binary := repositoryRoot + "/d1-server/target/release/" + name
		_, err := os.Stat(binary)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		binaries = append(binaries, binary)
	}
	if len(binaries) == 0 {
		t.Fatalf("neither d1-oracle nor d1-recomp is built, so the Rust normalizer is unchecked; " +
			"run `cd d1-server && cargo build --release -p d1-oracle -p d1-recomp`")
	}
	policy := gate.Normalize(GameProfile, repositoryRoot)
	listenSelective(t)
	weakened := gate.Normalize(GameProfile+selectiveAllowance, repositoryRoot)
	requirePolicyProbe(t, weakened, "network", "connect", "127.0.0.1", selectivePort, "allowed")
	for _, binary := range binaries {
		output, status := run(t, nil, nil, "/usr/bin/sandbox-exec", "-p", policy, "--", binary, "--help")
		if status != 0 || strings.Contains(output, "REFUSED") {
			t.Fatalf("%s refused the launcher's policy: status %d", binary, status)
		}
		output, status = run(t, nil, nil, "/usr/bin/sandbox-exec", "-p", weakened, "--", binary, "--help")
		if status != 2 || !strings.Contains(output, "its profile did not apply") {
			t.Fatalf("%s accepted a selectively weakened policy: status %d", binary, status)
		}
	}
}
