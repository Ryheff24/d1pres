package netguard

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestMinimalStartup proves a program starts under each profile at all.
func TestMinimalStartup(t *testing.T) {
	requireProbe(t, "", "hello")
	requireProbe(t, "profiles/game.sb", "hello")
}

// TestUnixPaths pairs forbidden live sockets with the broker's parameterized allowed socket. The
// game has no Unix-socket allowance: its broker channel is an inherited descriptor.
func TestUnixPaths(t *testing.T) {
	requireSeatbelt(t)
	secondSocketPath := filepath.Join(controlDirectory, "b")
	for _, path := range []string{brokerSocketPath, secondSocketPath} {
		listener, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			listener.Close()
		})
		requireProbe(t, "", "unix", path, "allowed")
	}
	requireProbe(t, "profiles/broker.sb", "unix", brokerSocketPath, "allowed")
	requireProbe(t, "profiles/broker.sb", "unix", secondSocketPath, "denied")
	requireProbe(t, "profiles/game.sb", "unix", brokerSocketPath, "denied")
	requireProbe(t, "profiles/game.sb", "unix", secondSocketPath, "denied")
}

// TestUnixListening proves only the broker can listen on its own parameterized path. The bind
// and listen are raw syscalls with no socket option first, at paths the helper first shows are
// writable, so each denial is the network rule (astra review 2026-10-16, finding 4).
func TestUnixListening(t *testing.T) {
	requireSeatbelt(t)
	secondSocketPath := filepath.Join(controlDirectory, "b")
	temporaryPath := "/private/tmp/d1-listen-" + strconv.Itoa(os.Getpid())
	t.Cleanup(func() {
		os.Remove(temporaryPath)
	})
	requireProbe(t, "", "unix-listen", temporaryPath, "allowed")
	requireProbe(t, "", "unix-listen", brokerSocketPath, "allowed")
	requireProbe(t, "", "unix-listen", secondSocketPath, "allowed")
	requireProbe(t, "profiles/broker.sb", "unix-listen", brokerSocketPath, "allowed")
	requireProbe(t, "profiles/broker.sb", "unix-listen", secondSocketPath, "denied")
	requireProbe(t, "profiles/game.sb", "unix-listen", temporaryPath, "denied")
}

// TestExecution proves T4's osascript denial, paired with the same exec allowed outside. Exec in
// general stays allowed under game.sb until d1-recomp stops spawning clang (T2 deferred); the
// helper re-executing itself is the positive control that the denial is by path.
func TestExecution(t *testing.T) {
	requireProbe(t, "", "execute", "allowed", "/bin/sh", "-c", "exit 0")
	output := requireProbe(t, "profiles/game.sb", "execute", "allowed", gatePath, "hello")
	if !strings.Contains(output, "helper started") {
		t.Fatal("allowed exec did not reach the replacement helper")
	}
	requireProbe(t, "", "start", "allowed", "/usr/bin/osascript", "-e", "")
	requireProbe(t, "profiles/game.sb", "start", "denied", "/usr/bin/osascript", "-e", "")
}

// TestOpenExecution proves T4 without asking LaunchServices to open a file or application.
func TestOpenExecution(t *testing.T) {
	output := requireProbe(t, "", "start", "allowed", "/usr/bin/open")
	if !strings.Contains(output, "Usage: open") {
		t.Fatal("open did not run far enough to print its usage")
	}
	requireProbe(t, "profiles/game.sb", "start", "denied", "/usr/bin/open")
}

// TestResolver checks the safe baseline, then gates the sandboxed lookup on T1 passing.
func TestResolver(t *testing.T) {
	requireSeatbelt(t)
	name := resolverName(t)
	requireResolver(t, "", name, "allowed")
	if !t.Run("T1Prerequisite", TestGameNetwork) {
		t.Fatal("T1 failed; sandboxed resolver control was not run")
	}
	requireResolver(t, "profiles/game.sb", name, "denied")
}

// resolverName obtains this Mac's service-backed name outside the sandbox.
func resolverName(t *testing.T) string {
	t.Helper()
	output, err := exec.Command("/usr/sbin/scutil", "--get", "LocalHostName").Output()
	if err != nil {
		t.Fatal(err)
	}
	name := strings.TrimSpace(string(output))
	if name == "" {
		t.Fatal("scutil returned an empty LocalHostName")
	}
	return name + ".local"
}

// requireResolver rejects Go resolver fallback even when the lookup has the expected result.
// The selection line differs by Go release (net/conf.go): 1.23 printed "using cgo DNS resolver",
// 1.27 prints "GODEBUG setting forcing use of the cgo resolver" for GODEBUG=netdns=cgo, and
// "using the cgo DNS resolver" under the netcgo build tag. A binary without cgo prints "ignoring
// GODEBUG=netdns=cgo", which must fail. The per-lookup hostLookupOrder line is required in all cases.
func requireResolver(t *testing.T, profilePath string, name string, expectation string) {
	t.Helper()
	output := requireProbe(t, profilePath, "resolve", name, expectation)
	selected := false
	for _, line := range []string{"using cgo DNS resolver", "using the cgo DNS resolver", "GODEBUG setting forcing use of the cgo resolver"} {
		selected = selected || strings.Contains(output, line)
	}
	if !selected ||
		strings.Contains(output, "ignoring GODEBUG=netdns=cgo") ||
		strings.Contains(output, "using the Go DNS resolver") ||
		!strings.Contains(output, "hostLookupOrder("+name+") = cgo") {
		t.Fatalf("libSystem resolver selection was not proven:\n%s", output)
	}
}

// TestResolverDeliberateBreak proves T3 detects resolver socket access after T1 passes.
func TestResolverDeliberateBreak(t *testing.T) {
	requireSeatbelt(t)
	name := resolverName(t)
	requireResolver(t, "", name, "allowed")
	if !t.Run("T1Prerequisite", TestGameNetwork) {
		t.Fatal("T1 failed; resolver deliberate break was not run")
	}
	requireResolver(t, "profiles/game.sb", name, "denied")
	contents, err := os.ReadFile("profiles/game.sb")
	if err != nil {
		t.Fatal(err)
	}
	broken := string(contents)
	for _, path := range []string{"/var/run/mDNSResponder", "/private/var/run/mDNSResponder"} {
		rule := "(deny network* (literal \"" + path + "\"))"
		if !strings.Contains(broken, rule) {
			t.Fatalf("game profile no longer contains the resolver socket rule %s to deliberately break", rule)
		}
		broken = strings.Replace(broken, rule, "(allow network-outbound (literal \""+path+"\"))", 1)
	}
	brokenPath := filepath.Join(t.TempDir(), "broken.sb")
	err = os.WriteFile(brokenPath, []byte(broken), 0600)
	if err != nil {
		t.Fatal(err)
	}
	requireResolver(t, brokenPath, name, "allowed")
}

// TestMDNSResponder proves the explicit T3 socket denial against the real live service.
func TestMDNSResponder(t *testing.T) {
	requireSeatbelt(t)
	for _, path := range []string{"/var/run/mDNSResponder", "/private/var/run/mDNSResponder"} {
		requireProbe(t, "", "unix", path, "allowed")
		requireProbe(t, "profiles/game.sb", "unix", path, "denied")
	}
}
