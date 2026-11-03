package netguard

import (
	"errors"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"d1preservation/netguard/gate"
)

// listedPort is the port local.sb lists that the positive controls use (d1-localonly's own).
const listedPort = "8789"

// buildLocalOnly builds d1-localonly with root as its build-time repository root, into bin/.
func buildLocalOnly(t *testing.T, root string) string {
	t.Helper()
	launcher := filepath.Join(root, "bin", "d1-localonly")
	command := buildCommand("-ldflags", "-X main.repositoryRoot="+root, "-o", launcher, "./cmd/d1-localonly")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build d1-localonly: %v\n%s", err, output)
	}
	return launcher
}

// fakeLocalRepository builds a repository holding every protected file, runs/, the given text as
// its local.sb (which d1-localonly must ignore), and d1-localonly built for that root. It lives
// in the control directory: inside this repository, outside temporary space.
func fakeLocalRepository(t *testing.T, profile string) (string, string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	files := append(slices.Clone(gate.ProtectedFiles), "notes.md", "containment/notes.md")
	writeTree(t, root, append(files, "runs/.keep", "bin/.keep"))
	err = os.WriteFile(filepath.Join(root, "containment/go/profiles/local.sb"), []byte(profile), 0600)
	if err != nil {
		t.Fatal(err)
	}
	return root, buildLocalOnly(t, root)
}

// writeTree creates each named file under root. Inside the agent sandbox, which refuses some names
// (.git/config, .claude/settings.json) anywhere, a refused file is left out; only tests that apply
// no profile run there, and outside it every file is made.
func writeTree(t *testing.T, root string, names []string) {
	t.Helper()
	for _, name := range names {
		path := filepath.Join(root, name)
		err := os.MkdirAll(filepath.Dir(path), 0700)
		if err == nil {
			err = os.WriteFile(path, []byte("fake\n"), 0600)
		}
		if err != nil && !(seatbeltUnavailable != "" && errors.Is(err, fs.ErrPermission)) {
			t.Fatal(err)
		}
	}
}

// localPolicy is local.sb normalized for root and the account's home, as d1-localonly makes it.
func localPolicy(t *testing.T, profile string, root string) string {
	t.Helper()
	home, err := gate.Home()
	if err != nil {
		t.Fatal(err)
	}
	return gate.NormalizeWith(profile, map[string]string{"REPO": root, "HOME": home})
}

// TestLocalNormalize: the normalized local policy carries no parameter and has the root and home
// in place; game.sb normalizes exactly as before NormalizeWith existed. Pure parsing.
func TestLocalNormalize(t *testing.T) {
	policy := gate.NormalizeWith(LocalProfile, map[string]string{"REPO": "/r", "HOME": "/h"})
	for _, wanted := range []string{`(subpath "/r")`, `(string-append "/r" path)`, `(string-append "/h" "/.cargo/registry")`} {
		if !strings.Contains(policy, wanted) {
			t.Fatalf("the normalized local policy lacks %s: %s", wanted, policy)
		}
	}
	if strings.ContainsAny(policy, ";\n") || strings.Contains(policy, "param") {
		t.Fatalf("the normalized local policy is not one comment-free line with no parameter left: %s", policy)
	}
	game := gate.Normalize(GameProfile, "/r")
	if strings.Contains(game, "string-append") || !strings.Contains(game, `(subpath "/r/runs")`) {
		t.Fatalf("game.sb no longer normalizes to the text the Rust build makes: %s", game)
	}
	if LocalProfile != readProfile(t, "profiles/local.sb") {
		t.Fatal("the embedded profile differs from profiles/local.sb; rebuild")
	}
}

// readProfile reads a profile from disk, so a stale embed is noticed.
func readProfile(t *testing.T, path string) string {
	t.Helper()
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(text)
}

// TestLocalProtectedFiles (drift): the exact paths local.sb denies are gate.ProtectedFiles, every
// directory above one, and the repository itself; nothing more, nothing less. Pure parsing.
func TestLocalProtectedFiles(t *testing.T) {
	var denied []string
	for _, match := range regexp.MustCompile(`\(repo-path "([^"]*)"\)`).FindAllStringSubmatch(sbplRulesOnly(LocalProfile), -1) {
		denied = append(denied, strings.TrimPrefix(match[1], "/"))
	}
	wanted := []string{""}
	for _, name := range gate.ProtectedFiles {
		for path := name; path != "."; path = filepath.Dir(path) {
			wanted = append(wanted, path)
		}
	}
	slices.Sort(denied)
	slices.Sort(wanted)
	wanted = slices.Compact(wanted)
	if !slices.Equal(denied, wanted) {
		t.Fatalf("local.sb's exact denies differ from gate.ProtectedFiles and their directories:\nlocal.sb: %q\nwanted:   %q", denied, wanted)
	}
	if len(wanted) < len(gate.ProtectedFiles)+10 {
		t.Fatal("the drift check found too few paths to mean anything")
	}
}

// TestLocalProtectedTrees (drift): the subpaths local.sb denies are gate.ProtectedTrees, nothing
// more, nothing less, and every directory above one is denied as an exact path as well, so the
// rename around a file rule (the comment above them) is closed for a tree too. Pure parsing.
func TestLocalProtectedTrees(t *testing.T) {
	var denied []string
	for _, match := range regexp.MustCompile(`\(repo-tree "([^"]*)"\)`).FindAllStringSubmatch(sbplRulesOnly(LocalProfile), -1) {
		denied = append(denied, strings.TrimPrefix(match[1], "/"))
	}
	wanted := slices.Clone(gate.ProtectedTrees)
	slices.Sort(denied)
	slices.Sort(wanted)
	if !slices.Equal(denied, wanted) {
		t.Fatalf("local.sb's subpath denies differ from gate.ProtectedTrees:\nlocal.sb: %q\nwanted:   %q", denied, wanted)
	}
	if len(wanted) == 0 {
		t.Fatal("the drift check found no trees to mean anything")
	}
	exact := map[string]bool{}
	for _, match := range regexp.MustCompile(`\(repo-path "([^"]*)"\)`).FindAllStringSubmatch(sbplRulesOnly(LocalProfile), -1) {
		exact[strings.TrimPrefix(match[1], "/")] = true
	}
	for _, tree := range gate.ProtectedTrees {
		for path := filepath.Dir(tree); path != "."; path = filepath.Dir(path) {
			if !exact[path] {
				t.Errorf("local.sb denies the tree %s but not its parent %s as an exact path, so %s could be renamed", tree, path, path)
			}
		}
	}
}

// sbplRulesOnly drops comments and the define line, leaving the rules that use repo-path.
func sbplRulesOnly(profile string) string {
	var rules []string
	for _, line := range strings.Split(profile, "\n") {
		rule, _, _ := strings.Cut(line, ";")
		if !strings.HasPrefix(rule, "(define") {
			rules = append(rules, rule)
		}
	}
	return strings.Join(rules, "\n")
}

// TestLocalOnlyRuns is the positive control and its negative: a command runs; a listen and
// connect on 127.0.0.1 at a listed port carries a byte; the same at an unlisted port is refused.
// A launcher built without a repository root refuses before it applies anything.
func TestLocalOnlyRuns(t *testing.T) {
	requireSeatbelt(t)
	_, launcher := fakeLocalRepository(t, LocalProfile)
	output, status := run(t, nil, nil, launcher, "/bin/echo", "contained")
	if status != 0 || !strings.Contains(output, "contained") {
		t.Fatalf("d1-localonly did not run the command: status %d", status)
	}
	output, status = run(t, nil, nil, launcher, gatePath, "loopback", "127.0.0.1", listedPort, "allowed")
	if status != 0 || !strings.Contains(output, "loopback exchange completed") {
		t.Fatalf("a loopback connection on listed port %s did not work: status %d", listedPort, status)
	}
	output, status = run(t, nil, nil, launcher, gatePath, "loopback", "127.0.0.1", "48124", "denied")
	if status != 0 || !strings.Contains(output, "refused by policy") {
		t.Fatalf("a loopback connection on an unlisted port was not refused: status %d", status)
	}
	unrooted := filepath.Join(t.TempDir(), "d1-localonly")
	log, err := buildCommand("-o", unrooted, "./cmd/d1-localonly").CombinedOutput()
	if err != nil {
		t.Fatalf("build: %v\n%s", err, log)
	}
	output, status = run(t, nil, nil, unrooted, "/bin/echo", "contained")
	if status != 2 || !strings.Contains(output, "repository root") || strings.Contains(output, "\ncontained") {
		t.Fatalf("a launcher built without a repository root did not refuse: status %d", status)
	}
}

// TestLocalOnlyGameBinary: a game binary is refused up front (exit 64), naming d1-nonet.
func TestLocalOnlyGameBinary(t *testing.T) {
	_, launcher := fakeLocalRepository(t, LocalProfile)
	output, status := run(t, nil, nil, launcher, "/x/d1-server/target/release/d1-recomp", "--help")
	if status != 64 || !strings.Contains(output, "run it under d1-nonet") {
		t.Fatalf("a game binary was not refused up front: status %d", status)
	}
}

// TestLocalOnlySabotage runs the prove step under local.sb with one rule removed; it must exit 2
// naming the probe that rule served. The unmodified policy passes, in the same test.
func TestLocalOnlySabotage(t *testing.T) {
	requireSeatbelt(t)
	home, err := gate.Home()
	if err != nil {
		t.Fatal(err)
	}
	root, launcher := fakeLocalRepository(t, LocalProfile)
	_, status := proveUnder(t, localPolicy(t, LocalProfile, root), launcher, nil)
	if status != 0 {
		t.Fatalf("the prove step refused the embedded policy: status %d", status)
	}
	cases := []struct {
		name   string
		remove func(line string) bool
		named  string
	}{
		{"network", prefixed("(deny network*) "), "tcp 192.0.2.1:443: "},
		{"outbound", prefixed("(allow network-outbound "), "tcp 127.0.0.1:" + listedPort + " (a listed port): refused"},
		{"bind", prefixed("(allow network-bind "), "bind 127.0.0.1:0: refused"},
		{"socket-options", prefixed("(deny socket-option-set "), "setsockopt IP_MULTICAST_TTL: succeeded"},
		{"protected", containing(`(repo-path "/CLAUDE.md")`), "write " + filepath.Join(root, "CLAUDE.md") + ": succeeded"},
		{"home", prefixed("(deny file-write*) "), "write " + home + ": succeeded"},
		{"exec", prefixed("(deny process-exec "), "exec /usr/bin/osascript: succeeded"},
	}
	for _, sabotage := range cases {
		t.Run(sabotage.name, func(t *testing.T) {
			policy := localPolicy(t, removeLines(t, LocalProfile, sabotage.remove), root)
			output, status := proveUnder(t, policy, launcher, nil)
			if status != 2 || !strings.Contains(output, sabotage.named) {
				t.Fatalf("the sabotaged policy was not refused naming %q: status %d", sabotage.named, status)
			}
		})
	}
}

// TestLocalOnlyIgnoresRepositoryProfile is the selective-allowance control: a fake repository's
// local.sb admitting one extra port is ignored. The weakening is shown to be real first, then a
// command under d1-localonly built for that repository still cannot reach the port.
func TestLocalOnlyIgnoresRepositoryProfile(t *testing.T) {
	requireSeatbelt(t)
	listenSelective(t)
	weakened := LocalProfile + selectiveAllowance
	root, launcher := fakeLocalRepository(t, weakened)
	requirePolicyProbe(t, localPolicy(t, weakened, root), "network", "connect", "127.0.0.1", selectivePort, "allowed")
	output, status := run(t, nil, nil, launcher, gatePath, "network", "connect", "127.0.0.1", selectivePort, "denied")
	if status != 0 || !strings.Contains(output, "refused by policy") {
		t.Fatalf("d1-localonly applied the repository's profile instead of its embedded one: status %d", status)
	}
}

// TestLocalOnlyInheritedSocket (T7): a socket at descriptor 10 refuses the prove step; the
// launcher marks it close-on-exec, so the same launch through d1-localonly runs; a socket on
// stdout refuses.
func TestLocalOnlyInheritedSocket(t *testing.T) {
	requireSeatbelt(t)
	root, launcher := fakeLocalRepository(t, LocalProfile)
	files := make([]*os.File, 8)
	files[7] = socketFile(t)
	output, status := proveUnder(t, localPolicy(t, LocalProfile, root), launcher, files)
	if status != 2 || !strings.Contains(output, "descriptor 10: socket") {
		t.Fatalf("an inherited socket at descriptor 10 was not refused: status %d", status)
	}
	_, status = run(t, nil, files, launcher, "/usr/bin/true")
	if status != 0 {
		t.Fatalf("the launcher handed an inherited socket on to the prove step: status %d", status)
	}
	output, status = run(t, socketFile(t), nil, launcher, "/usr/bin/true")
	if status != 2 || !strings.Contains(output, "stdout: socket") {
		t.Fatalf("a socket on stdout was not refused: status %d", status)
	}
}

// TestLocalOnlyNamedFiles: under the policy, creating a protected file that does not exist, and
// writing, renaming and unlinking one that does, are refused and of unprotected files beside them allowed; renaming a directory above a
// protected file is refused, and renaming one that holds none is allowed.
func TestLocalOnlyNamedFiles(t *testing.T) {
	requireSeatbelt(t)
	root, _ := fakeLocalRepository(t, LocalProfile)
	policy := localPolicy(t, LocalProfile, root)
	at := func(name string) string {
		return filepath.Join(root, name)
	}
	for _, absent := range []string{"AGENTS.md", ".cargo/config.toml"} {
		err := os.Remove(at(absent))
		if err != nil {
			t.Fatal(err)
		}
	}
	requirePolicyProbe(t, policy, "mutate", "denied", at("AGENTS.md"), at("CLAUDE.md"), at("CLAUDE.renamed"))
	requirePolicyProbe(t, policy, "mutate", "denied", at(".cargo/config.toml"), at("containment/c/d1netgate.c"), at("containment/c/x.c"))
	requirePolicyProbe(t, policy, "mutate", "allowed", at("new.md"), at("notes.md"), at("notes.renamed"))
	requirePolicyProbe(t, policy, "mutate", "allowed", at("containment/new.md"), at("containment/notes.md"), at("containment/notes.renamed"))
	requirePolicyProbe(t, policy, "rename", at("containment"), at("containment.x"), "denied")
	requirePolicyProbe(t, policy, "rename", at("containment/go/profiles"), at("containment/go/p"), "denied")
	requirePolicyProbe(t, policy, "rename", at("runs"), at("runs.x"), "allowed")
}

// TestLocalOnlyBinds documents what Seatbelt cannot do: under local.sb a bind to 0.0.0.0 and to
// this Mac's LAN address is allowed, like one to 127.0.0.1, so loopback-only listening is not
// kernel-enforced. With the bind rule removed, the bind to 127.0.0.1 is refused: the probe can
// see a refusal. If macOS starts refusing these binds, this test fails and the docs change.
func TestLocalOnlyBinds(t *testing.T) {
	requireSeatbelt(t)
	root, _ := fakeLocalRepository(t, LocalProfile)
	policy := localPolicy(t, LocalProfile, root)
	addresses := []string{"127.0.0.1", "0.0.0.0"}
	lan := lanAddress(t)
	if lan != "" {
		addresses = append(addresses, lan)
	}
	for _, address := range addresses {
		requirePolicyProbe(t, policy, "bind", address, "allowed")
	}
	unbound := localPolicy(t, removeLines(t, LocalProfile, prefixed("(allow network-bind ")), root)
	requirePolicyProbe(t, unbound, "bind", "127.0.0.1", "denied")
}

// lanAddress is this Mac's first up, non-loopback IPv4 address, or "" if it has none.
func lanAddress(t *testing.T) string {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range interfaces {
		if device.Flags&net.FlagUp == 0 || device.Flags&net.FlagLoopback != 0 {
			continue
		}
		assigned, _ := device.Addrs()
		for _, network := range assigned {
			prefix, err := netip.ParsePrefix(network.String())
			if err == nil && prefix.Addr().Is4() && prefix.Addr().IsGlobalUnicast() {
				return prefix.Addr().String()
			}
		}
	}
	t.Log("no LAN IPv4 address on this Mac; the LAN bind is not shown")
	return ""
}
