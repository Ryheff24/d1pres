// Command d1-localonly runs one command kept to this Mac: d1-localonly CMD [ARGS...]. It is for
// the servers, their tests and tools that talk to them; game code runs under d1-nonet. The
// reviewed profile, profiles/local.sb, is embedded at build time, and so is the repository root
// (-ldflags "-X main.repositoryRoot=<root>"), so nothing found at run time selects the policy or
// what it lets the command write. It cleans up its descriptors and environment, runs its prove
// step as a child under the profile and requires it to pass, then replaces itself with
// sandbox-exec applying the same text to CMD, which inherits it and cannot lift it. The applied
// kernel policy contains the process; the probes check selected properties of it.
//
// Exit status: 2 refusal (one REFUSED line on stderr), 64 usage or a game binary, 127 CMD not
// found, else CMD's. "d1-localonly --prove" is the child: it prints its failed items on one line
// and exits 2, or exits 0. It never runs a command.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"d1preservation/netguard"
	"d1preservation/netguard/gate"
)

// repositoryRoot is set at build time; gate.CheckRoot refuses it empty or wrong.
var repositoryRoot string

const proveFlag = "--prove"

// listedPort is the port local.sb lists that the positive control aims at: d1-forge's second
// control plane, which nothing else on this Mac uses.
const listedPort = 8789

// main picks the launcher or the prove step. SIGPIPE is ignored so a closed stderr cannot stop
// a refusal short of exit 2. A socket on stderr exits 2 silently: the refusal cannot be written
// through the thing being refused.
func main() {
	signal.Ignore(syscall.SIGPIPE)
	if gate.IsSocket(2) {
		os.Exit(2)
	}
	arguments := os.Args[1:]
	if len(arguments) == 1 && arguments[0] == proveFlag {
		prove()
	}
	if len(arguments) == 0 || arguments[0] == proveFlag {
		fmt.Fprintln(os.Stderr, "usage: d1-localonly CMD [ARGS...]\n  runs CMD kept to this Mac: connections only to the servers' loopback ports, no multicast,\n  writes only to temporary space, the repository (never its protected files) and cargo's caches")
		os.Exit(64)
	}
	if slices.Contains(gate.GameBinaries, filepath.Base(arguments[0])) {
		fmt.Fprintln(os.Stderr, gate.OneLine("d1-localonly: "+filepath.Base(arguments[0])+" runs game code; run it under d1-nonet, whose policy its own gate requires"))
		os.Exit(64)
	}
	launch(arguments)
}

// refuse prints the REFUSED line naming the command and every failure, then exits 2.
func refuse(command string, failures []string) {
	fmt.Fprintln(os.Stderr, gate.Refusal("d1-localonly", command, failures))
	os.Exit(2)
}

// launch runs outside the profile: hygiene, the policy, the command's path, the prove child
// under the policy, then sandbox-exec with the same policy and CMD.
func launch(arguments []string) {
	command := arguments[0]
	failures := gate.Hygiene()
	if len(failures) > 0 {
		refuse(command, failures)
	}
	policy, err := localPolicy()
	if err != nil {
		refuse(command, []string{err.Error()})
	}
	self, err := gate.Executable()
	if err != nil {
		refuse(command, []string{"its own path: " + err.Error()})
	}
	resolved, err := exec.LookPath(command)
	if err != nil {
		fmt.Fprintln(os.Stderr, gate.OneLine(fmt.Sprintf("d1-localonly: cannot run %q: %v", command, err)))
		os.Exit(127)
	}
	environment := gate.CleanEnvironment()
	why := gate.ProveUnder(policy, self, proveFlag, environment)
	if why != "" {
		refuse(command, []string{why})
	}
	commandLine := append([]string{gate.SandboxExec, "-p", policy, "--", resolved}, arguments[1:]...)
	err = syscall.Exec(gate.SandboxExec, commandLine, environment)
	refuse(command, []string{"sandbox-exec: " + err.Error()})
}

// localPolicy is local.sb with the build's repository root for REPO and the account's home for
// HOME, both checked before they are put into the text.
func localPolicy() (string, error) {
	err := gate.CheckRoot(repositoryRoot)
	if err != nil {
		return "", fmt.Errorf("repository root: %w", err)
	}
	home, err := gate.Home()
	if err != nil {
		return "", fmt.Errorf("home directory: %w", err)
	}
	parameters := map[string]string{"REPO": repositoryRoot, "HOME": home}
	return gate.NormalizeWith(netguard.LocalProfile, parameters), nil
}

// prove runs inside the profile as the launcher's child. Nothing may leave this Mac (checked
// first, stopping at the first leak); then every refusal must hold and every positive control
// must pass. The Mach denies need cgo to probe and are not checked here. It prints the failed
// items on one line and exits 2, or exits 0.
func prove() {
	home, err := gate.Home()
	if err != nil {
		fmt.Fprintln(os.Stderr, gate.OneLine("home directory: "+err.Error()))
		os.Exit(2)
	}
	failures := gate.BeyondThisMac()
	if len(failures) == 0 {
		failures = append(failures, gate.NoOpenSockets()...)
		failures = append(failures, gate.NoNetwork()...)
		failures = append(failures, gate.LoopbackOpen(listedPort)...)
		failures = append(failures, gate.LocalSocketOptions()...)
		failures = append(failures, gate.Writes(deniedWrites(home), filepath.Join(repositoryRoot, "runs"))...)
		failures = append(failures, gate.Execs([]string{"/usr/bin/open", "/usr/bin/osascript"})...)
	}
	if len(failures) > 0 {
		fmt.Fprintln(os.Stderr, gate.OneLine(strings.Join(failures, ", ")))
		os.Exit(2)
	}
	os.Exit(0)
}

// deniedWrites lists the paths the write probe must find refused: the home directory, each
// protected file that exists (CLAUDE.md always does: CheckRoot requires it), and, where they
// exist, Claude Code's settings and the toolchain. A missing path proves nothing, so it is left out.
func deniedWrites(home string) []string {
	paths := []string{home}
	candidates := []string{filepath.Join(home, ".claude", "settings.json"), filepath.Join(home, ".rustup", "toolchains")}
	for _, name := range gate.ProtectedFiles {
		candidates = append(candidates, filepath.Join(repositoryRoot, name))
	}
	for _, path := range candidates {
		_, err := os.Stat(path)
		if err == nil {
			paths = append(paths, path)
		}
	}
	return paths
}
