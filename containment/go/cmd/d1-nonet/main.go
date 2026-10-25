// Command d1-nonet runs one command with no network: d1-nonet CMD [ARGS...]. The reviewed
// profile, profiles/game.sb, is embedded at build time, so no file found at run time selects
// the policy. It cleans up its descriptors and environment, runs its prove step as a child
// under the profile and requires it to pass, then replaces itself with sandbox-exec applying
// the same text to CMD, which inherits it and cannot lift it. The applied kernel policy
// contains the process; the probes check selected properties of it.
//
// Exit status: 2 refusal (one REFUSED line on stderr), 64 usage, 127 CMD not found, else CMD's.
// "d1-nonet --prove" is the child: it prints its failed items on one line and exits 2, or exits
// 0. It never runs a command, so it cannot start one without the launcher's own apply.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"unicode"

	"d1preservation/netguard"
	"d1preservation/netguard/gate"
)

const proveFlag = "--prove"
const sandboxExec = "/usr/bin/sandbox-exec"

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
		fmt.Fprintln(os.Stderr, "usage: d1-nonet CMD [ARGS...]\n  runs CMD with no network: no sockets, no socket options, writes only to temporary space and runs/")
		os.Exit(64)
	}
	launch(arguments)
}

// refuse prints the REFUSED line naming the command and every failure, then exits 2.
func refuse(command string, failures []string) {
	fmt.Fprintln(os.Stderr, gate.Refusal("d1-nonet", command, failures))
	os.Exit(2)
}

// launch runs outside the profile: hygiene, the repository (for runs/ only), the command's path,
// the prove child under the embedded policy, then sandbox-exec with the same policy and CMD.
func launch(arguments []string) {
	command := arguments[0]
	failures := gate.Hygiene()
	if len(failures) > 0 {
		refuse(command, failures)
	}
	root, err := locate()
	if err != nil {
		refuse(command, []string{"repository: " + err.Error()})
	}
	self, err := executable()
	if err != nil {
		refuse(command, []string{"its own path: " + err.Error()})
	}
	resolved, err := exec.LookPath(command)
	if err != nil {
		fmt.Fprintln(os.Stderr, gate.OneLine(fmt.Sprintf("d1-nonet: cannot run %q: %v", command, err)))
		os.Exit(127)
	}
	policy := gate.Normalize(netguard.GameProfile, root)
	environment := cleanEnvironment()
	why := proveUnder(policy, self, environment)
	if why != "" {
		refuse(command, []string{why})
	}
	commandLine := append([]string{sandboxExec, "-p", policy, "--", resolved}, arguments[1:]...)
	err = syscall.Exec(sandboxExec, commandLine, environment)
	refuse(command, []string{"sandbox-exec: " + err.Error()})
}

// proveUnder runs this binary's prove step as a child under policy. It returns "" if the child
// passed, its failed items if it refused (exit 2), else why the profile did not apply.
func proveUnder(policy string, self string, environment []string) string {
	child := exec.Command(sandboxExec, "-p", policy, "--", self, proveFlag)
	child.Env = environment
	output, err := child.CombinedOutput()
	text := strings.Join(strings.Fields(string(output)), " ")
	var exit *exec.ExitError
	if err == nil {
		return ""
	}
	if errors.As(err, &exit) && exit.ExitCode() == 2 && text != "" {
		return text
	}
	if strings.Contains(text, "Operation not permitted") {
		return "sandbox-exec: could not apply its profile (a Seatbelt profile cannot be applied inside another sandbox unless it is the same profile)"
	}
	return "sandbox-exec: could not apply its profile (" + text + " " + err.Error() + ")"
}

// cleanEnvironment is the environment without loader and Go runtime controls (DYLD_*, LD_*,
// GODEBUG*, GOTRACEBACK*), for sandbox-exec, the prove child and the command. It cannot protect
// this launcher's own startup, which runs before main: that is the hook and install path's contract.
func cleanEnvironment() []string {
	var kept []string
	for _, variable := range os.Environ() {
		removed := false
		for _, prefix := range []string{"DYLD_", "LD_", "GODEBUG", "GOTRACEBACK"} {
			removed = removed || strings.HasPrefix(variable, prefix)
		}
		if !removed {
			kept = append(kept, variable)
		}
	}
	return kept
}

// prove runs inside the profile as the launcher's child: every check Go can attempt without cgo
// must be refused; the Mach denies are checked by the C gate inside each game process instead.
// It prints the failed items on one line and exits 2, or exits 0. The home directory comes from
// the account database (gate.Home), not $HOME, so a caller cannot point the probe elsewhere.
func prove() {
	root, err := locate()
	if err != nil {
		fmt.Fprintln(os.Stderr, gate.OneLine("repository: "+err.Error()))
		os.Exit(2)
	}
	home, err := gate.Home()
	if err != nil {
		fmt.Fprintln(os.Stderr, gate.OneLine("home directory: "+err.Error()))
		os.Exit(2)
	}
	protected := []string{home}
	for _, name := range []string{"CLAUDE.md", "containment", "design", "d1-server/crates", ".git"} {
		protected = append(protected, filepath.Join(root, name))
	}
	failures := gate.NoOpenSockets()
	failures = append(failures, gate.NoNetwork()...)
	failures = append(failures, gate.NoSocketOptions()...)
	failures = append(failures, gate.Writes(protected, "/private/tmp")...)
	failures = append(failures, gate.Execs([]string{"/usr/bin/open", "/usr/bin/osascript"})...)
	if len(failures) > 0 {
		fmt.Fprintln(os.Stderr, gate.OneLine(strings.Join(failures, ", ")))
		os.Exit(2)
	}
	os.Exit(0)
}

// locate finds the repository root, which selects only runs/ and the protected paths, never the
// policy. It is refused under temporary space, where the profile lets game code write, and if it
// holds a character the policy text cannot carry unescaped (gate.Normalize).
func locate() (string, error) {
	root := findRoot()
	if root == "" {
		return "", errors.New("no directory holding CLAUDE.md and containment/ above this binary or the current directory")
	}
	if strings.ContainsAny(root, "\"\\") || strings.IndexFunc(root, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("%q contains a double quote, a backslash or a control character", root)
	}
	for _, temporary := range []string{"/private/tmp", "/private/var/folders"} {
		if root == temporary || strings.HasPrefix(root, temporary+"/") {
			return "", fmt.Errorf("%s is under %s, where the profile lets game code write", root, temporary)
		}
	}
	return root, nil
}

// findRoot walks up from this binary's directory, then from the current directory, to the first
// directory holding CLAUDE.md and containment/. Paths are resolved first: Seatbelt matches
// resolved paths, so /tmp must read as /private/tmp.
func findRoot() string {
	var starts []string
	self, err := executable()
	if err == nil {
		starts = append(starts, filepath.Dir(self))
	}
	current, err := os.Getwd()
	if err == nil {
		starts = append(starts, current)
	}
	for _, start := range starts {
		directory, err := filepath.EvalSymlinks(start)
		for err == nil {
			if isRoot(directory) {
				return directory
			}
			if directory == filepath.Dir(directory) {
				break
			}
			directory = filepath.Dir(directory)
		}
	}
	return ""
}

// isRoot reports whether directory holds a CLAUDE.md file and a containment directory.
func isRoot(directory string) bool {
	instructions, err := os.Stat(filepath.Join(directory, "CLAUDE.md"))
	containment, containmentError := os.Stat(filepath.Join(directory, "containment"))
	return err == nil && containmentError == nil && instructions.Mode().IsRegular() && containment.IsDir()
}

// executable is this binary's own path with symbolic links resolved.
func executable() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(path)
}
