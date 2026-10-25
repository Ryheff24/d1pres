package gate

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"unicode"
)

// SandboxExec applies a profile to the command it runs; the profile is inherited and cannot be lifted.
const SandboxExec = "/usr/bin/sandbox-exec"

// CheckParameter refuses a value the policy text cannot carry unescaped (NormalizeWith does not
// escape): a double quote, a backslash or a control character.
func CheckParameter(value string) error {
	if strings.ContainsAny(value, "\"\\") || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("%q contains a double quote, a backslash or a control character", value)
	}
	return nil
}

// CheckRoot accepts root, set at build time, as this repository's root: a clean absolute path
// holding a CLAUDE.md file and a containment directory, outside temporary space (where game code
// may write, so a planted copy there could pose as the repository), and a valid parameter.
func CheckRoot(root string) error {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return fmt.Errorf("%q is not a clean absolute path (build with -ldflags \"-X main.repositoryRoot=<root>\")", root)
	}
	err := CheckParameter(root)
	if err != nil {
		return err
	}
	for _, temporary := range []string{"/private/tmp", "/private/var/folders"} {
		if root == temporary || strings.HasPrefix(root, temporary+"/") {
			return fmt.Errorf("%s is under %s, where game code may write", root, temporary)
		}
	}
	instructions, err := os.Stat(filepath.Join(root, "CLAUDE.md"))
	containment, containmentError := os.Stat(filepath.Join(root, "containment"))
	if err != nil || containmentError != nil || !instructions.Mode().IsRegular() || !containment.IsDir() {
		return fmt.Errorf("%s does not hold CLAUDE.md and containment/", root)
	}
	return nil
}

// Home is the account's home directory from the account database (getpwuid through libSystem,
// which Go reaches on macOS without cgo), not $HOME, which a caller can set.
func Home() (string, error) {
	account, err := user.Current()
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(account.HomeDir) {
		return "", fmt.Errorf("the account database gives %q, not an absolute path", account.HomeDir)
	}
	return account.HomeDir, CheckParameter(account.HomeDir)
}

// Executable is this binary's own path with symbolic links resolved.
func Executable() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(path)
}

// CleanEnvironment is the environment without loader and Go runtime controls (DYLD_*, LD_*,
// GODEBUG*, GOTRACEBACK*), for sandbox-exec, the prove child and the command. It cannot protect
// the launcher's own startup, which runs before main: the hook admits a launcher only from a
// command line that adds no such variable (containment/README.md, the entry contract).
func CleanEnvironment() []string {
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

// ProveUnder runs self with proveFlag as a child under policy. It returns "" if the child passed,
// its failed items if it refused (exit 2), else why the profile did not apply. The child never
// runs a command, so it cannot start one without the launcher's own apply.
func ProveUnder(policy string, self string, proveFlag string, environment []string) string {
	child := exec.Command(SandboxExec, "-p", policy, "--", self, proveFlag)
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
