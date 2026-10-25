package netguard

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

var controlDirectory string
var gatePath string
var brokerSocketPath string
var repositoryRoot string
var seatbeltUnavailable string

// TestMain builds a Go-only helper once and keeps all generated files in the workspace.
func TestMain(tests *testing.M) {
	os.Exit(runTests(tests))
}

// runTests cleans up even on failure, without writing to the system temporary directory.
func runTests(tests *testing.M) int {
	workspace, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	controlDirectory, err = os.MkdirTemp(workspace, ".p-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(controlDirectory)
	for name, value := range map[string]string{
		"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOFLAGS": "-mod=mod",
		"GOCACHE": filepath.Join(workspace, ".gocache"), "CGO_ENABLED": "0",
		"TMPDIR": controlDirectory,
	} {
		err = os.Setenv(name, value)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	repositoryRoot, err = filepath.EvalSymlinks(filepath.Join(workspace, "..", ".."))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	err = buildHelpers()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	err = checkSeatbelt()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return tests.Run()
}

// buildHelpers builds the probe helper and d1-nonet once, into the control directory.
func buildHelpers() error {
	gatePath = filepath.Join(controlDirectory, "gate")
	nonetPath = filepath.Join(controlDirectory, "d1-nonet")
	brokerSocketPath = filepath.Join(controlDirectory, "a")
	for output, source := range map[string]string{gatePath: "./testdata/probe", nonetPath: "./cmd/d1-nonet"} {
		command := exec.Command("go", "build", "-o", output, source)
		log, err := command.CombinedOutput()
		if err != nil {
			return fmt.Errorf("build %s: %w\n%s", source, err, log)
		}
	}
	return nil
}

// checkSeatbelt applies a trivial profile once. Inside another sandbox, the agent's included,
// that fails with "Operation not permitted"; every test that applies a profile then skips
// instead of failing. Any other failure is left for the tests to report.
func checkSeatbelt() error {
	trivialPath := filepath.Join(controlDirectory, "trivial.sb")
	err := os.WriteFile(trivialPath, []byte("(version 1)(allow default)"), 0600)
	if err != nil {
		return err
	}
	output, err := exec.Command("/usr/bin/sandbox-exec", "-f", trivialPath, "/usr/bin/true").CombinedOutput()
	if err != nil && strings.Contains(string(output), "Operation not permitted") {
		seatbeltUnavailable = strings.TrimSpace(string(output))
	}
	return nil
}

// requireSeatbelt skips a test that applies a profile where no profile can be applied.
func requireSeatbelt(t *testing.T) {
	t.Helper()
	if seatbeltUnavailable != "" {
		t.Skipf("no Seatbelt profile can be applied inside this sandbox (%s); run these tests outside it", seatbeltUnavailable)
	}
}

// probe applies profiles using separate -D arguments, never interpolating profile text.
func probe(profilePath string, arguments ...string) (string, error) {
	return probeWithFiles(profilePath, nil, arguments...)
}

// probeWithFiles is probe with extra inherited descriptors, the first at descriptor 3.
func probeWithFiles(profilePath string, files []*os.File, arguments ...string) (string, error) {
	if profilePath == "" {
		return runProbe(nil, files, arguments)
	}
	parameters := []string{
		"-f", profilePath, "-D", "BROKER_SOCKET=" + brokerSocketPath, "-D", "REPO=" + repositoryRoot,
	}
	return runProbe(parameters, files, arguments)
}

// probePolicy applies policy text with sandbox-exec -p, the form d1-nonet uses, then the helper.
func probePolicy(policy string, arguments ...string) (string, error) {
	return runProbe([]string{"-p", policy, "--"}, nil, arguments)
}

// runProbe runs the helper, under sandbox-exec with sandboxArguments when there are any.
func runProbe(sandboxArguments []string, files []*os.File, arguments []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	executable := gatePath
	if len(sandboxArguments) > 0 {
		executable = "/usr/bin/sandbox-exec"
		arguments = append(append(slices.Clone(sandboxArguments), gatePath), arguments...)
	}
	command := exec.CommandContext(ctx, executable, arguments...)
	command.ExtraFiles = files
	// +2 prints both the selected resolver and the lookup order for the supplied name.
	command.Env = append(os.Environ(), "GODEBUG=netdns=cgo+2")
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		return string(output), fmt.Errorf("probe timed out: %w", ctx.Err())
	}
	return string(output), err
}

// requirePolicyProbe is requireProbe for policy text.
func requirePolicyProbe(t *testing.T, policy string, arguments ...string) string {
	t.Helper()
	requireSeatbelt(t)
	output, err := probePolicy(policy, arguments...)
	t.Logf("policy=%q arguments=%q\n%s", policy, arguments, output)
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	return output
}

// requireProbe treats setup failures as failures too, so containment is never silently skipped.
func requireProbe(t *testing.T, profilePath string, arguments ...string) string {
	t.Helper()
	if profilePath != "" {
		requireSeatbelt(t)
	}
	output, err := probe(profilePath, arguments...)
	t.Logf("profile=%q arguments=%q\n%s", profilePath, arguments, output)
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	return output
}
