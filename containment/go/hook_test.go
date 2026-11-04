package netguard

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"d1preservation/netguard/gate"
	"d1preservation/netguard/hook"
)

// The hook's decision tests are in hook/decide_test.go, where they run under d1-nonet with the
// rest of the hook package. TestHookBinary stays here, because it builds the hook (buildCommand).

// fakeHookTree builds a repository holding every protected file and two unprotected ones, a home
// directory with .claude/settings.json, and a launcher directory holding the three binaries as
// files (owned by the test's user, so never trusted). AGENTS.md is left absent.
func fakeHookTree(t *testing.T) hook.Config {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	config := hook.Config{Root: filepath.Join(base, "repo"), Home: filepath.Join(base, "home"), LauncherDirectory: filepath.Join(base, "libexec", "d1-agent")}
	var files []string
	for _, name := range gate.ProtectedFiles {
		if name != "AGENTS.md" {
			files = append(files, filepath.Join("repo", name))
		}
	}
	files = append(files, "repo/notes.md", "repo/containment/notes.md", "home/.claude/settings.json")
	for _, name := range []string{"d1-nonet", "d1-localonly", "d1-agent-hook"} {
		files = append(files, filepath.Join("libexec", "d1-agent", name))
	}
	writeTree(t, base, files)
	return config
}

// editEvent is an edit-tool PreToolUse event for one path.
func editEvent(t *testing.T, tool string, path string, cwd string) []byte {
	t.Helper()
	field := "file_path"
	if tool == "NotebookEdit" {
		field = "notebook_path"
	}
	return marshal(t, map[string]any{"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": map[string]any{field: path}, "cwd": cwd})
}

// marshal is json.Marshal that fails the test on error.
func marshal(t *testing.T, value any) []byte {
	t.Helper()
	text, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return text
}

// TestHookBinary: the built hook blocks with exit 2 and one BLOCKED line on garbage, on an edit of
// a protected file and on any argument; it admits an edit beside it with exit 0; "settings" prints
// JSON naming the installed path; a hook built without a repository root blocks everything.
func TestHookBinary(t *testing.T) {
	config := fakeHookTree(t)
	binary := filepath.Join(filepath.Dir(config.Root), "d1-agent-hook")
	log, err := buildCommand("-ldflags", "-X main.repositoryRoot="+config.Root, "-o", binary, "./cmd/d1-agent-hook").CombinedOutput()
	if err != nil {
		t.Fatalf("build: %v\n%s", err, log)
	}
	unrooted := binary + "-unrooted"
	log, err = buildCommand("-o", unrooted, "./cmd/d1-agent-hook").CombinedOutput()
	if err != nil {
		t.Fatalf("build: %v\n%s", err, log)
	}
	cases := []struct {
		binary    string
		arguments []string
		event     []byte
		status    int
		output    string
	}{
		{binary, nil, []byte("garbage"), 2, "d1-agent-hook: BLOCKED - the event is not one this hook can read"},
		{binary, nil, editEvent(t, "Edit", config.Root+"/claude.md", "/"), 2, "is protected"},
		{binary, nil, editEvent(t, "Edit", config.Root+"/notes.md", "/"), 0, ""},
		{binary, []string{"sandbox-off"}, editEvent(t, "Edit", config.Root+"/notes.md", "/"), 2, "unknown arguments"},
		{binary, []string{"settings"}, nil, 0, `"command": "/usr/local/libexec/d1-agent/d1-agent-hook"`},
		{unrooted, nil, editEvent(t, "Edit", config.Root+"/notes.md", "/"), 2, "built without a valid repository root"},
	}
	for _, test := range cases {
		command := exec.Command(test.binary, test.arguments...)
		command.Stdin = strings.NewReader(string(test.event))
		command.Env = append(os.Environ(), "CLAUDE_PROJECT_DIR="+config.Root)
		output, _ := command.CombinedOutput()
		status := command.ProcessState.ExitCode()
		if status != test.status || !strings.Contains(string(output), test.output) || test.status == 2 && strings.Count(string(output), "\n") != 1 {
			t.Errorf("%s %q: wanted status %d and %q, got %d:\n%s", filepath.Base(test.binary), test.arguments, test.status, test.output, status, output)
		}
	}
	if !slices.Contains(gate.ProtectedFiles, "containment/go/cmd/d1-agent-hook/main.go") {
		t.Error("the hook's own source is not protected")
	}
}
