package hook

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPR9Regression covers R1-R5 in REVIEW-codex-pr9-2026-11-03.md. These are
// requirements, not snapshots of the vulnerable decisions: an admitted unsafe
// form fails. Commands are event data only; no shell, agent, game or server runs.
// Like the other hook tests, build this package and run its binary under d1-nonet.
func TestPR9Regression(t *testing.T) {
	t.Run("R1_CodexOptions", func(t *testing.T) {
		config := fakeTree(t)
		pr9CheckCommands(t, config, config.Root, false, []pr9Command{
			{"readonly_control", "codex exec -s read-only -", false},
			{"workspace_write_control", "codex exec -s workspace-write -", false},
			{"unquoted_bypass_control", "codex exec --dangerously-bypass-approvals-and-sandbox -", true},
			{"quoted_bypass", "codex exec '--dangerously-bypass-approvals-and-sandbox' -", true},
			{"attached_sandbox", "codex exec -sdanger-full-access -", true},
			{"attached_configuration", "codex exec -csandbox_mode=danger-full-access -", true},
		})
	})

	t.Run("R2_OutputExpansion", func(t *testing.T) {
		config := fakeTree(t)
		// The path is checked before any shell expansion. HOME is never read or
		// changed here: an unresolved expansion must not count as a literal path
		// in the repository, whatever the actual session's HOME happens to be.
		pr9CheckCommands(t, config, config.Root, false, []pr9Command{
			{"relative_output_control", "codex exec -s read-only -o docs/result.md -", false},
			{"quoted_output_control", "codex exec -s read-only -o 'docs/result with spaces.md' -", false},
			{"outside_output_control", "codex exec -s read-only -o " + filepath.Join(config.Home, "result.md") + " -", true},
			{"expanded_home", "codex exec -s read-only -o $HOME/.zshrc -", true},
		})
	})

	t.Run("R3_WorktreeCase", func(t *testing.T) {
		config := fakeTree(t)
		relative := "runs/wt-demo/d1-server/crates/d1-recomp/src/main.rs"
		writeTree(t, config.Root, []string{relative, "runs/wt-demo/notes.md"})
		original, err := os.Stat(filepath.Join(config.Root, relative))
		if err != nil {
			t.Fatal(err)
		}
		for _, prefix := range []string{"runs/wt-demo", "RUNS/wt-demo", "runs/WT-demo"} {
			t.Run(prefix, func(t *testing.T) {
				path := filepath.Join(config.Root, prefix, "d1-server/crates/d1-recomp/src/main.rs")
				alias, err := os.Stat(path)
				if err != nil {
					t.Fatalf("resolve case variant on the macOS fixture volume: %v", err)
				}
				if !os.SameFile(original, alias) {
					t.Fatal("the case variants must identify the same fixture file")
				}
				for _, tool := range []string{"Edit", "Write", "apply_patch"} {
					t.Run(tool, func(t *testing.T) {
						pr9CheckEdit(t, config, tool, path, true)
						// A refusal of the whole worktree must not satisfy the test.
						pr9CheckEdit(t, config, tool, filepath.Join(config.Root, prefix, "notes.md"), false)
					})
				}
			})
		}
	})

	t.Run("R4_RelativeScope", func(t *testing.T) {
		config := fakeTree(t)
		writeTree(t, config.Root, []string{"CLAUDE.md", "tools/d1/notes.md"})
		outside := config.Home
		relative, err := filepath.Rel(outside, config.Root)
		if err != nil {
			t.Fatal(err)
		}
		pr9CheckCommands(t, config, outside, true, []pr9Command{
			{"unrelated_copy_control", "cp x y", false},
			{"absolute_protected_copy_control", "cp x " + filepath.Join(config.Root, "CLAUDE.md"), true},
			{"relative_protected_copy", "cp x " + filepath.Join(relative, "CLAUDE.md"), true},
			{"relative_test", "cd " + relative + " && go test ./...", true},
			{"relative_server", "cd " + relative + " && go run ./cmd/example-server", true},
		})
		pr9CheckCommands(t, config, outside, false, []pr9Command{
			{"relative_read_control", "cat " + filepath.Join(relative, "CLAUDE.md"), false},
		})
	})

	t.Run("R5_TestWrapper", func(t *testing.T) {
		config := fakeTree(t)
		pr9CheckCommands(t, config, config.Root, false, []pr9Command{
			{"direct_test_control", "go test ./...", true},
			{"direct_compile_control", "go test -c ./...", false},
			{"wrapped_compile_control", "env go test -c ./...", false},
			{"wrapped_test", "env go test ./...", true},
		})
	})
}

type pr9Command struct {
	name    string
	command string
	refuse  bool
}

// pr9CheckCommands sends both kinds of case through the same elevated Codex
// session. A limited model's blanket refusal must not hide an argument bypass.
// Both scope directories are cwd so the R4 cases really originate elsewhere.
func pr9CheckCommands(t *testing.T, config Config, cwd string, sandboxOff bool, cases []pr9Command) {
	t.Helper()
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			raw := marshal(t, map[string]any{
				"hook_event_name": "PreToolUse",
				"tool_name":       "Bash",
				"cwd":             cwd,
				"model":           "gpt-6.1-sol",
				"tool_input": map[string]any{
					"command":                   test.command,
					"dangerouslyDisableSandbox": sandboxOff,
				},
			})
			pr9CheckDecision(t, test.command, Decide(raw, cwd, config), test.refuse)
		})
	}
}

func pr9CheckEdit(t *testing.T, config Config, tool string, path string, refuse bool) {
	t.Helper()
	var raw []byte
	if tool == "apply_patch" {
		patch := "*** Begin Patch\n*** Update File: " + path + "\n@@\n-fake\n+changed\n*** End Patch\n"
		raw = patchEvent(t, patch, config.Root)
	} else {
		raw = editEvent(t, tool, path, config.Root)
	}
	pr9CheckDecision(t, tool+" "+path, Decide(raw, config.Root, config), refuse)
}

func pr9CheckDecision(t *testing.T, input string, why string, refuse bool) {
	t.Helper()
	if refuse && why == "" {
		t.Errorf("unsafe input was admitted: %s", input)
	}
	if !refuse && why != "" {
		t.Errorf("allowed control was refused: %s\nreason: %s", input, why)
	}
}
