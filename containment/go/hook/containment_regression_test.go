package hook

import (
	"os"
	"path/filepath"
	"testing"
)

// TestContainmentRegression covers shell argument parsing, output paths,
// worktree protection, repository scope and wrapped test commands. These are
// requirements, not snapshots of the vulnerable decisions: an admitted unsafe
// form fails. Commands are event data only; no shell, agent, game or server runs.
// Like the other hook tests, build this package and run its binary under d1-nonet.
func TestContainmentRegression(t *testing.T) {
	t.Run("CodexOptions", func(t *testing.T) {
		config := fakeTree(t)
		checkCommandDecisions(t, config, config.Root, false, []commandDecisionCase{
			{"readonly_control", "codex exec -s read-only -", false},
			{"workspace_write_control", "codex exec -s workspace-write -", false},
			{"unquoted_bypass_control", "codex exec --dangerously-bypass-approvals-and-sandbox -", true},
			{"quoted_bypass", "codex exec '--dangerously-bypass-approvals-and-sandbox' -", true},
			{"attached_sandbox", "codex exec -sdanger-full-access -", true},
			{"attached_configuration", "codex exec -csandbox_mode=danger-full-access -", true},
		})
	})

	t.Run("OutputExpansion", func(t *testing.T) {
		config := fakeTree(t)
		// The path is checked before any shell expansion. HOME is never read or
		// changed here: an unresolved expansion must not count as a literal path
		// in the repository, whatever the actual session's HOME happens to be.
		checkCommandDecisions(t, config, config.Root, false, []commandDecisionCase{
			{"relative_output_control", "codex exec -s read-only -o docs/result.md -", false},
			{"quoted_output_control", "codex exec -s read-only -o 'docs/result with spaces.md' -", false},
			{"outside_output_control", "codex exec -s read-only -o " + filepath.Join(config.Home, "result.md") + " -", true},
			{"expanded_home", "codex exec -s read-only -o $HOME/.zshrc -", true},
		})
	})

	t.Run("WorktreeCase", func(t *testing.T) {
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
						checkEditDecision(t, config, tool, path, true)
						// A refusal of the whole worktree must not satisfy the test.
						checkEditDecision(t, config, tool, filepath.Join(config.Root, prefix, "notes.md"), false)
					})
				}
			})
		}
	})

	t.Run("RelativeScope", func(t *testing.T) {
		config := fakeTree(t)
		writeTree(t, config.Root, []string{"CLAUDE.md", "tools/d1/notes.md"})
		outside := config.Home
		relative, err := filepath.Rel(outside, config.Root)
		if err != nil {
			t.Fatal(err)
		}
		checkCommandDecisions(t, config, outside, true, []commandDecisionCase{
			{"unrelated_copy_control", "cp x y", false},
			{"absolute_protected_copy_control", "cp x " + filepath.Join(config.Root, "CLAUDE.md"), true},
			{"relative_protected_copy", "cp x " + filepath.Join(relative, "CLAUDE.md"), true},
			{"relative_test", "cd " + relative + " && go test ./...", true},
			{"relative_server", "cd " + relative + " && go run ./cmd/example-server", true},
		})
		checkCommandDecisions(t, config, outside, false, []commandDecisionCase{
			{"relative_read_control", "cat " + filepath.Join(relative, "CLAUDE.md"), false},
		})
	})

	t.Run("TestWrapper", func(t *testing.T) {
		config := fakeTree(t)
		checkCommandDecisions(t, config, config.Root, false, []commandDecisionCase{
			{"direct_test_control", "go test ./...", true},
			{"direct_compile_control", "go test -c ./...", false},
			{"wrapped_compile_control", "env go test -c ./...", false},
			{"wrapped_test", "env go test ./...", true},
		})
	})

	// The same gaps in the forms beside the ones the review probed: other spellings of a codex
	// option or of an output file, a game binary or test behind a wrapper, and a cd the hook cannot
	// resolve. Each unsafe case has an admitted control of the same shape.
	t.Run("SiblingForms", func(t *testing.T) {
		config := fakeTree(t)
		outside := filepath.Join(config.Home, "result.md")
		checkCommandDecisions(t, config, config.Root, false, []commandDecisionCase{
			{"owner_codex_pattern_control", "codex exec -m gpt-6.1-sol -c model_reasoning_effort='\"high\"' -s read-only -C \"$PWD\" --color never -o docs/r.md - <<'EOF' > \"$TMPDIR/codex.log\" 2>&1\ntask\nEOF", false},
			{"clustered_sandbox", "codex exec -hsdanger-full-access -", true},
			{"equals_sandbox", "codex exec -s=danger-full-access -", true},
			{"long_equals_sandbox", "codex exec --sandbox=danger-full-access -", true},
			{"quoted_sandbox_value", "codex exec -s 'danger-full-access' -", true},
			{"unknown_option", "codex exec --some-new-option -", true},
			{"feature_flag", "codex exec --enable some_feature -", true},
			{"split_variable", "codex exec $FLAGS -", true},
			{"cd_outside", "codex exec -s workspace-write -C " + config.Home + " -", true},
			{"cd_inside_control", "codex exec -s workspace-write -C " + config.Root + " -", false},
			{"add_dir_home", "codex exec -s workspace-write --add-dir ~ -", true},
			{"redirect_home", "codex exec -s read-only - > $HOME/.zshrc", true},
			{"redirect_outside", "codex exec -s read-only - > " + outside, true},
			{"redirect_inside_control", "codex exec -s read-only - > docs/out.md 2>&1", false},
			{"redirect_null_control", "xcodebuild -version > /dev/null", false},
			{"redirect_temporary_escape", "codex exec -s read-only - > $TMPDIR/../x", true},
			{"wrapped_game", "nice -n 5 d1-recomp run", true},
			{"shell_wrapped_test", "bash -c 'go test ./...'", true},
			{"timeout_wrapped_test", "timeout 60 go test ./...", true},
			{"lookup_control", "command -v codex", false},
		})
		checkCommandDecisions(t, config, config.Root, true, []commandDecisionCase{
			{"localonly_wrapped_test", config.LauncherDirectory + "/d1-localonly /usr/bin/env go test ./...", true},
		})
		elsewhere := config.Home
		checkCommandDecisions(t, config, elsewhere, true, []commandDecisionCase{
			{"unresolved_cd", "cd $REPO && cp x CLAUDE.md", true},
			{"substituted_cd", "cd $(git rev-parse --show-toplevel) && cp x CLAUDE.md", true},
			{"variable_path", "cp x $REPO/CLAUDE.md", true},
			{"case_variant_root", "cp x " + filepath.Join(filepath.Dir(config.Root), "REPO", "CLAUDE.md"), true},
			{"home_relative", "cp x ~/../repo/CLAUDE.md", true},
			{"glob_into_root", "cp x ../re*/CLAUDE.md", true},
			{"plain_variable_control", "echo $PATH", false},
			{"cd_elsewhere_control", "cd ../home && cp x y", false},
			{"home_control", "cp x ~/notes.md", false},
		})
	})
}

type commandDecisionCase struct {
	name    string
	command string
	refuse  bool
}

// checkCommandDecisions sends both kinds of case through the same elevated Codex
// session. A limited model's blanket refusal must not hide an argument bypass.
// Both scope directories are cwd so the relative-scope cases originate elsewhere.
func checkCommandDecisions(t *testing.T, config Config, cwd string, sandboxOff bool, cases []commandDecisionCase) {
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
			checkDecision(t, test.command, Decide(raw, cwd, config), test.refuse)
		})
	}
}

func checkEditDecision(t *testing.T, config Config, tool string, path string, refuse bool) {
	t.Helper()
	var raw []byte
	if tool == "apply_patch" {
		patch := "*** Begin Patch\n*** Update File: " + path + "\n@@\n-fake\n+changed\n*** End Patch\n"
		raw = patchEvent(t, patch, config.Root)
	} else {
		raw = editEvent(t, tool, path, config.Root)
	}
	checkDecision(t, tool+" "+path, Decide(raw, config.Root, config), refuse)
}

func checkDecision(t *testing.T, input string, why string, refuse bool) {
	t.Helper()
	if refuse && why == "" {
		t.Errorf("unsafe input was admitted: %s", input)
	}
	if !refuse && why != "" {
		t.Errorf("allowed control was refused: %s\nreason: %s", input, why)
	}
}
