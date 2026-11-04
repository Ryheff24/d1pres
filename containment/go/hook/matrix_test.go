package hook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// launched marks a probe the hook admits to the launcher: the fake tree's launchers belong to the
// test's user, so the call ends at RootOwned's refusal, after every rule of the matrix has passed.
const launched = "the launcher install cannot be trusted"

// probe is one call checked for both kinds of session. kind is "bash" (sandboxed), "off" (sandbox
// off), "edit" or "patch"; input is the command or the path written. elevated and other are ""
// when Decide admits the call, launched, or a piece of the refusal.
type probe struct {
	row             string // a prefix of exactly one Row's Capability
	kind, input     string
	elevated, other string
}

// sessionBash is a Bash event from the Claude Code session whose transcript is given.
func sessionBash(t *testing.T, command string, sandboxOff bool, cwd string, transcript string) []byte {
	t.Helper()
	input := map[string]any{"command": command}
	if sandboxOff {
		input["dangerouslyDisableSandbox"] = true
	}
	return marshal(t, map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": input, "cwd": cwd, "transcript_path": transcript})
}

// probeEvent is the event a probe sends from the session whose transcript is given.
func probeEvent(t *testing.T, p probe, cwd string, transcript string) []byte {
	t.Helper()
	switch p.kind {
	case "bash", "off":
		return sessionBash(t, p.input, p.kind == "off", cwd, transcript)
	case "edit":
		return marshal(t, map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Edit", "tool_input": map[string]any{"file_path": p.input}, "cwd": cwd, "transcript_path": transcript})
	case "patch":
		patch := "*** Begin Patch\n*** Update File: " + p.input + "\n@@\n-a\n+b\n*** End Patch\n"
		return marshal(t, map[string]any{"hook_event_name": "PreToolUse", "tool_name": "apply_patch", "tool_input": map[string]any{"command": patch}, "cwd": cwd, "transcript_path": transcript})
	}
	t.Fatalf("probe kind %q", p.kind)
	return nil
}

// TestAccessMatrix: every row of AccessMatrix is what Decide does, for an elevated model's session
// and for any other's. Each probe is checked for both; a cell that says "no" admits none of its row's
// probes, a cell that says "yes" admits at least one, and every row the hook decides has probes, the
// base cases neither kind of session gets included. agent-containment.md shows exactly MatrixTable().
func TestAccessMatrix(t *testing.T) {
	config := fakeTree(t)
	elevated := writeTranscript(t, config, "elevated.jsonl", assistant("claude-opus-5-5"))
	other := writeTranscript(t, config, "other.jsonl", assistant("deepseek/deepseek-v4.1-flash-1017"))
	program := filepath.Join(config.Root, "testbin", "d1sleeper")
	writeTree(t, config.Root, []string{"testbin/d1sleeper"})
	writeTree(t, config.Home, []string{".codex/sessions/2026/keep"})
	runs := filepath.Join(config.Root, "runs")
	if err := os.MkdirAll(runs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(config.Home, filepath.Join(runs, "out")); err != nil {
		t.Fatal(err)
	}
	trace, outside := filepath.Join(runs, "t.trace"), filepath.Join(config.Home, "x")
	writeTree(t, config.Root, []string{"runs/t.trace"})
	writeTree(t, config.Home, []string{"x"})
	xt := "/Applications/Xcode.app/Contents/Developer/usr/bin/xctrace"
	readProcess = func(pid int) (string, string, string) {
		switch pid {
		case 4001:
			return program, config.Root, ""
		case 4003:
			return "/bin/sleep", config.Root, ""
		}
		return "", "", "which is not running"
	}
	t.Cleanup(func() { readProcess = realReadProcess })
	nonet := config.LauncherDirectory + "/d1-nonet"
	localonly := config.LauncherDirectory + "/d1-localonly"
	release := filepath.Join(config.Root, "d1-server", "target", "release")
	companion := "node /Users/ryanheffernan/.claude/plugins/cache/openai-codex/codex/1.0.6/scripts/codex-companion.mjs"
	notes := filepath.Join(config.Root, "notes.md")
	onlyElevated, tool := "only elevated models", "is an elevated tool"
	probes := []probe{
		{"Bash inside", "bash", "ls -la", "", ""},
		{"Bash inside", "bash", "ps aux", "", ""},
		{"Bash that names", "bash", "cat CLAUDE.md", "", ""},
		{"Bash that names", "bash", "sed -i '' s/a/b/ CLAUDE.md", "names CLAUDE.md", "names CLAUDE.md"},
		{"Edit, Write or apply_patch of a protected", "edit", filepath.Join(config.Root, "CLAUDE.md"), "is protected", "is protected"},
		{"Edit, Write or apply_patch of a protected", "patch", filepath.Join(config.Root, "containment", "go", "hook", "hook.go"), "is protected", "is protected"},
		{"Edit, Write or apply_patch under a protected tree", "edit", filepath.Join(config.Root, "containment", "go", "hook", "planted_test.go"), "is protected", "is protected"},
		{"Edit, Write or apply_patch under a protected tree", "patch", filepath.Join(config.Root, ".git", "hooks", "pre-commit"), "is protected", "is protected"},
		{"Edit, Write or apply_patch under a protected tree", "edit", filepath.Join(config.Root, ".claude", "worktrees", "wt1", "containment", "go", "go.mod"), "protected", "protected"},
		{"Edit, Write or apply_patch under a protected tree", "edit", filepath.Join(config.Root, "runs", "wt-gfx", "CLAUDE.md"), "protected", "protected"},
		{"Bash that names a protected file or tree", "bash", "cat " + filepath.Join(config.Root, "containment", "go", "hook", "matrix.go"), "", ""},
		{"Bash that names a protected file or tree", "bash", "grep -n -E 'a|b' " + filepath.Join(config.Root, "CLAUDE.md") + " 2>&1 | head", "", ""},
		{"Bash that names a protected file or tree", "bash", "echo x > " + filepath.Join(config.Root, "containment", "go", "hook", "planted_test.go"), "names containment/go", "names containment/go"},
		{"Edit, Write or apply_patch of the session", "edit", other, "session records", "session records"},
		{"Edit, Write or apply_patch of the session", "patch", filepath.Join(config.Home, ".codex", "sessions", "2026", "r.jsonl"), "session records", "session records"},
		{"Game code", "off", nonet + " " + release + "/d1-recomp run --seconds 5", launched, launched},
		{"Game code", "bash", release + "/d1-recomp run", "runs game code", "runs game code"},
		{"Running tests", "off", nonet + " " + config.Root + "/testbin/hook.test", launched, launched},
		{"Running tests", "off", localonly + " " + config.Root + "/testbin/hook.test", "tests run only under d1-nonet", "tests run only under d1-nonet"},
		{"Servers", "off", localonly + " /usr/bin/true", launched, launched},
		{"Servers", "off", localonly + " " + release + "/d1-srv", "never a game binary", "never a game binary"},
		{"Codex through", "bash", companion + " task x", "", ""},
		{"Codex through", "bash", companion + " review", "reviews start ephemeral threads", "reviews start ephemeral threads"},
		{"The owner's sandbox-excluded", "bash", "xcodebuild -version", "", onlyElevated},
		{"The owner's sandbox-excluded", "bash", "codex exec -s read-only x", "", onlyElevated},
		{"The owner's sandbox-excluded", "bash", "xcodebuild -version > " + filepath.Join(config.Root, "CLAUDE.md"), "which is protected", onlyElevated},
		{"The owner's sandbox-excluded", "bash", "codex exec -s read-only -o " + filepath.Join(config.Home, ".claude", "settings.json") + " -", "writes that file outside every sandbox", onlyElevated},
		{"The owner's sandbox-excluded", "bash", "codex exec --dangerously-bypass-approvals-and-sandbox x", "turns off the sandbox", onlyElevated},
		{"The owner's sandbox-excluded", "bash", "codex exec -c sandbox_mode=danger-full-access x", "is not admitted", onlyElevated},
		{"copilot", "bash", "copilot -p x --allow-tool 'shell(ls)'", "copilot is not excluded", onlyElevated},
		{"copilot", "bash", "copilot -p x --allow-a\\\nll", "copilot is not excluded", onlyElevated},
		{"Running tests", "bash", "go test ./...", "inside the agent sandbox", "inside the agent sandbox"},
		{"Running tests", "bash", "go test -c -o " + filepath.Join(config.Root, "testbin") + "/ ./internal/...", "", ""},
		{"Running tests", "bash", "cargo test --no-run -p d1-bap", "", ""},
		{"The owner's sandbox-excluded", "bash", "xcodebuild -version # <<'EOF'\n/usr/bin/touch /tmp/owned\nEOF", "starts a comment", onlyElevated},
		// Read-only logs and profilers (profiler.go): the admitted forms for both kinds of session,
		// sandbox on and off, then every form the two 2026-10-28 reviews found, refused for both.
		{"Read-only logs", "bash", "/usr/bin/log show --last 1m --style compact", "", ""},
		{"Read-only logs", "off", "/usr/bin/log stream --process d1-recomp --level debug --timeout 5s", "", ""},
		{"Read-only logs", "off", xt + " export --input " + trace + " --xpath '/trace-toc/run[@number=\"1\"]/data/table[@schema=\"time-profile\"]'", "", ""},
		{"Read-only logs", "bash", xt + " list templates", "", ""},
		{"Read-only logs", "off", "/usr/bin/sample 4001 5 -mayDie", "", ""},
		{"Read-only logs", "bash", "/usr/bin/sample 4001 5 1", "", ""},
		{"Read-only logs", "off", "/usr/bin/vmmap -summary 4001", "", ""},
		{"Read-only logs", "off", "/usr/bin/footprint --format formatted 4001", "", ""},
		{"Read-only logs", "off", "/usr/bin/malloc_history 4001 -allBySize", "", ""},
		{"Read-only logs", "off", "/usr/bin/metalperftrace overview " + trace, "", ""},
		{"Read-only logs", "off", "/usr/bin/metalperftrace listen --pid 4001 --json", "", ""},
		{"Read-only logs", "off", "'/usr/bin/sample' 4001", "", ""},
		// review 1: a comment, quotes, continuations, outputs, redirections, bare names
		{"Read-only logs", "off", "/usr/bin/log show --last 1m # <<'EOF'\nexec /usr/bin/touch /tmp/owned\nEOF", "one line", "one line"},
		{"Read-only logs", "off", "/usr/bin/log show --last 1m # \\\n/usr/bin/touch /tmp/owned", "one line", "one line"},
		{"Read-only logs", "off", "/usr/bin/log show --last 1m #x", "shell syntax", "shell syntax"},
		{"Read-only logs", "off", xt + " record --template 'Time Profiler' '--launch' -- /bin/sh -c 'exec /usr/bin/true' --attach", "is not one of the admitted", "is not one of the admitted"},
		{"Read-only logs", "off", xt + " record --template 'Time Profiler' --attach 4001 --output " + runs + "/a.trace", "is not one of the admitted", "is not one of the admitted"},
		{"Read-only logs", "off", "/usr/bin/sample 4001 1 '-file' /tmp/owned", "-file is not admitted", "-file is not admitted"},
		{"Read-only logs", "off", "/usr/bin/sample 4001 1 '-e'", "-e is not admitted", "-e is not admitted"},
		{"Read-only logs", "off", "/usr/bin/sample 4001 1 -fi''le /tmp/owned", "-file is not admitted", "-file is not admitted"},
		{"Read-only logs", "off", "/usr/bin/sample 4001 1 -fi\\\nle /tmp/owned", "one line", "one line"},
		{"Read-only logs", "off", "/usr/bin/sample 4001 1 -file=/tmp/owned", "-file is not admitted", "-file is not admitted"},
		{"Read-only logs", "off", xt + " export --input " + trace + " --toc --output " + runs + "/a.xml", "--output is not admitted", "--output is not admitted"},
		{"Read-only logs", "off", "/usr/bin/footprint --json " + runs + "/f.json 4001", "--json is not admitted", "--json is not admitted"},
		{"Read-only logs", "off", "/usr/bin/metalperftrace collect --last 5m " + runs + "/mpt", "is not one of the admitted", "is not one of the admitted"},
		{"Read-only logs", "off", "/usr/bin/metalperftrace listen --pid 4001 --output " + runs + "/l.txt", "--output is not admitted", "--output is not admitted"},
		{"Read-only logs", "off", "/usr/bin/log show --last 1m 3< /dev/tcp/example.com/443", "shell syntax", "shell syntax"},
		{"Read-only logs", "off", "/usr/bin/log show --last 1m <<< x", "shell syntax", "shell syntax"},
		{"Read-only logs", "off", "/usr/bin/log show --last 1m > x", "shell syntax", "shell syntax"},
		{"Read-only logs", "off", "/usr/bin/log show --last 1m & /usr/bin/touch /tmp/owned", "shell syntax", "shell syntax"},
		{"Read-only logs", "off", "/usr/bin/vmmap 4001 | head", "shell syntax", "shell syntax"},
		{"Read-only logs", "off", "/usr/bin/vmmap 4001; curl x", "shell syntax", "shell syntax"},
		{"Read-only logs", "off", "/usr/bin/vmmap $PPID", "shell syntax", "shell syntax"},
		{"Read-only logs", "off", "/usr/bin/vmmap \"4001\"", "shell syntax", "shell syntax"},
		{"Read-only logs", "off", "/usr/bin/vmmap ~/x", "shell syntax", "shell syntax"},
		{"Read-only logs", "off", "/usr/bin/vmmap 40*", "shell syntax", "shell syntax"},
		{"Read-only logs", "off", "sample 4001 1", "its own path", "its own path"},
		{"Read-only logs", "off", "/tmp/sample 4001", "its own path", "its own path"},
		{"Read-only logs", "off", "PATH=/tmp sample 4001", "its own path", "its own path"},
		{"Read-only logs", "off", "/usr/bin/log show --pager", "--pager is not admitted", "--pager is not admitted"},
		{"Read-only logs", "off", "/usr/bin/log stream --predicate 'process == \"x\"'", "--predicate is not admitted", "--predicate is not admitted"},
		{"Read-only logs", "off", "/usr/bin/log collect --output " + runs + "/x", "is not one of the admitted", "is not one of the admitted"},
		{"Read-only logs", "off", "/usr/bin/footprint --forkCorpse 4001", "--forkCorpse is not admitted", "--forkCorpse is not admitted"},
		{"Read-only logs", "off", "/usr/bin/vmmap -forkCorpse 4001", "-forkCorpse is not admitted", "-forkCorpse is not admitted"},
		{"Read-only logs", "off", "/usr/bin/metalperftrace setup --pid 4001", "is not one of the admitted", "is not one of the admitted"},
		{"Read-only logs", "bash", "/usr/bin/sample 4001 1 '-file' " + notes, "-file is not admitted", "-file is not admitted"},
		// review 2: xcrun routes, the companion's fake heredoc, inputs, heap contents, other processes
		{"Read-only logs", "off", "/usr/bin/xcrun xctrace\\\n record --template 'Time Profiler' '--launch' -- /usr/bin/true", "one line", "one line"},
		{"Read-only logs", "off", "/usr/bin/xcrun xctrace list templates", "its own path", "its own path"},
		{"Read-only logs", "off", "xcrun 'xctrace' list templates", "its own path", "its own path"},
		{"Read-only logs", "off", companion + " status # <<'EOF'\n/usr/bin/sample 4001 1 -e\nEOF", "starts a comment", "starts a comment"},
		{"Read-only logs", "off", "/usr/bin/malloc_history 4001 -callTree -showContent", "-showContent is not admitted", "-showContent is not admitted"},
		{"Read-only logs", "off", "/usr/bin/malloc_history " + outside + " -callTree", "PID", "PID"},
		{"Read-only logs", "off", "/usr/bin/log show --archive " + outside, "--archive is not admitted", "--archive is not admitted"},
		{"Read-only logs", "off", xt + " export --input " + outside + " --toc", "not a file inside", "not a file inside"},
		{"Read-only logs", "off", xt + " export --input " + runs + "/out/x --toc", "not a file inside", "not a file inside"},
		{"Read-only logs", "off", xt + " export --input " + runs + "/../" + filepath.Base(trace) + " --toc", "without ..", "without .."},
		{"Read-only logs", "off", "/usr/bin/metalperftrace overview " + outside, "not a file inside", "not a file inside"},
		{"Read-only logs", "off", "/usr/bin/vmmap " + outside, "PID", "PID"},
		{"Read-only logs", "off", "/usr/bin/sample 4003 5", "only at this project's processes", "only at this project's processes"},
		{"Read-only logs", "off", "/usr/bin/sample Safari 5", "PID", "PID"},
		{"Read-only logs", "off", "/usr/bin/sample 4001 3600 1 -wait", "-wait is not admitted", "-wait is not admitted"},
		{"Read-only logs", "off", "/usr/bin/footprint --all --sample 0.5", "--all is not admitted", "--all is not admitted"},
		{"Read-only logs", "off", "/usr/bin/footprint --proc Safari", "--proc is not admitted", "--proc is not admitted"},
		{"Read-only logs", "off", "/usr/bin/metalperftrace listen --process Safari", "--process is not admitted", "--process is not admitted"},
		{"Read-only logs", "off", xt + " export --input --toc", "needs a value", "needs a value"},
		{"Read-only logs", "off", xt + " export --input " + trace + " --input " + trace, "appears twice", "appears twice"},
		{"Read-only logs", "off", "/usr/bin/log show --style ''", "an empty value", "an empty value"},
		{"Read-only logs", "off", "/usr/bin/sample 4001 5x", "a number", "a number"},
		{"Read-only logs", "off", "/usr/bin/vmmap 4001 12", "an address", "an address"},
		{"Read-only logs", "off", "/usr/bin/log show '", "unclosed quote", "unclosed quote"},
		{"Read-only logs", "off", "/usr/bin/log show '\tx'", "printable ASCII", "printable ASCII"},
		{"Read-only logs", "off", "/usr/bin/log show --last 1m\r", "one line", "one line"},
		{"Read-only logs", "off", "/usr/bin/log show --last 1m\x00", "shell syntax", "shell syntax"},
		{"Read-only logs", "off", "/usr/bin/log", "log needs a subcommand", "log needs a subcommand"},
		{"Read-only logs", "off", "/usr/bin/log show --info=x", "--info takes no value", "--info takes no value"},
		{"Read-only logs", "off", xt + " export --toc", "xctrace export needs --input", "xctrace export needs --input"},
		{"Read-only logs", "off", "/usr/bin/sample 4001 5 1 4001", "sample takes at most 3 words", "sample takes at most 3 words"},
		{"Read-only logs", "off", xt + " list devices", "xctrace list is one of", "xctrace list is one of"},
		{"Read-only logs", "off", xt + " list", "xctrace list is one of", "xctrace list is one of"},
		{"security", "bash", "security find-identity -p codesigning", "", onlyElevated},
		{"security", "bash", "security find-generic-password -w -s x", "security find-identity", onlyElevated},
		{"xcrun", "bash", "xcrun --show-sdk-path", "", onlyElevated},
		{"xcrun", "bash", "xcrun swift run", "only queries the SDK or starts", onlyElevated},
		{"Inspecting", "off", "/bin/ps aux | /usr/bin/grep d1 | /usr/bin/head -5", "", tool},
		{"Inspecting", "off", "/usr/bin/nettop -l 1", "", tool},
		{"Inspecting", "off", "/usr/bin/nettop", "logging mode", tool},
		{"Inspecting", "off", "/usr/bin/leaks 1 --outputGraph x", "writes a file", tool},
		{"Inspecting", "off", "/bin/ps aux > x", "is not allowed", tool},
		{"Reading system state", "off", "/usr/sbin/sysctl -n vm.swapusage | /usr/bin/grep used", "", tool},
		{"Reading system state", "off", "/usr/bin/pmset -g therm", "", tool},
		{"Reading system state", "off", "/usr/bin/memory_pressure -Q", "", tool},
		{"Reading system state", "off", "/usr/sbin/sysctl kern.maxfiles=1", "sets a value", tool},
		{"Reading system state", "off", "/usr/bin/pmset -a sleep 0", "only reads here", tool},
		{"Reading system state", "off", "/usr/bin/memory_pressure -S -l critical", "simulate pressure", tool},
		{"Stopping", "off", "/bin/kill 4001", "", tool},
		{"Stopping", "off", "/bin/kill 4003", "not one of this project's programs", tool},
		{"Stopping", "off", "/bin/kill -1", "names no process", tool},
		{"Opening files", "off", "/usr/local/bin/code -r " + notes, "", tool},
		{"Opening files", "off", "/usr/local/bin/code -r /etc/hosts", "outside it", tool},
		{"Anything else", "off", "curl http://example.com", "is not a launcher", "is not a launcher"},
		{"Anything else", "off", "sh -c ps", "is not a launcher", "is not a launcher"},
		{"Anything else", "off", "python3 -c x", "is not a launcher", "is not a launcher"},
	}
	rowOf := func(prefix string) int {
		found := -1
		for index, row := range AccessMatrix {
			if strings.HasPrefix(row.Capability, prefix) {
				if found >= 0 {
					t.Fatalf("probe row %q names more than one row", prefix)
				}
				found = index
			}
		}
		if found < 0 {
			t.Fatalf("probe row %q names no row", prefix)
		}
		return found
	}
	admits := make([][2]bool, len(AccessMatrix))
	probed := make([]bool, len(AccessMatrix))
	for _, p := range probes {
		index := rowOf(p.row)
		probed[index] = true
		for side, want := range []string{p.elevated, p.other} {
			transcript := []string{elevated, other}[side]
			why := Decide(probeEvent(t, p, config.Root, transcript), config.Root, config)
			if want == "" && why != "" || want != "" && !strings.Contains(why, want) {
				t.Errorf("%s %q from the %s session: wanted %q, got %q", p.kind, p.input, []string{"elevated", "other"}[side], want, why)
			}
			if want == "" || want == launched {
				admits[index][side] = true
			}
		}
	}
	for index, row := range AccessMatrix {
		for _, cell := range []string{row.Capability, row.Elevated, row.Other, row.Enforced} {
			if strings.Contains(cell, "|") {
				t.Errorf("row %q: a cell holds \"|\", which breaks the table", row.Capability)
			}
		}
		if !probed[index] {
			if !strings.Contains(row.Enforced, suiteTested) {
				t.Errorf("row %q: the hook decides it, and no probe checks it", row.Capability)
			}
			continue
		}
		for side, cell := range []string{row.Elevated, row.Other} {
			switch {
			case cell == "no" && admits[index][side]:
				t.Errorf("row %q says no for the %s column, and a probe was admitted", row.Capability, []string{"elevated", "other"}[side])
			case strings.HasPrefix(cell, "yes") && !admits[index][side]:
				t.Errorf("row %q says yes for the %s column, and no probe was admitted", row.Capability, []string{"elevated", "other"}[side])
			case cell != "no" && !strings.HasPrefix(cell, "yes"):
				t.Errorf("row %q: a cell the hook decides says %q, not no or yes", row.Capability, cell)
			}
		}
	}
	document, err := os.ReadFile(filepath.Join("..", "..", "agent-containment.md"))
	if err != nil {
		t.Fatal(err)
	}
	start := "<!-- access control matrix: generated from containment/go/hook/matrix.go (MatrixTable); TestAccessMatrix fails when this differs -->\n"
	end := "<!-- end of access control matrix -->"
	_, after, found := strings.Cut(string(document), start)
	shown, _, closed := strings.Cut(after, end)
	if !found || !closed {
		t.Fatalf("agent-containment.md has no access control matrix between %q and %q", start, end)
	}
	if shown != MatrixTable() {
		t.Errorf("agent-containment.md's access control matrix differs from MatrixTable(); it should read:\n%s", MatrixTable())
	}
}
