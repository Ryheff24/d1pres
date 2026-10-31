// Package hook holds d1-agent-hook's rules: a Claude Code (or Codex) PreToolUse event in, a
// decision out. Codex sends the same event shape; its shell calls arrive as Bash and its file
// edits as apply_patch.
// "" lets the call go on to Claude Code's own permission flow; anything else is the reason it is
// refused. Every input it cannot read is refused (fail closed).
package hook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"unicode"

	"d1preservation/netguard/gate"
)

// LauncherDirectory is the owner's root-owned install of d1-nonet, d1-localonly and the hook.
const LauncherDirectory = "/usr/local/libexec/d1-agent"

// Matcher is the PreToolUse matcher: Bash and every tool that edits a file.
const Matcher = "Bash|Edit|Write|MultiEdit|NotebookEdit"

// Config is what the rules are decided against: the repository (set at build time), the
// account's home directory, the launcher directory, and the session's ANTHROPIC_BASE_URL (empty
// when unset), which keeps a session on another provider at the current limits (Elevated).
type Config struct {
	Root              string
	Home              string
	LauncherDirectory string
	AnthropicBaseURL  string
}

// event is the part of the PreToolUse event the rules read. Codex sends the model; Claude Code
// sends the transcript and, for a subagent's call, its agent id (SessionModel). Cursor's native
// beforeShellExecution event sends neither, and its command at the top level, not in tool_input.
type event struct {
	HookEventName  string          `json:"hook_event_name"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	Command        *string         `json:"command"`
	Cwd            string          `json:"cwd"`
	TranscriptPath string          `json:"transcript_path"`
	AgentID        string          `json:"agent_id"`
	Model          string          `json:"model"`
}

// shellEvents are the event names this hook decides: Claude Code's and Codex's PreToolUse, Cursor's
// two spellings of it through its Claude-hook import, and Cursor's native shell event. shellTools
// are the tool names that run a shell: Claude Code and Codex send Bash, the cursor-agent CLI sends
// Shell.
var shellEvents = []string{"PreToolUse", "preToolUse", "beforeShellExecution"}
var shellTools = []string{"Bash", "Shell", "shell"}

// toolInput is the part of a tool's input the rules read; a field of the wrong type refuses.
type toolInput struct {
	Command                   *string `json:"command"`
	DangerouslyDisableSandbox *bool   `json:"dangerouslyDisableSandbox"`
	FilePath                  string  `json:"file_path"`
	NotebookPath              string  `json:"notebook_path"`
}

// Decide reads one event and applies the rule for its tool. projectDirectory is
// CLAUDE_PROJECT_DIR from the hook's environment.
// The owner's flag on this function (2026-10-27, answered by the 2026-10-31 audit, §1 and N7):
// the event-name line is right, and the gaps were below it. What was measured and what changed:
//
//   - Cursor. Its native event is beforeShellExecution with the command at the top level and no
//     tool_input, which this hook used to refuse as unreadable, so under that shape every Cursor
//     shell call was blocked. Both spellings of PreToolUse, beforeShellExecution and a top-level
//     command are read now, and Shell counts as Bash. No Cursor hook is registered on this Mac
//     (~/.cursor/hooks.json does not exist), so the path stays unverified by anything but the tests.
//   - Fail closed on the sandbox flag. Only Claude Code sends dangerouslyDisableSandbox. A harness
//     that sends neither transcript_path (Claude Code) nor model (Codex) is an unsandboxed shell,
//     and the sandbox-off rules apply to it as if the flag were true. Codex is covered by its own
//     -s sandbox, which is why its events are not treated that way.
//   - "Deny and specify correct use." Every refusal below names the allowed form, not only the doc:
//     the tripwire prints the reading programs and the staging route (howToRead), a game binary
//     prints the launcher command with the path filled in, a test prints the build-then-launch pair.
//   - "Tests included, automatically." A test that runs inside the agent sandbox is refused here
//     (runsTestsInSandbox), not only when the sandbox is off, so the rule is enforced in code and
//     not by remembering it. The lock is still the gate compiled into each test binary.
//
// What this function cannot answer is in the audit: the test-package control (N7), the server
// self-gate (F1 of 2026-10-27) and the documentation drift the owner describes are not hook rules.
func Decide(raw []byte, projectDirectory string, config Config) string {
	var call event
	var input toolInput
	err := json.Unmarshal(raw, &call)
	if err == nil && len(call.ToolInput) > 0 {
		err = json.Unmarshal(call.ToolInput, &input)
	}
	if err != nil {
		return "the event is not one this hook can read (" + err.Error() + ")"
	}
	if input.Command == nil {
		input.Command = call.Command
	}
	if call.HookEventName != "" && !slices.Contains(shellEvents, call.HookEventName) {
		return "this hook decides " + strings.Join(shellEvents, ", ") + " events, and was sent " + call.HookEventName
	}
	if slices.Contains(shellTools, call.ToolName) || call.ToolName == "" && call.HookEventName == "beforeShellExecution" {
		return decideBash(call, input, []string{projectDirectory, call.Cwd}, config)
	}
	switch call.ToolName {
	case "Edit", "Write", "MultiEdit", "NotebookEdit":
		return decideEdit(call.ToolName, input, call.Cwd, config)
	case "apply_patch":
		return decidePatch(input, call.Cwd, config)
	}
	return fmt.Sprintf("this hook decides %s, the edit tools and apply_patch only, and was sent %q", strings.Join(shellTools, ", "), call.ToolName)
}

// decideBash: a game binary named without the launcher is refused from any session. In sessions
// in, inside or above this repository, a read-only log or profiler command is decided by
// ProfilerForm for every model (profiler.go); a command naming one of the owner's excluded programs is
// for elevated models only and must be that command alone, and then skips the tripwire (the
// program runs outside the sandbox by the owner's choice, and a heredoc body is its data: codex
// prompts name protected files); any other command naming a protected file must be a pure read
// (Tripwire), and a call with the sandbox off must be the launcher form, or, from an elevated
// model's session, an elevated tool (ElevatedForm). matrix.go sums these rules up by row.
func decideBash(call event, input toolInput, directories []string, config Config) string {
	if input.Command == nil {
		return "Bash: no command string in the event"
	}
	command := *input.Command
	code := withoutHeredocBody(command)
	game := firstWordMatching(code, func(word string) bool { return slices.Contains(gate.GameBinaries, filepath.Base(word)) })
	if game != "" {
		return game + " runs game code; start it only as the argument of " + config.LauncherDirectory + "/d1-nonet, as one plain command: " +
			config.LauncherDirectory + "/d1-nonet " + filepath.Join(config.Root, "d1-server/target/release", filepath.Base(game)) +
			" ARGS --log FILE (absolute paths, optional D1_*=value in front, never D1_NET*, no quotes, pipes, \";\", \"$\" or redirection)"
	}
	if !inScope(directories, config.Root) && !strings.Contains(code, config.Root) {
		// A session working elsewhere meets the rules of this repository only when it reaches into
		// it: that is the whole of F2 and N9 (a sandbox-off "cp x <repo>/CLAUDE.md" from another
		// project passed), without imposing the launcher form on the owner's other projects, where
		// this hook is installed too.
		return ""
	}
	if why, decided := decideInRepository(call, command, code, config); decided {
		return why
	}
	if input.DangerouslyDisableSandbox != nil && *input.DangerouslyDisableSandbox || unsandboxedHarness(call) {
		return decideSandboxOff(call, command, config)
	}
	return ""
}

// unsandboxedHarness reports whether the event comes from a harness that sends no sandbox flag and
// applies no sandbox of its own: neither Claude Code's transcript_path nor Codex's model. Codex
// sends the model and applies its own -s sandbox to its tools; Cursor's shell has nothing, so its
// calls are decided as if the sandbox were off (fail closed, 2026-10-27 review §2).
func unsandboxedHarness(call event) bool {
	return call.TranscriptPath == "" && call.Model == ""
}

// decideInRepository applies the rules that hold for a session in, inside or above the repository,
// or whose command spells its root: the Codex plugin, the read-only profilers, the owner's
// sandbox-excluded programs, the spellings that would drop the Rust test gate, a test run inside
// the agent sandbox, and the tripwire. decided is false when none of them applies and the
// sandbox-off rules are next.
func decideInRepository(call event, command string, code string, config Config) (string, bool) {
	if isCompanion(code) {
		return CompanionForm(command), true
	}
	if RoutesToProfiler(code) {
		if why := ProfilerForm(command, config.Root); why != "" {
			return why, true
		}
		return Tripwire(command, config), true
	}
	if excluded := firstWordMatching(code, isExcludedName); excluded != "" {
		if elevated, because := Elevated(call, config); !elevated {
			return "the owner's settings run " + filepath.Base(excluded) + " outside the sandbox, which only elevated models may do, and " + because + " (containment/agent-containment.md, Access control matrix)", true
		}
		return ExcludedForm(command, call.Cwd, config), true
	}
	if override := overridesTestGate(code); override != "" {
		return override + " would build or run a Rust test without the test gate that d1-server/.cargo/config.toml links in; every test runs inside the network sandbox (containment/agent-containment.md, Tests)", true
	}
	if why := runsTestsInSandbox(code, config); why != "" {
		return why, true
	}
	if tripped := Tripwire(command, config); tripped != "" {
		return tripped, true
	}
	return "", false
}

// decideSandboxOff applies the sandbox-off rules: the launcher form, or an elevated tool from an
// elevated model's session.
func decideSandboxOff(call event, command string, config Config) string {
	launcher, why := LauncherForm(command, config)
	if why == "" {
		return RootOwned(launcher)
	}
	if unsandboxedHarness(call) {
		why += ". This harness sends no sandbox flag and applies no sandbox of its own (the event carries neither " +
			"transcript_path nor model), so every command from it is decided as if the sandbox were off, which is what " +
			"it is: ordinary shell work belongs in Claude Code or Codex, where it runs inside one"
	}
	words := strings.Fields(command)
	if len(words) == 0 || !isElevatedToolWord(words[0]) {
		return why
	}
	elevated, because := Elevated(call, config)
	if !elevated {
		return why + "; " + words[0] + " is an elevated tool, and " + because + " (containment/agent-containment.md, Access control matrix)"
	}
	return ElevatedForm(command, call.Cwd, config)
}

// runsTestsInSandbox returns "" unless command would run tests in the agent's own sandbox, where
// loopback is open and egress goes through the proxy: "go test" or "cargo test" (bench, nextest and
// cargo's t alias included) without the option that only builds them. Every test runs inside the
// game profile (owner, 2026-10-19), and until now only a sandbox-off test run was refused, which
// left the common case -- a plain "go test ./..." inside the sandbox -- passing (audit N7). The
// lock is the gate compiled into each test binary; this is the rule enforced where it is broken.
func runsTestsInSandbox(command string, config Config) string {
	builds := map[string]string{"go": "-c", "cargo": "--no-run"}
	for _, segment := range commandSegments(command) {
		words := strings.Fields(segment)
		for len(words) > 0 && isAssignment(words[0]) {
			words = words[1:]
		}
		if len(words) == 0 {
			continue
		}
		program := filepath.Base(words[0])
		only, known := builds[program]
		if !known || !slices.ContainsFunc(words[1:], isTestSubcommand) || slices.Contains(words[1:], only) {
			continue
		}
		return program + " " + strings.Join(words[1:], " ") + " would run tests inside the agent sandbox, where loopback is open; " +
			"every test runs inside the game profile (containment/agent-containment.md, Tests). Build them here, then run each " +
			"binary with the sandbox off: \"cargo test --no-run -p CRATE\" prints each Executable, then " +
			config.LauncherDirectory + "/d1-nonet " + filepath.Join(config.Root, "d1-server/target/debug/deps") + "/CRATE-HASH [filter]; " +
			"for Go, \"go test -c -o " + filepath.Join(config.Root, "testbin") + "/ ./internal/...\", then " +
			config.LauncherDirectory + "/d1-nonet " + filepath.Join(config.Root, "testbin") + "/NAME.test [-test.run X]"
	}
	return ""
}

// isTestSubcommand reports whether word is a go or cargo subcommand that runs tests.
func isTestSubcommand(word string) bool {
	return word == "test" || word == "t" || word == "bench" || word == "nextest"
}

// isElevatedToolWord reports whether word names one of elevatedGrants, by name or path.
func isElevatedToolWord(word string) bool {
	_, known := elevatedGrants[filepath.Base(word)]
	return known
}

// commandSegments splits a command at ; & | ( ) { } `, $( and newlines: what bash could run as
// separate commands, as a tripwire reads it (spelling-based, quotes not tracked).
func commandSegments(command string) []string {
	return strings.FieldsFunc(strings.ReplaceAll(command, "$(", ";"), func(character rune) bool {
		return strings.ContainsRune(";&|(){}`\n", character)
	})
}

// firstWordMatching returns the first word of any command segment (commandSegments, assignments
// skipped) that matches, or "". A tripwire: it is spelling-based.
func firstWordMatching(command string, matches func(string) bool) string {
	for _, segment := range commandSegments(command) {
		for _, word := range strings.Fields(segment) {
			if isAssignment(word) {
				continue
			}
			if matches(word) {
				return word
			}
			break
		}
	}
	return ""
}

// testGateOverrides are the variable-name spellings that would drop the test gate from a Rust
// build: any RUSTFLAGS or RUSTDOCFLAGS variable replaces the config file's flags, and a substitute
// compiler, wrapper or linker could leave the archive out.
var testGateOverrides = []string{"RUSTFLAGS", "RUSTDOC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_RUSTC"}

// overridesTestGate returns the first word of command that would build or run a Rust test without
// the test gate, or "": a variable named in testGateOverrides, RUSTC, a CARGO_TARGET_*_LINKER or
// _RUNNER, or cargo's --config. A tripwire, spelling-based like the rest of this file; the gate
// itself is in each test binary.
func overridesTestGate(command string) string {
	words := strings.FieldsFunc(command, func(character rune) bool {
		return unicode.IsSpace(character) || strings.ContainsRune(";&|(){}`'\"$", character)
	})
	for _, word := range words {
		name, _, _ := strings.Cut(word, "=")
		if name == "RUSTC" || strings.HasPrefix(name, "CARGO_TARGET_") && (strings.HasSuffix(name, "_LINKER") || strings.HasSuffix(name, "_RUNNER")) {
			return word
		}
		for _, override := range testGateOverrides {
			if strings.Contains(name, override) {
				return word
			}
		}
		if strings.HasPrefix(word, "--config") && strings.Contains(command, "cargo") {
			return word
		}
	}
	return ""
}

// isAssignment reports whether word is NAME=value with an upper-case shell name.
func isAssignment(word string) bool {
	name, _, found := strings.Cut(word, "=")
	return found && name != "" && strings.Trim(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") == ""
}

// LauncherForm accepts one plain command: D1_* assignments (never D1_NET*), then a launcher from
// the launcher directory spelled exactly, then the program by absolute path (for d1-nonet, a game
// binary built in this repository; for d1-localonly, anything but one), then arguments. No quotes,
// $, backquotes, ; & | < > or newlines, so the launcher is the only program the shell starts, and
// nothing but D1_* variables is added to the environment it starts with. It returns the launcher.
func LauncherForm(command string, config Config) (string, string) {
	for _, character := range command {
		if !strings.ContainsRune(" \t_./:,=@%+-", character) && !isAlphanumeric(character) {
			return "", fmt.Sprintf("sandbox off: %q is not allowed; run one plain command with no shell syntax", character)
		}
	}
	words := strings.Fields(command)
	for len(words) > 0 && isAssignment(words[0]) {
		name, _, _ := strings.Cut(words[0], "=")
		if !strings.HasPrefix(name, "D1_") || strings.HasPrefix(name, "D1_NET") {
			return "", "sandbox off: " + name + " may not be set; only D1_* variables, never D1_NET*, reach the launcher"
		}
		words = words[1:]
	}
	nonet := config.LauncherDirectory + "/d1-nonet"
	localonly := config.LauncherDirectory + "/d1-localonly"
	if len(words) > 0 && words[0] != nonet && words[0] != localonly {
		return "", "sandbox off: " + words[0] + " is not a launcher; start the command with " + nonet + " or " + localonly + ", spelled exactly"
	}
	if len(words) < 2 {
		return "", "sandbox off: run a launcher followed by the absolute path of the program it runs"
	}
	isGame := slices.Contains(gate.GameBinaries, filepath.Base(words[1]))
	switch {
	case words[0] == nonet && !isTestBinary(words[1], config) && (!isGame || words[1] != filepath.Join(config.Root, "d1-server/target/release", filepath.Base(words[1]))):
		return "", "sandbox off: d1-nonet runs only a game binary in " + filepath.Join(config.Root, "d1-server/target/release") +
			", a cargo test binary in " + filepath.Join(config.Root, "d1-server/target/{debug,release}/deps") +
			" or a Go test binary " + filepath.Join(config.Root, "testbin/<name>.test")
	case words[0] == localonly && (isGame || !filepath.IsAbs(words[1])):
		return "", "sandbox off: d1-localonly runs a program named by its absolute path, never a game binary (those run under d1-nonet)"
	case words[0] == localonly && runsTests(words[1:], config):
		return "", "sandbox off: tests run only under d1-nonet, never d1-localonly: every test runs inside the network sandbox (containment/agent-containment.md, Tests)"
	}
	return words[0], ""
}

// runsTests reports whether a program and its arguments run tests: a test binary, or cargo or go
// with a test, bench or nextest subcommand (cargo's t alias included).
func runsTests(words []string, config Config) bool {
	if isTestBinary(words[0], config) || strings.HasSuffix(words[0], ".test") {
		return true
	}
	program := filepath.Base(words[0])
	if program != "cargo" && program != "go" {
		return false
	}
	for _, word := range words[1:] {
		if word == "test" || word == "t" || word == "bench" || word == "nextest" {
			return true
		}
	}
	return false
}

// isTestBinary reports whether path is a test binary built in this repository: a cargo one,
// d1-server/target/{debug,release}/deps/<crate>-<16 hex digits>, or a Go one built with
// "go test -c -o <root>/testbin/<name>.test". Every test runs only under d1-nonet (owner,
// 2026-10-18: "tests are always ran inside containment"; 2026-10-19: any test at all). Cargo
// writes crate names there with "_", so the one "-" is the hash separator.
func isTestBinary(path string, config Config) bool {
	directory, name := filepath.Split(path)
	if directory == filepath.Join(config.Root, "testbin")+"/" {
		stem, found := strings.CutSuffix(name, ".test")
		return found && stem != "" && strings.Trim(stem, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") == ""
	}
	if directory != filepath.Join(config.Root, "d1-server/target/debug/deps")+"/" &&
		directory != filepath.Join(config.Root, "d1-server/target/release/deps")+"/" {
		return false
	}
	crate, hash, found := strings.Cut(name, "-")
	if !found || crate == "" || len(hash) != 16 {
		return false
	}
	for _, character := range crate {
		if character != '_' && !isAlphanumeric(character) {
			return false
		}
	}
	for _, character := range hash {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

// isAlphanumeric reports whether character is an ASCII letter or digit.
func isAlphanumeric(character rune) bool {
	return character < 128 && (character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9')
}

// RootOwned returns "" when path and every directory above it are owned by root, writable by no
// one else and not symbolic links: then no process of the user's can replace the launcher, or a
// directory on its path, between this check and the exec.
func RootOwned(path string) string {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return "the launcher install cannot be trusted: " + err.Error()
		}
		status, readable := info.Sys().(*syscall.Stat_t)
		if !readable || info.Mode()&os.ModeSymlink != 0 || status.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
			return fmt.Sprintf("the launcher install cannot be trusted: %s is %v owned by uid %d; it must be root-owned, not a link, and closed to group and other writes", current, info.Mode(), ownerOf(status))
		}
		if current == filepath.Dir(current) {
			return ""
		}
	}
}

// ownerOf is the owner's uid, or -1 when it could not be read.
func ownerOf(status *syscall.Stat_t) int64 {
	if status == nil {
		return -1
	}
	return int64(status.Uid)
}

// inScope reports whether any of the session's directories is this repository, inside it or
// above it. A directory that is not absolute or cannot be read counts as in scope, as does a
// session with none: the stricter rules then apply.
func inScope(directories []string, root string) bool {
	known := 0
	for _, directory := range directories {
		if directory == "" {
			continue
		}
		known++
		if !filepath.IsAbs(directory) || within(directory, root) || within(root, directory) {
			return true
		}
	}
	return known == 0
}

// within reports whether inner is outer or below it, by file identity, so neither case nor a
// symbolic link changes the answer. An outer it cannot read counts as containing.
func within(outer string, inner string) bool {
	outerInfo, err := os.Stat(outer)
	if err != nil {
		return true
	}
	for current := filepath.Clean(inner); ; current = filepath.Dir(current) {
		info, err := os.Stat(current)
		if err == nil && os.SameFile(info, outerInfo) {
			return true
		}
		if current == filepath.Dir(current) {
			return false
		}
	}
}
