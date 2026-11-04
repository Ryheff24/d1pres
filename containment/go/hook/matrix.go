package hook

import "strings"

// Row is one line of the access control matrix: a capability, what a session on one of
// ElevatedModels gets, what a session on any other model gets ("no", or "yes" and its limits), and
// the code that enforces it. TestAccessMatrix runs probes of every row through Decide for both kinds
// of session, and checks that agent-containment.md shows exactly MatrixTable().
type Row struct {
	Capability string
	Elevated   string
	Other      string
	Enforced   string
}

// suiteTested marks the rows the hook does not decide: the launchers' profiles enforce them, and
// the containment suite (containment/go, run by install.sh) tests them.
const suiteTested = "the containment suite tests them"

// AccessMatrix is who gets what, from the hook's side (owner, 2026-10-25: "an access control matrix
// would solve most of the who gets what permissions confusions"). The rows hold for sessions working
// in, inside or above this repository; a session elsewhere meets only the game-code row. The owner,
// in their own terminal, is outside the hook.
var AccessMatrix = []Row{
	{"Bash inside the sandbox", "yes: the sandbox's own limits", "yes: the sandbox's own limits",
		"Claude Code's sandbox; the hook passes it"},
	{"Bash that names a protected file or tree", "yes: pure reads only, read as bash reads the line (a quoted or escaped pipe is text, 2>&1 writes no file, tee is a word)", "yes: pure reads only, read as bash reads the line (a quoted or escaped pipe is text, 2>&1 writes no file, tee is a word)",
		"Tripwire (protect.go)"},
	{"Edit, Write or apply_patch of a protected file (gate.ProtectedFiles, ~/.claude/settings.json)", "no", "no",
		"ProtectedTarget (protect.go)"},
	{"Edit, Write or apply_patch under a protected tree (gate.ProtectedTrees: containment/go, containment/c, .claude/hooks, .git/hooks), or of either in a worktree", "no", "no",
		"ProtectedTarget, worktreeTarget (protect.go)"},
	{"Edit, Write or apply_patch of the session records (~/.claude/projects except each memory/, ~/.codex/sessions)", "no", "no",
		"RecordsTarget (elevated.go)"},
	{"Game code: d1-recomp, d1-oracle, d1-replay, d1-srv", "yes: only as d1-nonet's program, sandbox off", "yes: only as d1-nonet's program, sandbox off",
		"decideBash, LauncherForm (hook.go)"},
	{"Running tests (cargo and Go test binaries)", "yes: only under d1-nonet; go test and cargo test are refused in the sandbox unless they only build (-c, --no-run)", "yes: only under d1-nonet; go test and cargo test are refused in the sandbox unless they only build (-c, --no-run)",
		"runsTestsInSandbox, LauncherForm (hook.go); the test gate in each binary"},
	{"Servers and other programs that listen", "yes: only under d1-localonly, sandbox off, never a game binary or a test", "yes: only under d1-localonly, sandbox off, never a game binary or a test",
		"LauncherForm (hook.go)"},
	{"Codex through the plugin's companion script", "yes: setup, task, status, result, cancel, alone; no reviews", "yes: setup, task, status, result, cancel, alone; no reviews",
		"CompanionForm (shell.go)"},
	{"The owner's sandbox-excluded programs: xcodebuild, codesign, system_profiler, codex exec", "yes: alone, the line through the tripwire, no redirection into a file and no codex -o (they run outside the sandbox, so the file would be opened after the check); codex only with its own sandbox left on; codesign only to display or verify, to standard output", "no",
		"decideBash (hook.go), ExcludedForm, codexForm (shell.go)"},
	{"copilot (its pinned path no longer exists, it has no sandbox of its own, and --allow-tool shell grants what --allow-all was refused for)", "no", "no",
		"ExcludedForm (shell.go)"},
	{"Read-only logs and profilers: log show and stream, xctrace export and list, sample, vmmap, footprint, malloc_history, metalperftrace overview and listen", "yes: at its own path, alone, one line of plain words or '...' text, listed options only, this project's processes by PID and files in the repository only, no output files", "yes: at its own path, alone, one line of plain words or '...' text, listed options only, this project's processes by PID and files in the repository only, no output files",
		"ProfilerForm, profilerSpecs (profiler.go)"},
	{"security (also sandbox-excluded)", "yes: find-identity only", "no",
		"ExcludedForm (shell.go)"},
	{"xcrun (also sandbox-excluded)", "yes: SDK queries; simctl, devicectl", "no",
		"xcrunForm (shell.go)"},
	{"Inspecting processes, memory and network: ps, pgrep, lsof, nettop, top, vm_stat, leaks, heap", "yes: sandbox off, alone or piped into grep, head, tail, wc; no writing options; nettop and top only with -l", "no",
		"ElevatedForm, elevatedGrants (elevated.go)"},
	{"Reading system state: sysctl, pmset, memory_pressure", "yes: sandbox off, alone or piped into grep, head, tail, wc; sysctl without -w or name=value; pmset -g only; memory_pressure alone or -Q", "no",
		"systemForm (elevated.go)"},
	{"Stopping processes: kill, pkill, killall", "yes: sandbox off, this project's processes only", "no",
		"killForm, projectProcess (elevated.go)"},
	{"Opening files in VS Code: code", "yes: sandbox off, -r or -g, up to 20 existing files in this repository; no folders, workspaces, .vscode, .git", "no",
		"codeForm (elevated.go)"},
	{"Anything else with the sandbox off", "no", "no",
		"LauncherForm (hook.go), ElevatedForm (elevated.go)"},
	{"Network from game code and from servers", "game code none; servers this Mac only", "game code none; servers this Mac only",
		"game.sb, local.sb and the C gate; " + suiteTested},
}

// MatrixTable is AccessMatrix as the Markdown agent-containment.md shows.
func MatrixTable() string {
	lines := []string{
		"Elevated models: `" + strings.Join(ElevatedModels, "`, `") + "`. Every other model, Claude Code subagents included (each by its own model), is the second column.",
		"",
		"| capability | elevated models | every other model | enforced by |",
		"|---|---|---|---|",
	}
	for _, row := range AccessMatrix {
		lines = append(lines, "| "+strings.Join([]string{row.Capability, row.Elevated, row.Other, row.Enforced}, " | ")+" |")
	}
	return strings.Join(lines, "\n") + "\n"
}
