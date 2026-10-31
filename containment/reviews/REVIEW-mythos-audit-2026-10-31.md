# Containment audit: source, installed binaries and live use (Mythos 5.1, 2026-10-31)

Scope: `../d1remote` `origin/main` (3c5b281, PR #7), which is byte-identical to the
d1preservation copy of `containment/` (three review files are local only); the installed
binaries in `/usr/local/libexec/d1-agent/` (built 2026-10-30 16:12, root-owned, mode 0755, the
profiler rules present); `~/.claude/settings.json`, the project's `.claude/settings.local.json`
and `.codex/hooks.json`; `~/.codex/config.toml`. Method: every rule file read; 57 crafted
PreToolUse events fed to the installed hook (`scratchpad/probe.py`, `probe2.py`; 7 controls,
all as expected); write probes from the agent's own Bash sandbox (open for append, nothing
written; create and remove in directories, as `gate.Writes` does); two real Write-tool probes
into `.git/hooks/` and `.claude/hooks/` (dotfiles, removed afterwards through `d1-localonly
/bin/rm`); one Go test package run inside the agent sandbox. No file's content was changed.
The 2026-10-27 review (`REVIEW-mythos-containment-2026-10-27.md`, F1 to F8) is still open in
full: F2, F4, F5 and F8 were re-measured today and are unchanged. This file lists only what is
new or sharper.

## 1 The owner's flag in `hook.go` (the `preToolUse` line)

The line itself is right: an event whose name is not `PreToolUse` or `preToolUse` is refused,
and an event with no name at all is decided (E1 to E3). The gap is below it, not in it:

- A Cursor-shaped event (`beforeShellExecution`, `command` at top level, no `tool_input`) is
  refused outright: "the event is not one this hook can read (unexpected end of JSON input)",
  so under that shape every Cursor shell call is blocked, which matches "it would always error".
  Whether Cursor today sends `tool_name: "Bash"` with a `tool_input` could not be checked:
  `~/.cursor/hooks.json` does not exist and the project has no `.cursor/`, so no Cursor hook is
  registered on this Mac at all. The 2026-10-27 fix (treat an event with neither
  `transcript_path` nor `model` as an unsandboxed shell; accept `Shell`) stands.
- The owner's wider complaint is measured in this session: six of my own read-only commands were
  refused by the tripwire (`;` after a protected name, `|` inside a grep alternation, the word
  `metalperftrace` inside a grep pattern routed to `ProfilerForm`). F5's fix (token-wise,
  quote-aware tripwire; `tee` as a word) is the one that stops agents "blanking".

## 2 New findings, most severe first

**N1. Two unsandboxed code paths are open to every model through the Write tool.**
`.claude/settings.local.json` (protected) runs `sh .claude/hooks/owner-inbox.sh` on every
PostToolUse and on Stop, outside any sandbox. The script is not protected: a Write event for it
passes the hook (H7), and a real Write of a dotfile into `.claude/hooks/` succeeded. Likewise
`.git/hooks/` accepts a Write-tool file (measured); only `pre-push` is protected, so a
`pre-commit` or `post-checkout` hook would run in the owner's terminal at their next git command.
Bash in the agent sandbox is refused on both directories (Claude Code's own denial), so the
Write tool and `d1-localonly` are the open routes; under `local.sb` the `rm` of both probes
succeeded, which means a contained server can create files there too (the directory `literal`
rules stop renames, not entries). Fix: add `.claude/hooks/owner-inbox.sh` and every git hook
name to `gate.ProtectedFiles` (or protect the two directories as a whole), and add the same to
`local.sb` as `subpath` denies.

**N2. ExcludedForm skips the tripwire, so a redirection or an output option can overwrite a
protected file outside the sandbox (the screenshot's item 2, confirmed).** Admitted by the
installed hook: `xcodebuild -version > CLAUDE.md`, `security find-identity > CLAUDE.md`,
`system_profiler ... > game.sb`, `codex exec -s read-only -o ~/.claude/settings.json -`
(G15, G16, H1 to H4), with the sandbox on or off: `sandbox.excludedCommands` runs them outside
the sandbox either way. Elevated models only. Fix as the owner wrote: `Tripwire(
withoutHeredocBody(command))` on the command line before `ExcludedForm` returns "", and refuse
`-o`/`--output` for codex.

**N3. ExcludedForm admits the flags that turn the excluded programs' own sandboxes off.** The
bundled codex has `--dangerously-bypass-approvals-and-sandbox`, `--dangerously-bypass-hook-trust`
and `-c sandbox_mode=...`; all three pass (G17, H16, H17). `copilot -p ... --allow-tool shell`
passes (G18, G19): `copilotBlanket` refuses only `--allow-all*` and `--yolo`, and a shell tool
grant is the same thing. The pinned copilot path does not exist on this Mac (nvm is on v22.23.4
now), so `copilot` only runs bare, resolved on PATH. For elevated models these are arbitrary code
outside every sandbox. Fix: a per-program option denylist in `ExcludedForm` (codex: both
`--dangerously-*`, `-c`, `--config`, `-o`; copilot: `--allow-tool` values that name shell or
write, `--add-dir`), and drop copilot until its path is real.

**N4. The hook's own rule files are editable (the screenshot's item 2, confirmed and wider).**
Write passes for `containment/go/hook/profiler.go` (a rule file: every model's profiler form),
`matrix.go`, `go.mod`, a new `hook/planted_test.go`, `README.md`,
`netguard-requirements.md`, `settings-allow.sh` and `.codex/hooks.json` (G3 to G11); from the
sandbox `profiler.go`, `.codex/hooks.json`, the `hook/` directory and `.gocache/` are writable
too. What makes these matter: `install.sh` runs `go test ./...` and `go build` on the checkout as
the owner, with `GOCACHE` pointing at the agent-writable `.gocache/`, so a planted or edited file
runs in the owner's terminal and a poisoned cache can make a failing control pass. `update.sh` is
safe against edited tracked files (it checks main out over them) and stops on extra files under
`go/` and `c/`, but it keeps `.gocache/` and the README still offers `install.sh` alone.
`settings-allow.sh` is run by the owner with `bash` and is unprotected. `.codex/hooks.json`
is what makes Codex run this hook (Codex trusts it by hash in `~/.codex/config.toml`; an edit
makes it untrusted, and what Codex then does with an untrusted hook is unverified). Fix: protect
every file under `containment/go` and `containment/c` and `.codex/hooks.json` (the list is
"named files only" by the owner's 2026-10-16 rule; a `subpath` deny in `local.sb` and a
prefix rule in `ProtectedTarget` would do it without listing tests one by one); `install.sh`
uses a fresh `GOCACHE`; the README says `update.sh` only.

**N5. `install.sh` builds in the owner's temporary directory, which contained processes may
write.** `build=$(mktemp -d)` and `control=$(mktemp -d)` land under
`/var/folders/.../T/` (measured: `DARWIN_USER_TEMP_DIR`), and both `game.sb` and `local.sb`
allow writes under `/private/var/folders`. A game or server process running during the install
(two were running during this audit) could replace a built binary between `go build` and
`sudo install`. `update.sh` already uses `$HOME` for its clone for exactly this reason. Fix:
build under `$HOME` or a root-owned directory, or `sudo install` from a directory created with
`mktemp -d "$HOME/..."`.

**N6. Worktree copies of protected files are not protected, and worktrees lack
`containment/`.** `.claude/worktrees/*` and `runs/wt-*` hold their own
`d1-server/crates/d1-recomp/src/main.rs` (the gate call site) and `build.rs`; a Write there
passes (G12). The hook refuses a game binary by name wherever it is, and `LauncherForm` admits
only `<root>/d1-server/target/release`, so a rebuilt gate-less copy cannot be run through the
launcher, but it can be run bare inside the agent sandbox under another name, where loopback is
open (`allowLocalBinding`) and egress goes through the proxy. Also `runs/hookstage`, `runs/hs-v2`,
`runs/hs-v4` and one worktree hold full copies of `containment/go`. Fix: protect the
repository-relative names in every worktree (match by suffix under `.claude/worktrees/*` and
`runs/wt-*`), and `d1 worktree` copies `containment/`, `CLAUDE.md` and `.codex/hooks.json`.

**N7. Tests still run outside containment when they do not carry the gate.** `go test ./...`
in `tools/d1` passes the hook with the sandbox on (G13), and the sandbox has loopback TCP open
(measured: connect to 127.0.0.1 gets `EINPROGRESS`, 192.0.2.1 gets `EPERM`). The Go gate does
refuse where it is imported (measured: `internal/testgate` exits 2 inside the sandbox), but
seven of the 24 package directories with tests have no file importing it: `cmd/d1-srv`,
`cmd/roadmap-check`, `internal/perfscan`, `internal/r01cmp`, `internal/renderm`,
`internal/sched`, `internal/viewdiff`. Either `TestEveryTestPackageIsGated` has a narrower
criterion than "every package with tests" or it is not run by agents (it lives in the gated
package, which refuses to start inside the sandbox). This is the owner's "tests included"
rule not holding at the code level. Fix: the control's walk counts every directory with a
`_test.go`; the hook refuses `go test` and `cargo test` without `-c`/`--no-run` in scope
(the documented build-then-launch form stays admitted, H19).

**N8. `Elevated` trusts `model` in the event and then skips the base-URL check** (E5: an event
carrying `model: claude-opus-5-5` with `ANTHROPIC_BASE_URL` at the local proxy passes; without
the field it is refused, E6). Today only Codex sends the field, so this is a fragility, not a
breach: the day Claude Code adds `model` to its events, every proxy session names itself.
Fix: apply the base-URL rule whenever `transcript_path` is present, whatever else the event
carries.

**N9. Sandbox-off from a session elsewhere is unlimited here** (G23: `cp x <repo>/CLAUDE.md`
with cwd in another project passes; the Write tool is still refused, G24). F2 of 10-27, now
with the write case measured.

## 3 What held (controls)

Pure reads of protected files pass; `tee`, `;`, `&`, `>` refuse them. Edit and Write of every
listed protected file and of `~/.claude/settings.json` refuse from any cwd. A bare game binary
refuses by name; the launcher form passes and `RootOwned` holds on the install. An unknown
model is never elevated; a proxy base URL demotes. `ProfilerForm` refuses `>` and a second
line. `ExcludedForm` refuses `&&`. The agent sandbox denies writes to every protected file
(Claude Code turns the deny rules into sandbox denials, as the README says), to `~/.cargo`,
`~/.claude/projects`, `/tmp` and every PATH directory, so a planted excluded program cannot be
found on PATH. The Go test gate refuses inside the sandbox. The d1remote source and the
installed hook agree (the profiler rules are in the binary).

## 4 Order of work

1. N1 (protect the two hook directories; `local.sb` subpath denies).
2. N2 and N3 (tripwire on excluded commands; option denylists; drop the dead copilot path).
3. N4 and N5 (protect all of `containment/go` and `c`, `.codex/hooks.json`,
   `settings-allow.sh`; fresh `GOCACHE`; build under `$HOME`; README: `update.sh` only).
4. N7 (test control over every tested package; refuse in-sandbox `go test`/`cargo test`).
5. 10-27 items 1, 3, 4, 5 (Cursor fail-closed, scope, matcher `*`, token-wise tripwire).
6. N6, N8, N9; then the docs: `agent-containment.md` carries three superseded designs and a
   "proposed text" for a rule that has been in force since 10-17; move them to a decisions
   file so the active doc is the matrix and the command table (the screenshot's item 1).
