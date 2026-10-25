# Pieces 3 and 4 of the port plan: d1-localonly and d1-agent-hook (2026-10-17)

Built by Claude (Opus 5.5) from the archived Rust to the owner's constraints. Piece 3 is commit
7931534; piece 4 is "piece 4: d1-agent-hook, the PreToolUse hook, with settings and check".
Suite: **42 pass outside the agent sandbox, none skipped** (26 before, 9 piece 3, 7 piece 4).

## Piece 3: `d1-localonly CMD` (`go/cmd/d1-localonly`, `go/profiles/local.sb`)

**Surface.** `local.sb` and `main.go`. Exits: 2 refusal, 64 usage or a game binary, 127 not
found, else CMD's. The refusal is d1-nonet's `gate.Refusal`:
`d1-localonly: REFUSED - "<cmd>" would run without network containment ( <failed items> ); follow
the procedure in containment/agent-containment.md and spec/03-runtime/03.2-recomp-runtime.md section 7; do not
modify, bypass or work around this check; if the procedure does not resolve it, stop and report.`
A game binary: `d1-localonly: d1-recomp runs game code; run it under d1-nonet, whose policy ...`.

**Kept from the Rust:** LOCAL_PORTS; bind and inbound on `localhost:*`; IPv4/IPv6 options
denied; the 12 delegates, `open`/`osascript`, job creation; writes to temp, the repo and
`~/.cargo/{registry,git}` minus the protected files and every directory above one (the
rename-the-parent route); `.sb` and `/private/tmp/claude*`; the probe order and items.
**Changed:** the root is set at build time (`-ldflags -X main.repositoryRoot`), not found from
cwd, because REPO grants writes; home comes from getpwuid (no cgo needed), not `$HOME`. Named
files only (owner): `.git/hooks/` and the `.cargo/` directories became `.git/config`,
`.git/hooks/pre-push` and the two `config.toml`; home needs no deny (not writable). The repo root
is now an exact-path deny (the Rust let `mv <repo> /private/tmp/x` through). Positive controls
added: TCP and UDP to 127.0.0.1:8789, a bind to 127.0.0.1:0, SO_REUSEADDR, a write in `runs/`.

**Kernel-enforced:** every rule above. **Probed per launch:** as listed, plus no open socket and
writes to home, `~/.claude/settings.json`, `~/.rustup/toolchains` and each protected file present.
**Suite only:** directory renames, absent-file creation (`TestLocalOnlyNamedFiles`). **Neither:**
the Mach and job denies (no cgo, as for d1-nonet), and `require_loopback`: Seatbelt admits binds
to 0.0.0.0 and the LAN address under `localhost` (`TestLocalOnlyBinds` measures it), so a server
bound wider is reachable from the LAN, and the macOS firewall is that control.

## Piece 4: `d1-agent-hook` (`go/cmd/d1-agent-hook`, `go/hook/`)

**Surface.** Exit 0 sends the call on to Claude Code's own permission flow; exit 2 with one line
`d1-agent-hook: BLOCKED - <reason>` stops it (the Rust contract, still current Claude Code's
blocking path; a Go panic also exits 2). Reasons: `sandbox off: X is not a launcher; start the
command with .../d1-nonet or .../d1-localonly, spelled exactly`; `';' is not allowed; run one
plain command with no shell syntax`; `GODEBUG may not be set; only D1_* variables, never D1_NET*,
reach the launcher`; `d1-nonet runs only a game binary in <root>/d1-server/target/release`; `the
launcher install cannot be trusted: ...`; `d1-recomp runs game code; start it only as the argument
of .../d1-nonet`; `a command naming an excluded program must be that program alone: ";" starts
another command`; `Edit of P refused: <root>/CLAUDE.md is protected: only the owner edits it,
outside agent sessions; show the owner the change instead (...point 5)`; `the event is not one
this hook can read (...)`.

**Kept:** the launcher form and root-owned anchor; `D1_NET*` refused; paths compared by device
and inode with case-folded missing names, dangling links refused (final review finding 2);
scope (Bash rules for sessions in, inside or above the repo; edits from any session).
**Changed, owner constraints:** excluded commands are admitted, not refused, each only as one
command (heredoc with a quoted delimiter and redirections allowed, so the owner's codex pattern
works; chaining refused, flag or not, in scope); `D1_OWNER_EDIT` is gone (no off switch); the
protected set is named files (`~/.claude/` became `~/.claude/settings.json`; the `.claude/`
directory rule went; the Bash tripwire went too, and is restored: see Follow-ups); `check` drops the firewall, listener, byte-identity and
self-test lines. The hook names `system_profiler` and `log` too: your settings exclude them.

**Guarantees and limits.** The launcher form adds only `D1_*` variables and no redirection, so
nothing on the command line reaches the launcher's startup. It cannot clear what Claude Code's
shell already carries: that environment comes from your shell profile and `settings.json`'s
`env` (no DYLD_* or GODEBUG today), which agents cannot write. Stdio is Claude Code's: a socket
on stdin (the launcher replaces it), pipes on stdout and stderr; a socket on stderr makes the
launcher exit 2 silently. Not covered: sandboxed Bash writing a protected file (the repo is
writable in the agent sandbox; the printed deny rules may or may not reach it, unverified); MCP
tools that write files (`mcp__filesystem` is allowed in your settings); excluded programs, which
run bare by your choice and may write anywhere; a hook binary that cannot start (Claude Code then
lets the call through; `check` shows it); a new git hook planted by code under `d1-localonly`.

## Line counts (excluding tests) and what was not done

* **d1-localonly:** `main.go` 155; shared `gate/local.go` 131, `gate/launch.go` 109, `gate.go` +20.
* **d1-agent-hook:** `main.go` 109; `hook/` 800 (hook 234, protect 231, shell 173, install 162).
  Over 200: the excluded-form parser (the Rust refused those outright), path identity, `settings`, `check`.
* **local.sb:** 52 rule lines, not 30: 54 protected paths at two to four per line.

Not done: no install, no live hook run (the owner's). `d1-nonet` keeps its own copies of what
`gate/launch.go` shares and finds its root from cwd once installed; it was outside this brief.

## Follow-ups (review of pieces 3 and 4, one commit)

* **Bash tripwire restored** (`hook/protect.go` `Tripwire`, called in scope only, after the
  excluded-program rule and before the launcher rule). A command whose text names a protected file, ignoring case, passes
  only with none of `; & > < $(` backquote, newline, `tee`, and every `|` segment a reader (the
  Rust lists). Refusal: `this command names CLAUDE.md, which is protected, and is not a pure read
  (it contains ">"): ... show the owner the change instead (containment/agent-containment.md, point 5)`.
  Two choices beyond the brief. A protected file is spelled by its basename unless another
  protected file shares it or it is a bare word, then by the shortest trailing path that is
  neither (`d1-nonet/main.go`, `.git/config`), so a `sed` on another crate's `main.rs` or a
  `git config` is not refused. Readers must be spelled bare with no `NAME=` before them, and
  `--output`, `--pre`, `--open-files-in-pager`, `--log-file`, git's `-O` and less's `-o`/`-O` are
  refused (each writes a file or runs a program). Tested in `TestHookTripwire` (32 cases).
  **Revised (lead):** an excluded program run alone (`ExcludedForm` admits it) skips the tripwire,
  so the owner's `codex exec` prompts may name CLAUDE.md, game.sb or d1netgate.c; anything chained
  to it is still refused by `ExcludedForm`. Limit: `codex exec -s workspace-write` can write the
  protected files, and the hook cannot stop it, since the owner excluded codex from the sandbox.
* **git as a reader (live hook test, `LIVE-hook-test-2026-10-17.md`):** the subcommand after any
  `-C <dir>` pairs must be log, show, diff, blame, status, grep or ls-files; `-c`, `--config-env`, `-o`, `--ext-diff` refuse.
* **`TestLocalWriteExclusions`** runs the `.sb` and `/private/tmp/claude` mutate probes under
  `local.sb` (REPO this repository, HOME the account's), with the removed-rule control; it shares
  `requireWriteExclusions` with `TestWriteExclusions`, whose checks are unchanged.
* **d1-nonet `prove()`** now takes home from `gate.Home` (two lines: the call and the comment);
  `TestNonet*` pass.
* **README "Install (owner)"**: the macOS firewall is the only control on a server bound to 0.0.0.0
  under `d1-localonly`. The hook paragraph and table row now name the tripwire.

Suite after the follow-ups: **44 pass outside the agent sandbox, none skipped** (2 new).
