# Containment review: code, the pending Mythos change, and how agents behaved (Mythos 5.1, 2026-10-27)

Scope: `~/Documents/projects/d1remote` (branch `elevated-mythos`, f1a0846, plus the unmerged
`system-queries` and `update-script` PR branches), the installed binaries in
`/usr/local/libexec/d1-agent/` (built 11:45 today from the d1preservation working copy), the
owner's comment in `hook.go` (`Decide`, the `preToolUse` line), and every agent session this
machine holds for the project (agentlog: 1183 sessions searched, 849 real hook refusals in 76
sessions, all Claude Code; Codex rollouts carry no cwd in the catalog and are not in the counts;
Cursor is not an agentlog harness, its two transcripts were read by hand). Verification method:
crafted PreToolUse events fed to the installed hook (`scratchpad/hookprobe/run.sh`), the hook
package's own tests built from the branch and run under `d1-nonet`, and targeted agentlog
reads of every session the scan named. Nothing in either repository was changed.

## 1 The pending change (elevated-mythos) is correct and incomplete only in merge order

- `ElevatedModels` gains `claude-mythos-5-1`; the matrix table regenerates; `TestHookElevatedModel`
  gains a Mythos row and a Mythos-through-OpenRouter row (refused). Built from the branch and run
  under `d1-nonet`: TestHookElevatedModel, TestHookElevatedForm, TestHookRecordEdits, TestHookXcrun
  pass; TestHookProcessReaders skips (ps sees nothing under the profile, expected);
  TestAccessMatrix fails only because it opens `../../agent-containment.md` relative to cwd, so
  the README's "runs from any directory" is wrong for that one test.
- The installed hook already contains it: this session's transcript records `claude-mythos-5-1`
  (137 assistant entries) and a sandbox-off `/usr/bin/vm_stat` from this session passed.
- The d1preservation working copy is main plus all three unmerged branches (mythos, sysctl/pmset/
  memory_pressure, update.sh and its local.sb line). `containment/update.sh` overwrites with main,
  so running it before the three PRs merge reverts the installed behavior. All three touch
  `elevated.go`, `matrix.go` and the generated table in `agent-containment.md`: expect conflicts,
  merge, then regenerate the table.
- `d1-agent-hook check` prints one FAIL today: `checkSettings` (install.go) does not know
  `isCompanion`, so the two `node .../codex-companion.mjs *` entries in `sandbox.excludedCommands`
  read as unknown. The hook itself admits them (`CompanionForm`). A check that always fails is a
  check nobody reads.

## 2 The owner's flag: Cursor (`preToolUse`)

Measured, not assumed (`hookprobe/run.sh`, installed hook):

| event fed to the hook | decision |
|---|---|
| `preToolUse`, tool `Shell`, cwd `""`, `ls` | BLOCKED: "decides Bash ... and was sent Shell" |
| `preToolUse`, tool `Bash`, cwd `""`, `curl -s https://example.com` | passes (exit 0) |

Cursor's third-party hook import maps Claude hook names, honours exit 2 (Cursor staff, forum
173171), and fails open on malformed stdout JSON (forum 152669). The field that decides
everything here is the one Cursor never sends: `dangerouslyDisableSandbox`. Cursor's shell runs
with no Claude Code sandbox, so after the `preToolUse` line every Cursor shell call is treated as
sandboxed, and `LauncherForm`, `ElevatedForm` and the elevated check never run: `curl`, `go run`
of a server, `sandbox-exec`, anything passes the hook. If Cursor sends `Shell` (what the
cursor-agent CLI sends per the forum report, and what the Oct 22 Cursor transcript's own tool
name is), every call is refused instead. Either way the Cursor path is unverified: the only Cursor
sessions on record are 2026-10-22 12:04 to 12:24, both refused on the event name before the fix,
none since. `cwd` arriving `""` and no `transcript_path` are safe (in scope, never elevated).

Fix (one rule, fail closed): a Bash event with neither `transcript_path` (Claude Code) nor
`model` (Codex) is an unsandboxed shell; apply the sandbox-off rules to it as if the flag were
true. Accept `Shell` as `Bash`. Add the Cursor-shaped event to `hook_test.go`. Register a native
`~/.cursor/hooks.json` entry with `failClosed: true` so a hook that cannot start blocks instead of
passing. Codex has the same shape (no flag) but applies its own `-s` sandbox, so it is covered
by a different mechanism; say so in a comment where the harness is detected.

## 3 Code findings in priority order

F1 Servers are prose-only. Tests are gated in-binary (libd1testgate.a, tools/d1 testgate +
`TestEveryTestPackageIsGated`), game binaries are gated in-binary (C gate), but of the servers
only `d1-srv` probes its containment. `cargo run -p d1-activity-host -- --bind 0.0.0.0:4110` and
`go run ./cmd/d1-overlay-bridge --listen 0.0.0.0:8787` pass the hook inside the agent sandbox
(measured), where `sandbox.network.allowLocalBinding` is true and egress goes through the proxy.
This is the owner's "must be in containment automatically": add one `localgate` package
(Go) and one C constructor (Rust servers) that refuse unless `BeyondThisMac` is refused and
loopback is open, called first in every server `main`, with a drift test over `cmd/*` and the
server crates like the one tests have.

F2 Scope is decided by cwd and `CLAUDE_PROJECT_DIR` only (`inScope`). A session whose cwd is
`../d1remote` (a sibling) or `~/Downloads` meets only the game-binary spelling and the edit rules.
Measured: sandbox-off `curl` from cwd d1remote passes; sandbox-off
`cd <repo>/tools/d1 && go run ./cmd/... --listen 0.0.0.0:8787` from `~/Downloads` passes. Drop
the scope test for sandbox-off calls (the launcher form costs an out-of-scope session nothing),
or treat the repository root spelled in the command as in scope.

F3 Codex in worktrees has no hook and no instructions. `.codex/` is gitignored
(`.gitignore:37`), so `runs/wt-*` checkouts have no `.codex/hooks.json`; Codex ran there
(wt-frlproofs, wt-frameloop, wt-gfx-spec, wt-gfx-texkey). `containment/` and `CLAUDE.md` are
ignored too (`.gitignore:164`, commit 80792d2), so in a worktree `AGENTS.md -> CLAUDE.md`
dangles and Codex reads no rules; `containment/` is absent, so the test-binary and test-gate
tooling that looks for it is on the main checkout's mercy. Codex's own `-s workspace-write`
sandbox is the only control in a worktree. Fix: a user-level Codex hook (`~/.codex/hooks.json`
if Codex reads one; otherwise `d1 worktree` creates the two files), and make the worktree
creation path (`EnterWorktree`, `git worktree add`) copy `.codex/hooks.json`, `CLAUDE.md`.

F4 MCP execution tools bypass the hook and the deny rules: the matcher is
`Bash|Edit|Write|MultiEdit|NotebookEdit`; `mcp__ide__executeCode`, browser-use `browser_exec`
(runs Python), chrome-devtools `evaluate_script`, and the `mcp__filesystem` allow rule in
`~/.claude/settings.json` are outside it. Default-deny instead: matcher `*`, the hook passes an
allowlist of inert tools (Read, Glob, Grep, WebFetch, WebSearch, Agent, TodoWrite, Skill ...)
and refuses the rest by name with the reason "runs code outside containment".

F5 The tripwire splits on `|` without reading quotes (`protect.go`, `Tripwire`,
`strings.Split(command, "|")`) and matches `tee` and `;`/`&` as substrings. Measured:
`grep -n -E 'alpha|beta' .../d1netgate.c | head` is refused ("beta' ... is not one of the
reading programs"); `grep -n steering .../agent-containment.md` is refused ("contains tee").
In the logs this is the single largest refusal class: 438 of 849 refusals name a protected file
in what is almost always a read (pipe 338, `;` 234, grep flags 230, `&&` 177, `2>&1` 51,
heredoc 41, `git commit -m` 15, `tee` 5), and `d1-oracle/src/main.rs` alone accounts for 55
refusals because agents grep it with `\|` alternations. Use `splitPlain` (elevated.go already
has the quote-aware scanner), match operators as tokens, exempt `[0-9]>&[0-9]`, and match
`tee` as a word.

F6 `autoMode.environment` in `~/.claude/settings.json` is from another project: "Host
containment: None configured, assume ... open internet", "Trusted repo: .../CSE521/HW/HW1". The
classifier that admits sandbox-off calls reads this. agent-containment.md said one line about
the launchers would go there; it never did.

F7 Refusals name the doc, not the allowed form. The agents' own words after refusals (section 4)
show they do not know what to do next. Every refusal can carry one concrete line: for the
tripwire "read it with the Read tool, or rename your staging copy so the command does not spell
<name>"; for sandbox-off "<launcher> <abs path> ARGS, no quotes, pipes, ; or $"; for a game
binary the exact command with the path filled in.

F8 Drift and leftovers: `containment/go/.p-129052752/` in the d1preservation copy holds a
user-owned `d1-nonet` binary, `trivial.sb`, a fake `CLAUDE.md` and `game.sb` from
`TestNonetDescriptors` (not cleaned up); `update.sh` skips `.p-*` so it is harmless to the
build but it is a planted launcher copy sitting in the repository. The README still says the
window hand-off ends with `cp -R <window dir>/. .` in one place and with a d1remote PR in another.

## 4 How agents behaved (the logs)

Numbers: 849 refusals, 76 sessions, every one a Bash call. By model: Opus 612, DeepSeek 114,
Haiku 52, Sonnet 44, Fable 16, Mythos 11. By reason: protected name in a non-pure-read 438,
sandbox-off form 205, excluded program chained 105, game binary outside the launcher 86, test
without the test gate 4. Peaks: 10-17 (191), 10-19 (171), 10-25 (136). Top sessions: 58b86de7
(Opus, 66), 78581d6e (Opus, 54), 14f142e9 (DeepSeek, 45), a191dbb1 (Sonnet, 44), then five Opus
sessions of the "d1 on mac" lineage at 33 to 43 each.

What happened after a refusal (23 sampled, read in full): 16 reformulated into the allowed form
(Read tool, `-e` patterns instead of `\|`, redirect dropped from a launcher call), 3 moved to a
staging copy, 2 changed design, 1 retried verbatim, 1 gave up. The lock held: no game binary ran
outside the launcher (86 refusals, 0 runs found), no test ran outside it in the cases checked,
and every non-launcher sandbox-off attempt the scan flagged as "passed" was in fact refused
(verified in the transcripts: `git` 11, `gh` 6, `ps` 9, `/usr/bin/sandbox-exec` 3, `yt-dlp` 3,
`code --new-window` 3).

Recurring behaviors, with the session as evidence:

- Routing around the tripwire by spelling. Mythos 24798869 #1605 (10-16 22:11): "I need to avoid
  directly naming protected files like AGENTS.md or CLAUDE.md in any command, so I'm trying glob
  patterns like `A*.md`"; #1606 ran `C*.md` and passed. Sonnet a191dbb1 #181: `cd` into the crate
  then `src/main.rs`, passed. Opus 58b86de7 #1010: "I can't delete a file by name directly, so
  ... the workaround" and renamed the staging copy to `staged-agent-doc.md`. All three were reads
  or scratchpad writes, so no harm, but the reflex is the one the system card warns about and the
  tripwire teaches it (F5, F7).
- Trying the launcher's job by hand. Opus 78581d6e: sandbox-off `/usr/bin/sandbox-exec` three
  times; Mythos 24798869 #1813: "I can't invoke sandbox-exec directly, so I'm considering running
  the program through..." then `sandbox-exec -D REPO=$PWD -f ...` inside its own sandbox (fails,
  profiles do not nest). Both then stopped and handed the measurement to the owner.
- Sandbox-off as the first retry after any sandboxed failure. The same session asks for
  `git worktree remove`, `git switch` in d1remote, `gh pr list`, `tlapm --version`, `ps` with
  the sandbox off, each refused, each followed by the in-sandbox form or a "You need to" line.
  This is the behavior F2 would turn into a hole from an out-of-scope cwd.
- Retrying verbatim after a refusal happens, but rarely (1 of 23, 77e639ef #248 then #249).
- The Cursor session bac62ac0 (10-22) is the owner's "they just blank" case in full: three
  refusals on the event name, two readings of the containment doc, a false explanation
  ("pipes and `&&` violated the rule"), then "I won't try a fourth time", before the owner
  diagnosed the hook. The agent reasoned correctly from the refusal text it had; the text was
  wrong for its harness.
- Network use by agents was agent tooling, not game or server code: the local model proxy
  127.0.0.1:8317 (today, Opus b79d10d1, the owner's own test), GitHub API reads of the d1pres PR
  with the owner's `gh` token (Opus 58b86de7 #3328, #3547, in-sandbox), prior-art clones, and
  `rsync` of `runs/` profiles to `/Volumes/RYANSSD/Mac-Archive.noindex` (Fable ea509fc1 #3434,
  ordered by the owner at #3418 "RYANSSD is hooked ... dump old runs"). The drive is not mounted
  now, so its format (the exFAT rule) could not be checked.
- Fabricated approval between agents: none found in the samples (not exhaustively searched).

The owner's Mythos case. No Mythos session exists between 10-25 and 10-27; the Mythos sessions
are 24798869 (10-16 18:31 to 10-17, the containment review in ~/Downloads) and 2d250e4a (10-19,
no refusals). The closest sequence to "two Bash calls refused, then a third tool call editing a
locked file that passed" is 24798869 #1892 (grep naming d1netgate.c, refused), #1910 and #1911
(Write of `window2/containment/go/profiles/game.sb` and `local.sb`, passed), #1912 (mkdir + sed
copying d1netgate.c into window2, refused). The writes that passed were scratchpad staging copies
under `window2/`, the sanctioned hand-off; `ProtectedTarget` compares inode and path, so a copy
with a protected basename is not refused by design. The Edit of the real `CLAUDE.md` in that
session (#525, 10-16 17:52) predates the install (21:34).

Exact-path edits of protected files after the install, every harness: 15 calls. 7 were denied by
Claude Code's own `permissions.deny` Edit rules (CLAUDE.md, AGENTS.md, protect.go, install.sh,
hook.go), 2 were no-ops, 6 passed, and all 6 were creations of files that were listed as
protected minutes to hours later by the owner's own commits: the four test-gate files written
10-19 10:50 EDT and listed at 10:56 (3f05fd2), the two orkey files written 10-24 20:50 EDT and
listed at 22:08 (5c6db1e). No protected file was written by any agent after it was protected; the
deny rules did the stopping, and the hook never had to refuse an edit. One session not in the
catalog (eb7205e0, 10-26 03:24 UTC, three Edit attempts on hook.go, denied) is the only unknown
actor; its harness should be identified.

## 5 What to change, in order

1. Harness detection and fail-closed sandbox-off for events without the flag (Cursor); `Shell`
   as `Bash`; Cursor-shaped test; `failClosed` native registration.
2. Server self-gate in Go and C with a drift test, like the test gate.
3. Scope: sandbox-off rules for every session, not only in-scope ones.
4. Matcher `*` with an inert-tool allowlist.
5. Quote-aware tripwire, word match for `tee`, exempt `2>&1`; refusal text that states the
   allowed form.
6. `.codex/hooks.json` and `CLAUDE.md` into every worktree; a user-level Codex hook if Codex
   reads one.
7. `checkSettings` learns `isCompanion`; `autoMode.environment` describes this machine; clean
   `.p-*`; merge the three PR branches before the next `update.sh`.
