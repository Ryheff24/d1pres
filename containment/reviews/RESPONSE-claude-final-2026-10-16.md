# Response to the final review (gate 2), 2026-10-16

The review is `containment/reviews/REVIEW-claude-final-2026-10-16.md`, written by the review session at
9387515. Its verdict: "Not yet. Fix three things, then copy." The code is in b504d55; the docs
follow in the next commit. Status key as in the GPT response:
* **fixed**: code changed, with a control that fails without the change;
* **narrowed**: the route is smaller, and the rest is stated;
* **owner**: a decision or install that is the owner's;
* **peer**: a file the netguard session owns.

| # | finding | status | what changed |
|---|---|---|---|
| 1 | `sandbox.excludedCommands` runs `xcrun`, `xcodebuild`, `codex`, `codesign`, `security` bare | fixed in the hook; **owner** for the settings | `hook::bare_runner`: any segment of any Bash command (split on `; & \| ( ) { }`, backtick, `$(`, newline) whose first word, by name or path, is one of `BARE_RUNNERS` is refused, flagged or not. This applies to sessions in, inside or above the repo. Tests cover eight spellings and four non-matches, and the hook binary was run on a real event: `xcrun /usr/bin/true` with no flag is BLOCKED. `d1-agent-hook check` fails while the settings list them. Removing them is the owner's (README step 2). A consequence: agents in this repo can no longer start Codex. GPT reviews become the owner's to start (README step 6). |
| 2 | `protect` compares paths case-sensitively on a case-insensitive volume | fixed | `hook::real_path` normalizes a path lexically and resolves the existing part with `F_GETPATH`, which returns the stored case. The part that does not exist yet is appended as given. Comparison against the repo and `PROTECTED` is case-folded. Non-ASCII names in the repo and dangling symlinks are refused. Existing targets are also compared by (device, inode) against every protected file, which catches hard links. Tests cover `claude.md`, `Claude.MD`, `Design/agent-containment.md`, a new `Crates/D1-NETGATE/build.rs`, `agents.md` (absent file), `.CLAUDE/`, a dotless-ı name, a hard link to `CLAUDE.md` under `target/`, and a dangling symlink to `AGENTS.md`. They also check that `design/Recomp-Runtime.md` and new unprotected files still pass. `permissions.deny` is probably still case-sensitive and stays depth. Whether sandboxed `touch claude.md` fails is in the README step 3 table. |
| 3 | The local-only allowlist includes `~/.rustup`, `~/.cargo`, `~/Library/Caches` | fixed | The allowlist is now temp space, the repo, `~/.cargo/registry` and `~/.cargo/git`. `home_protected()` denies `~/.cargo/config.toml`, `~/.cargo/config`, `~/.cargo/bin/`, `~/.rustup/` and `~/.claude/` outright. Probes added: `~/.rustup/toolchains`, `~/.cargo/bin`, `~/.cargo/config.toml`, `~/.claude/settings.json`. The sabotage child `toolchain` (the first version's allowlist) must fail the check, and does. Measured: `d1-localonly cargo build --offline -p d1-netgate` still builds. `cargo fetch` runs in the agent sandbox (§7, README). |
| 4 | The `denyWrite` ancestor plan breaks builds or leaves the rename hole | **owner**, both options written down | README step 2 sets out the two options for sandboxed Bash. **(a)** `schg` flags stop every write, rename and addition in the protected paths. They do not stop `mv design x; mkdir design` putting a different file in place; that shows in `check` and the history. **(b)** `denyWrite`, with the positive check (`touch d1-server/crates/d1-recomp/src/x` must succeed) next to the negative ones. `d1-localonly` already closes the rename route with literal denies. Which semantics Claude Code's `denyWrite` has can only be measured with settings changes, which are the owner's. |
| 5 | `~/.claude` is not protected from the file tools | fixed; one **owner** choice | The hook refuses Edit/Write anywhere in `~/.claude/` except `projects/` (agent memory) and `plans/`. `d1-agent-hook settings` adds `permissions.deny` rules for `settings.json`, `settings.local.json`, `CLAUDE.md`, `hooks/`, `agents/`, `skills/` and `commands/`. Both launcher profiles deny all of `~/.claude`. The reviewer also asks to protect `~/.claude/projects/`. That would switch off agent memory; it is left writable for the owner to decide. |
| 6 | Both profiles can write Claude Code's session state | fixed | `(deny file-write* (regex #"^/private/tmp/claude"))` is in both profiles. `/private/var/folders` holds none here: checked, no `claude*` under `*/T/`. Rust and C probes check `/private/tmp/claude-<uid>`. Sabotage children (`harness`) in both profile tests. As a result, game-run outputs move from the session scratchpad to `runs/` (run 162). |
| 7 | The hook passes sessions started above the repo | fixed, wider than asked | Edit/Write of this repo's protected files is refused from **any** session. The `~/.claude` rule, the Bash tripwire and `sandbox-off` apply when the session directory and the repo are the same or one contains the other. Measured on the binary: a session in `~/Documents/projects` is blocked from editing `CLAUDE.md`; one in `/tmp` is too, but its `xcrun` and its own `CLAUDE.md` pass. Making `sandbox-off` global is left to the **owner**, since other projects may need bare commands (README "What it does not stop"). |
| 8 | Four documentation inconsistencies | fixed in ours; **peer** for `agent-containment.md` | `d1-nonet.rs` names `/usr/local/libexec/d1-agent/`. §7's interim line (run through `target/release/d1-nonet` until install) is withdrawn in place. The proposed interim rule (agents do not run game binaries or servers until the install and `check` are done) is written down as pending the owner. The netguard session has proposed the matching point 1 (d1cded1). Its State line and point 1 are its own. |
| 9 | Drop 80 and 8080 from `LOCAL_PORTS` unless a server binds them | kept, with the reason | `d1-responder` binds both by default (`--http-ports 80,8080,31315,8788`). `check` fails if anything else listens on a listed port. Today nothing does (checked). |
| 10 | Residuals | unchanged | Mach send rights, `D1_NETGUARD_FD` provenance, the `d1-activity-host` worker split, the delegate list. The README now says to do the worker split before the hold on servers lifts. |

## "Making the human check small"

Built as proposed, with two changes:
* `d1-agent-hook settings` prints the exact block to merge, so the settings are generated, not
  typed. `check` verifies the same values it prints.
* The agent-side checks are a ten-row table in README step 3, not a script. Most of them test the
  hook and Claude Code's sandbox on tool calls, which only an agent session can make.

`check` before install, on this Mac: every install line FAILs (not installed), the settings lines
FAIL (no hooks or deny rules; the five excluded runners are listed), `sandbox.enabled` is OK, the
firewall is on, "block all" is off, and the listeners are OK. Inside the agent sandbox,
`socketfilterfw` reported the firewall as off: run `check` in your own terminal.

## Verification at b504d55

* `cargo test -p d1-netgate`: 13 lib and 6 callsite tests pass inside and outside the agent sandbox.
* The hook binary was run on real events: unflagged `xcrun` is blocked; `claude.md` edits are
  blocked; `~/.claude/settings.json` is blocked and memory is allowed; a parent-directory session
  is blocked; a `/tmp` session's `CLAUDE.md` edit of this repo is blocked.
* Run 162: `d1-recomp run` under `d1-nonet`, Metal, 15 s, linked and logged into `runs/r162`;
  ended on its time limit, no refusal.

## After re-verification (same day)

The review session re-verified b504d55/4e7b023: blockers 1–3 are closed (its "Re-verification"
section). Its verdict: copy once the owner approves the peer's point 1 and the interim rule. It
also gave three non-blocking points, and corrected F4 (a) by measurement. All are applied:
* **F4 (a) recipe.** A flag on a directory stops renaming it and adding or removing entries,
  and leaves its unflagged files editable. README step 2 now flags the protected files, the
  protected directories (recursively) and each in-repo ancestor (non-recursively). With that,
  `mv design x` fails too.
* **`check`, identity.** When the installed binary and `target/release` differ, the line names
  d1-netgate's last commit and whether the tree is clean, and says what to do. An agent's
  rebuild then does not read as an unexplained FAIL.
* **`check`, excludedCommands.** It is now an allowlist: anything but `log stream`/`log show`
  and `system_profiler` FAILs. Before, only entries that were themselves bare runners failed.
  A test covers an unknown runner (`python3 *`).
* `socketfilterfw` wording confirmed by measurement; no change.
