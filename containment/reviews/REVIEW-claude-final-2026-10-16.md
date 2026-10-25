# Final review (gate 2): the network-containment collection at 9387515

Reviewer: Claude (Mythos 5.1), 2026-10-16, at the lead's request, before the procedure is copied
into `CLAUDE.md` and `AGENTS.md`. Read: everything `containment/README.md` lists,
the GPT 6.1 sol review and the response to it, and my three earlier reviews. Three measurements on
this Mac, none touching the repo: `realpath(3)` case behaviour, the owner's `~/.claude/settings.json`
sandbox block, and the current loopback listeners. Nothing built, run or changed in the repo.

## Verdict

**Not yet. Fix three things, then copy.** The design is now anchored in the right place (a
root-owned launcher directory, an exact-path rule, profiles with write allowlists), and every
finding from the three earlier reviews is either closed in code or stated as the owner's decision.
But three gaps undo the stated rule in practice, each cheap to fix:

1. The owner's own `sandbox.excludedCommands` already runs ten command families outside the
   sandbox without the flag the hook keys on. `xcrun`, `xcodebuild`, `codex exec` and `security`
   run bare today, with network, and the `sandbox-off` rule never sees them.
2. The `protect` rule compares paths case-sensitively on a case-insensitive volume, and macOS
   `realpath` does not correct case (measured). `Edit /repo/claude.md` edits `CLAUDE.md` and passes.
3. The this-Mac-only write allowlist includes `~/.rustup` and `~/.cargo` wholesale. The toolchain's
   `rustc` and `cargo` live there (measured: `~/.rustup/toolchains` exists). Replacing them plants
   code the owner's next unsandboxed build runs, which is GPT finding 3 again by another door.

The rest below is depth, documentation, or the owner's call. The last section is about the
owner's real problem: there are now many pieces, and checking them by hand is harder than the
pieces themselves. It proposes collapsing that into one command and one short table.

## What actually holds the boundary

Of everything in the collection, four things carry the weight. If these four are right, the rest
can be wrong and nothing leaves this Mac. If one of these is wrong, the rest do not save it.

| load-bearing | what it must be | where it is checked |
|---|---|---|
| The launcher directory is root-owned, with root-owned ancestors, and holds the binaries the owner built from a reviewed tree | `/usr/local/libexec/d1-agent/`, uid 0, mode 755 all the way up | `hook::root_owned`, at every sandbox-off call |
| Every unsandboxed Bash call starts a launcher by its exact path and nothing else | the `sandbox-off` rule, installed in **user** settings | `hook::sandbox_off`, plus README step 3 (`/usr/bin/true` must be BLOCKED) |
| The two profiles deny what they say | `profile()`, `local_only_profile()`, and the probes that refuse if a clause is missing | `cargo test -p d1-netgate` outside the agent sandbox (sabotage controls) |
| Everything else runs inside the agent's own sandbox | Claude Code's sandbox on, no routes around it | **not checked anywhere today** (finding 1) |

Depth, not boundary: the self-applied gates in each binary, the C gate, `tests/callsites.rs`,
`require_loopback`, the basename refusal in `d1-localonly`, the Bash half of `protect`, and the
procedure text. They catch drift and mistakes. They should stay, and they should be described as
depth so the owner does not spend checking effort on them.

## Findings, ranked

### 1. High: `sandbox.excludedCommands` is a route around the whole design

The hook's `sandbox-off` rule fires on `dangerouslyDisableSandbox: true`
(`src/bin/d1-agent-hook.rs:46`). But Claude Code also runs a command outside the sandbox when it
matches `sandbox.excludedCommands`, and then no flag is set. The owner's user settings (read
2026-10-16) exclude:

```
xcodebuild *, xcrun *, log stream *, log show *, /usr/bin/log stream*, /usr/bin/log show*,
codesign *, security *, system_profiler *, codex exec -s read-only *
```

`xcrun python3 -c '…'` and `xcrun swift -e '…'` run arbitrary code bare, with the network, in
any session in this repo, and the hook passes it. `security find-generic-password -w` reads the
keychain bare. Whether a compound command such as `codex exec -s read-only x; curl …` matches the
glob is for the owner to measure; if the matcher is a plain glob on the whole string, it does.
This is the "nothing network-touching runs bare" rule being false before the first launcher is
installed, with no agent doing anything wrong.

Fix, two parts:
* The owner removes `xcrun *`, `xcodebuild *`, `codesign *`, `security *` and `codex exec …` from
  user settings for as long as agent sessions run in this repo, or moves them to a project that
  is not this one (settings arrays merge; a project cannot subtract a user-level entry). `log`
  and `system_profiler` read system state and can stay.
* The hook stops trusting the flag alone: in this repo, `sandbox-off` also denies any Bash
  command, flagged or not, whose first word (after `D1_*` assignments) is in a fixed list
  mirroring the excluded commands (`xcrun`, `xcodebuild`, `codex`, `codesign`, `security`, and
  their `/usr/bin/` spellings). Then a stale user setting cannot reopen this. README step 3 gets
  one more line: `xcrun /usr/bin/true` must print BLOCKED.

### 2. High: `protect` compares paths case-sensitively on a case-insensitive volume

`in_repo` (`src/hook.rs:112-128`) normalizes lexically, canonicalizes, and `is_protected`
(`:130-133`) does string prefix and equality against `PROTECTED`. Measured on this Mac:

```
realpath('/users/RYANHEFFERNAN/downloads/D1-SECURITY-REVIEW-2026-10-16')
  -> /users/RYANHEFFERNAN/downloads/D1-SECURITY-REVIEW-2026-10-16
```

macOS `realpath` returns the spelling it was given. So `Edit /repo/claude.md`,
`Edit /repo/Design/agent-containment.md`, `Write /repo/D1-Server/crates/d1-netgate/build.rs`
(a new file: canonicalize fails, the lexical path is used, and a `build.rs` in the gate crate runs
at the owner's next build) all pass the hook and land on the protected file. APFS also folds
Unicode normalization (`CLAUDE.md` spelled with a decomposed character). The Edit and Write tools
run in-process, not under Seatbelt, so the hook is the only control on them. The `permissions.deny`
Edit patterns are almost certainly case-sensitive too. `sandbox.filesystem.denyWrite` is Seatbelt
and matches the vnode's real path, so sandboxed Bash is probably fine; step 3 should confirm with
`touch /repo/claude.md`.

Fix: for a path that exists, compare identity, not spelling: `(st_dev, st_ino)` of the target
against each protected file and each file under a protected directory, or compare the real
on-disk name obtained with `F_GETPATH` on an opened descriptor (that call does return the real
case). For a path that does not exist, canonicalize the longest existing ancestor the same way and
append the rest. As a floor, fold case and NFC-normalize before comparing. Add a test with
`claude.md`, `Design/agent-containment.md` and a new file under `D1-Server/crates/d1-netgate/`.

### 3. Medium-High: the this-Mac-only write allowlist includes the toolchain

`local_writable()` (`src/lib.rs:100-110`) allows `~/.cargo`, `~/.rustup` and `~/Library/Caches`
as subpaths. `~/.rustup/toolchains/*/bin/rustc`, `…/cargo`, `~/.rustup/settings.toml`,
`~/.cargo/config.toml` and `~/.cargo/bin/` are all inside. Anything under `d1-localonly` can
replace `rustc`; the owner's next `cargo build`, unsandboxed, runs it with the network. This is the
same class as GPT finding 3, fixed for the game profile and left open in the local-only one.

Fix: allow only what a build needs: `~/.cargo/registry`, `~/.cargo/git`, and the repo's `target/`
(already inside the repo subpath). Drop `~/.rustup` and `~/Library/Caches`; a `cargo test` under
the launcher needs neither (it cannot fetch anyway: no network to crates.io, so `cargo fetch` runs
in the agent sandbox first; say so in §7). Deny `~/.cargo/config.toml`, `~/.cargo/config` and
`~/.cargo/bin/` as literals/subpaths in case the allowlist widens later. Add
`~/.rustup/toolchains` and `~/.cargo/config.toml` (where they exist) to the local-only write
probe, and a `no-toolchain-deny` sabotage child.

### 4. Medium: the `denyWrite` ancestor plan has a bad outcome either way

README step 2 says to list every directory between the repo and a protected path in
`sandbox.filesystem.denyWrite`, so a parent cannot be renamed out from under its rule. The lead's
own profile does this with `(literal …)`, which stops the rename and still allows files inside.
Claude Code's `denyWrite` almost certainly compiles to `subpath`. Then listing `d1-server` and
`design` denies every write under them, and builds and `spec/03-runtime/03.2-recomp-runtime.md` edits stop working;
the owner removes the entries, and the rename route (`mv design x; edit; mv x design`) is open
again inside the agent sandbox. The README notes the uncertainty but not this consequence.

Alternative that does not depend on `denyWrite` semantics: the owner sets the system immutable
flag on the protected files and directories (`sudo chflags schg CLAUDE.md AGENTS.md
containment/agent-containment.md …`, and `-R` on `d1-server/crates/d1-netgate`, `containment/go`,
`archive/agent-hooks-rust`). Nothing running as the user can then write, rename or delete them, wherever
their parent is moved, and nothing can add a file (a `build.rs`) to a flagged directory. The owner
clears the flag to edit (`sudo chflags noschg`) and sets it again; `git checkout` of a branch that
changes those files needs the same. It is the same idea as the root-owned launcher directory, and
it reduces the settings to the two hook lines plus `permissions.deny`. If the owner prefers
`denyWrite`, step 3 must include a positive check (`touch d1-server/crates/d1-recomp/src/x` must
succeed) beside the negative ones.

### 5. Medium: the control plane itself is not in the protected set

`PROTECTED` covers the repo's `.claude/` but not `~/.claude/settings.json`, where the hooks and
deny rules now live, and `permissions.deny` has no rule for it either. The agent sandbox denies it
to Bash; the Edit and Write tools are not sandboxed. Hooks are snapshotted at session start, so an
edit lands in the next session, but it lands. Add `Edit(//Users/ryanheffernan/.claude/**)` to
`permissions.deny` and the absolute `~/.claude/` prefix to the hook's `protect` rule. The same
goes for `~/.claude/projects/` (agent memory, loaded into context each session: an injection
target of the kind point 5 is about).

### 6. Medium: both launcher profiles can write Claude Code's own session state

`game_writable()` and `local_writable()` allow `/private/tmp` and `/private/var/folders`
wholesale. Claude Code keeps per-session state under `/private/tmp/claude-<uid>/…` (task
notifications, edit diffs), and its own agent sandbox denies the agent those paths. A process under
either launcher can write them. That is an injection channel into the agent, not a network
escape, but it is one the harness itself thought worth closing. Deny `(regex #"^/private/tmp/claude-")`
and the same under `/private/var/folders` if the harness uses it, in both profiles, and probe one
existing such path.

### 7. Medium: the hook rules only when the project directory is inside the repo

`d1-agent-hook.rs:27-33` passes every event whose `CLAUDE_PROJECT_DIR` is not under the repo. A
session started in `~/Documents/projects` (the parent) gets no rules and can edit and run
everything in the repo. Rule when either directory contains the other. Better: make `sandbox-off`
global (an unsandboxed Bash call anywhere must start a launcher), since no other project of the
owner's has a reason to run bare commands from an agent; keep `protect` repo-scoped.

### 8. Low: four documentation inconsistencies that would be copied

* `containment/agent-containment.md` point 1 and the `autoMode.environment` line still say game
  binaries run bare (peer file, netguard session). The copy into `CLAUDE.md` must carry the
  revised point 1 and the revised one-liner, not these.
* `spec/03-runtime/03.2-recomp-runtime.md` §7 line 432 says sessions run game binaries through
  `d1-server/target/release/d1-nonet` until the owner installs; `agent-containment.md` line 77
  says game runs need the owner until then. The first is the user-owned anchor GPT finding 1 is
  about. Keep the second, delete the first.
* `src/bin/d1-nonet.rs` line 4 still says the launcher is installed in `.claude/hooks/`.
* The "State" line at the top of `agent-containment.md` predates everything after d441732.

### 9. Low: `LOCAL_PORTS` and the live listeners

80 and 8080 are the common local-proxy ports (Charles, mitmproxy, Burp default to 8080). Drop them
unless a server binds them; keep 443 if the responder must answer the client's TLS there. Measured
today: Claude Code's own sandbox proxies listen on ephemeral loopback ports, Postgres on 5432, an
IDE on two more; none collide with the list. Add to README step 3: `lsof -nP -iTCP -sTCP:LISTEN`
during a session, and no listener on a listed port that is not ours.

### 10. Low: residuals, correctly stated, nothing to add

Inherited Mach send rights (needs a test service; the parent is a shell, so the likelihood is
low); the `D1_NETGUARD_FD` exception takes any AF_UNIX descriptor without provenance (moot under
the launchers, which close everything above 2; relevant only to the owner's own bare runs);
`d1-activity-host` runs codecs in a networked process (do the worker split before the hold on
servers lifts, not after); the delegate list is incomplete by nature.

## The earlier findings, checked against the code

| from | finding | status at 9387515 |
|---|---|---|
| hooks review 1 | anchor on agent-writable `target/` | **closed**: root-owned `/usr/local/libexec/d1-agent`, `root_owned` walks every ancestor, symlinks refused, exact spelling only |
| hooks review 2 | Bash `protect` bypass without naming the path | **narrowed**: tripwire stated; `denyWrite` proposed (finding 4 above); `d1-localonly` profile denies protected paths and ancestors |
| hooks review 3 | fail-open when the hook cannot run | **stated** in README with the BLOCKED check |
| hooks review 4 | MCP code-exec tools, Codex | **stated**: README steps 5 and 6 |
| hooks review 5 | `agent-containment.md`, `archive/agent-hooks-rust/` unprotected | **closed** |
| hooks review 6 | `members()` trailing comma, `NETWORK` list | **closed** |
| local-only 1 | `NESTED` proves little, non-nesting apply failures pass | **closed**: every apply failure refuses, Rust and C, `malformed` child |
| local-only 2 | no `no-restrictions` sabotage child | **closed**, plus `all-ports`, `no-sockopt`, `no-writes` |
| local-only 3 | binds default-only | **closed** for our servers (`require_loopback`); arbitrary programs: firewall, owner |
| local-only 4, 5 | stacking wording, Unix-socket EPERM, multicast option | **closed**; multicast closed harder than asked (profile denies the options) |
| GPT 1-12 | as mapped in `RESPONSE-gpt-6.1-sol-2026-10-16.md` | the mapping is accurate; 3 reopens for the local-only profile (finding 3 above); 9, 10, 12 remain owner/peer as stated |

## Making the human check small

The owner's concern is right: there are now two profiles, two launchers, a hook with two rules,
three settings mechanisms, a drift test, a C gate, a firewall setting, an MCP setting, an
`AGENTS.md` line, and four documents, and the install steps ask a person to verify each by hand
after every Claude Code update. The pieces are individually fine. The checking is where this will
fail: a step skipped once, a setting that silently stopped matching, an excluded command added for
an unrelated project.

Proposal: one command and one table.

**`d1-agent-hook check`**, a third subcommand of the root-owned binary, run by the owner (not an
agent) and printing one `OK`/`FAIL` line per fact. It is static and needs no agent session:
* the launcher directory and each launcher: root-owned, mode, and SHA-256 equal to the
  `target/release` build from a clean tree at a named commit (so "did I reinstall after that
  change?" is answered);
* `~/.claude/settings.json`: both hook lines present with the exact command strings; the eight
  `permissions.deny` Edit rules present, plus the `~/.claude` one; `sandbox.enabled` true;
  `sandbox.excludedCommands` empty or only the read-only entries; `denyWrite` present or the
  `schg` flags set on every protected path;
* the firewall: `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate --getblockall`;
* the profiles: `cargo test -p d1-netgate` passed outside the agent sandbox for the installed
  build (the check can run the installed launchers' self-test instead of trusting a memory);
* no loopback listener on a `LOCAL_PORTS` port that is not one of ours.

**The agent-side table**, the seven behavioural checks of README step 3 plus `xcrun /usr/bin/true`
and `touch /repo/claude.md`, in one script under `archive/agent-hooks-rust/` that the owner asks an agent
to run and that prints the same `OK`/`FAIL` lines. The owner reads two short outputs, not seven
prose bullets.

Then the owner's recurring job is: after a Claude Code update or a `d1-netgate` change, run the
one command and have an agent run the one script. Everything else is read once, at install.

## For the copy into CLAUDE.md and AGENTS.md

Copy after findings 1 to 3 are fixed and the peer doc is corrected. The text should be the
revised point 1 (launcher only, never bare, never from `target/release`), points 2 to 6 as they
stand, and the one-liner "network-touching code runs in the agent sandbox, under
`/usr/local/libexec/d1-agent/d1-localonly`, or as an argument to `…/d1-nonet`; nothing runs bare;
never set `D1_NET*`". For Codex, the README's step 6 line. Add one sentence that is missing
everywhere: **until the owner has run the install and the check, agents do not run game binaries
or servers at all; the owner does.** That is the interim rule, and it is the one that matters
this week.

## What is good

The anchor is in the right place and the hook verifies it rather than assuming it. Every apply
failure refuses. The write allowlists turn GPT's "plant something for later" class into an OS
decision for the game. The sabotage tests now cover each clause of each profile, and the
`malformed` and `high fd` children were the right additions. The response document maps every
external finding to a change or a decision, honestly. The `/dev/fd` listing, the stdio check and
the launcher hygiene close finding 7 for every agent-started run. The documents retract rather than
rewrite history, which is what makes a review like this possible.

## Re-verification at b504d55 (code) and 4e7b023 (docs)

Read: `RESPONSE-claude-final-2026-10-16.md`, the diffs of `hook.rs`, `lib.rs`, `d1netgate.c`,
`d1-agent-hook.rs`, `d1-nonet.rs`, the new `install.rs`, the README and `agent-containment.md`.
Two measurements on this Mac, outside the repo: what the immutable flag stops, and the exact
wording `socketfilterfw` prints. Nothing built or run from the repo.

**Verdict: the three blockers are closed. Copy once the owner approves the peer's point 1 and
the interim rule.** The copy's content should be the README's "What changes for agents" plus
points 2 to 6; nothing in the code needs to change first.

| # | status | what I checked |
|---|---|---|
| 1 | **closed** | `bare_runner` takes the first non-assignment word of every segment, split on `; & \| ( ) { }`, backtick, `$(` and newline, by basename. It runs before the flag test in `d1-agent-hook.rs:64`, so flagged or not. The glob in `excludedCommands` only matches a command that starts with the runner's name, and the hook catches every spelling the glob can. `check` fails while a listed pattern is itself a bare runner. |
| 2 | **closed** | `real_path` opens the canonicalized existing part and reads `F_GETPATH`, which returns the stored case; the missing tail is appended and the comparison is lower-cased; an unresolvable head (dangling symlink, unreadable) is `Err` and denied; existing targets are also compared by `(dev, ino)` against every protected file. Fail-closed in each branch. Tests cover the three examples I gave and five more. |
| 3 | **closed** | `local_writable` is temp, the repo, `~/.cargo/registry`, `~/.cargo/git`. `home_protected` denies `~/.cargo/config*`, `~/.cargo/bin/`, `~/.rustup/`, `~/.claude/` after the allow, so a later widening cannot reopen them. Probes ask about `~/.rustup/toolchains`, `~/.cargo/bin`, `~/.cargo/config.toml`, `~/.claude/settings.json`; the `toolchain` child applies the old allowlist and must fail. |
| 5, 6, 7 | closed as described | `~/.claude` protected except `projects/` and `plans/` (owner's choice to leave memory writable; the harness treats memory as background, not instructions, so I agree). Both profiles deny `^/private/tmp/claude` after the allow, with probes and `harness` sabotage children. The repo's protected files are refused from any session; scope for the rest is "same or one contains the other". |
| 4 | owner, with one correction | see below |
| 8, 9, 10 | as the response says | §7's interim line is withdrawn; `agent-containment.md` point 1 remains the peer's and the owner's. 80 and 8080 stay because `d1-responder` binds them; `check` reports strangers on any listed port. |

**Finding 4, measured.** The README says option (a), `schg`, does not stop `mv design x; mkdir
design`. That is true of a flag on the file alone and not of a flag on the directory. On this Mac,
with the user flag (same semantics as `schg`, only who may clear it differs):

| flag on | `mv dir x` | `touch dir/new` | append to an unflagged file inside | `mv parent y; mkdir parent` |
|---|---|---|---|---|
| the directory | EPERM | EPERM | **allowed** | not applicable |
| the file only | allowed | allowed | the file itself: EPERM | **allowed** |

So the recipe for (a) is: flag each protected **file**, and flag each protected **directory and
each in-repo ancestor directory non-recursively**: `design`, `tools`, `d1-server/crates`,
`d1-server/crates/d1-recomp/runtime`, `.claude`. A non-recursive flag on a directory stops its
rename and any new entry, and leaves existing unflagged files inside editable, so
`spec/03-runtime/03.2-recomp-runtime.md` stays an agent's to edit while `design` cannot be moved or added to.
The cost is that new files in those directories (a new crate under `crates/`, a new design doc)
need the owner. The README's sentence "flagging `design/` itself would stop it, but would refuse
new files there" is right and should become the recipe rather than the aside.

**Small points in `install.rs`, none blocking.**
* The byte-identity line compares the installed launcher with `target/release`, which an agent
  can rebuild (a `cargo build` is an allowed reader). After an agent build the line FAILs with
  nothing wrong, which trains the owner to read past FAIL. Have `check` also print
  `git log -1 --format=%h -- d1-server/crates/d1-netgate` and whether that tree is clean, and
  word the line as "identical to the build of <commit>, clean" or "differs from the current build;
  review `git diff` before reinstalling".
* `check` fails `excludedCommands` only for patterns that are themselves bare runners. A new
  entry such as `swift *` would pass. Invert it: FAIL on any entry not in a short allowlist of
  read-only ones (`log …`, `system_profiler …`).
* The firewall wording the check parses is, measured: `Firewall is enabled. (State = 1)` and
  `Firewall has block all state set to enabled.` Both `contains` tests match; `disabled` does not
  contain `enabled`. Correct as written. Inside the agent sandbox the tool reports the firewall
  off, so the README's "in your own terminal" matters.

**What the owner now decides, in one list.** Approve the peer's point 1 revision; approve the
interim rule (agents do not run game binaries or servers until install and `check` pass); run
install steps 1 to 4; remove the five excluded commands; choose (a) with the directory recipe or
(b); decide `~/.claude/projects/`; decide the global `sandbox-off`; then copy.
