# Response to the GPT 6.1 sol review (gate 1), 2026-10-16

The review is `containment/reviews/REVIEW-gpt-6.1-sol-2026-10-16.md`: GPT 6.1 sol at xhigh effort, run
read-only on the collection as of b596178. Its verdict was "do not copy the procedure as written."
This maps each finding to what changed. The code is in 8e836b4 and eacbb4d; the docs follow in
the next commit.

Status key:
* **fixed**: code changed, with a control that fails without the change;
* **narrowed**: the route is smaller and the rest is stated;
* **owner**: a decision or install that is the owner's;
* **peer**: a file the netguard session owns.

| # | finding | status | what changed |
|---|---|---|---|
| 1 | An admitted command can replace the trust anchor | fixed, plus owner | The launchers and hook move to a **root-owned** `/usr/local/libexec/d1-agent/`. The hook verifies that the directory and each ancestor are uid 0 and not group- or world-writable. Settings go in `~/.claude/settings.json`: a project `.claude/` can be renamed from the agent sandbox (measured: renaming a denied path's parent succeeds). Both launcher profiles carry a write allowlist. `d1-localonly` also denies every protected file, `.git/hooks`, `.git/config`, the cargo configs, `*.sb`, and each in-repo directory above a protected path (as a literal, which stops the rename). The owner chooses whether to install. A separate macOS user or a VM is the stronger boundary GPT names; that is an owner decision. |
| 2 | Canonicalized aliases permit a race | fixed | Aliases are no longer admitted. The program must be spelled exactly `/usr/local/libexec/d1-agent/d1-nonet` or `…/d1-localonly`; `..`, `//`, symlinks and other spellings are denied, with tests. The root-owned ancestry means nothing in the path can be swapped by the user. |
| 3 | Game file writes can recruit a later unsandboxed process | fixed (OS boundary); `map_path` itself not changed | The game profile allows writes only to `/private/tmp`, `/private/var/folders`, the repo's `runs/` and three devices. The gate proves it by asking the sandbox about `~`, `~/.zshenv`, `~/.zshrc`, `~/Library/LaunchAgents`, `CLAUDE.md` and a source file, with `/private/tmp` as the control. A `..` path from `map_path` now ends at EPERM. Making `map_path` resolve beneath a directory fd is still worth doing for correctness, but it is no longer the boundary. |
| 4 | `NESTED` accepts an unknown policy from sampled denials | fixed | `NESTED` is gone. Every apply failure refuses, in Rust and in C, including a C failure with no error text (`err ? err : strerror(errno)`). Inside the agent sandbox, gated binaries now refuse; they run through a launcher. |
| 5 | Arbitrary localhost access includes relays | narrowed | Outbound under `d1-localonly` is limited to `LOCAL_PORTS` (the servers' 13 ports), not `localhost:*`, with a probe of unlisted port 9 and a lookalike test that allows every port. Residual: 80, 443 and 8080 are common proxy ports. A relay on one of those would still be reachable. The owner can drop them if the servers move. GPT's point about the agent sandbox's own egress proxy is about the harness, outside this code. |
| 6 | The multicast escape remains for native code | fixed | Game profile: `(deny socket-option-set)`, every option (measured: all `setsockopt` EPERM). Local-only profile: IPv4- and IPv6-level options denied (measured: `SO_REUSEADDR` still works, which the servers need). Probes: `SO_REUSEADDR` must be EPERM in the game gate; `IP_MULTICAST_TTL` and `IPV6_MULTICAST_HOPS` must be EPERM in the local-only gate. Sabotage tests drop each clause. |
| 7 | Inherited Unix sockets are delegation channels | fixed | Stdio is no longer exempt; the only exception is AF_UNIX on `D1_NETGUARD_FD`. Launchers put `/dev/null` on stdin and close every descriptor above 2 before applying the profile. Descriptors are listed from `/dev/fd`: the old loop to `getdtablesize()` missed fd 500 under a lowered limit (GPT "Limits"; measured, with a control). FIFOs and other IPC handles are closed by the launcher but not scanned by the gates. stdout and stderr stay as Claude Code gives them (files or pipes). |
| 8 | The call-site scan cannot enforce gating | accepted; documented | `tests/callsites.rs` is documented as drift detection, not a boundary. Each binary must have exactly one `fn main`. The boundary is now the launchers: a game binary is only an argument to `d1-nonet`, whatever its source says. Tests that run game code (`d1-oracle`, `d1-replay`, `d1-recomp`) run inside the agent sandbox, one of the three places, or under `d1-nonet`. `d1-activity-host` running codecs in a networked process is the listed exception. Splitting the codecs into a `d1-nonet` worker is an **owner** decision. |
| 9 | `require_loopback` covers only the listed servers | owner | Seatbelt cannot narrow binds (measured), so for arbitrary programs under `d1-localonly` the control is the macOS firewall, "Block all incoming connections" (README, install step 4). |
| 10 | The procedure tells agents to run bare | **peer** for `agent-containment.md`; fixed in ours | `spec/03-runtime/03.2-recomp-runtime.md` §7 and §8 and the README retract the bare form and prescribe `d1-nonet`. Bare runs from Claude Code now refuse (stdin is a socket). Point 1 and the `autoMode` line in `containment/agent-containment.md` belong to the netguard session. It has proposed a revised point 1 in d1cded1, **pending the owner**: one plain command through `/usr/local/libexec/d1-agent/d1-nonet`, naming game-running tests, codec workers and Codex, and effective only once the launchers are installed. It also marked the autoMode clause superseded. The approved text stands until the owner rules. The `denyWrite` example still lists paths in prose; the install check list verifies it. |
| 11 | The hook rules reject their own documented launch | fixed | The launcher path no longer contains `.claude`. `the_documented_run_passes_both_rules` runs the documented command through both rules. |
| 12 | `game.sb` still allows `BROKER_SOCKET` | **peer** | The netguard session owns `containment/go/profiles/game.sb`. It agrees, and the fix is part of the piece 1 revision, which is on hold for the owner's go. That profile is not in use. Composition: the gate now refuses under `game.sb`, so netguard's game side will likely become `d1-nonet`'s profile, applied by a launcher that creates `D1_NETGUARD_FD` after the fd sweep. The two sessions propose that jointly before piece 2. |

## GPT's "Limits" items

* **Descriptor scan after lowering `RLIMIT_NOFILE`**: real; fixed (finding 7 row).
* **The C null-error path**: the C gate now refuses any failure of `sandbox_init`. The message
  falls back to `strerror(errno)` when the error text is null. Not fault-injected.
* **Inherited Mach send rights.** Not probed. The profile filters `mach-lookup` by name, which
  covers rights the process looks up. A send right to an unlisted service that the parent passed
  in another way (special ports, or one received in a message) is not covered. Probing this needs
  a test Mach service. It is listed as open.
* **Unlisted Mach services (`configd` and the rest)**: the delegate list is incomplete by nature,
  as before. Denying Mach lookups wholesale behind an allowlist is netguard's game profile.

## What the owner decides

1. Whether to install the launchers and hook root-owned (`sudo`, README step 1), and the user
   settings (step 2).
2. A separate macOS user or a VM for agent sessions (finding 1's stronger boundary).
3. The firewall setting (finding 9).
4. Whether the codecs in `d1-activity-host` move into a `d1-nonet` worker (finding 8).
5. Whether 80, 443 and 8080 stay in `LOCAL_PORTS` (finding 5).
6. Turning off MCP tools that run code, and the `AGENTS.md` line for Codex (README steps 5–6).

## Verification at eacbb4d

* `cargo test -p d1-netgate`: 10 lib and 6 callsite tests pass inside the agent sandbox and outside
  it. Outside, every sabotage control runs.
* The hook binary was checked against this repo, a `d1-server` subdirectory, `/tmp` (passes
  through), an unset project dir (blocked), and an edit of `CLAUDE.md` from a `d1-server` session
  (blocked).
* Runs 160 and 161: `d1-recomp run` under `d1-nonet`, with Metal; no denial, ended on the time
  limit.
* HEAD builds in a clean worktree (`d1-netgate`, `d1-recomp`).
