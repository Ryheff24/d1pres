# Response to the C boot-gate review (2026-10-16)

Review: `containment/reviews/REVIEW-gpt-6-astra-c-gate-2026-10-16.md`. All C changes are in
`containment/c/d1netgate.c`. The profile text (`D1_NETGATE_PROFILE`) is
byte-identical to the reviewed revision. Inside the agent sandbox, every route still exits 2.
The run outside the agent sandbox, where the binaries must exit 0, is still to do.

| finding | what changed (file:function, one line) | status |
|---|---|---|
| A1 broker fd exemption | d1netgate.c:netgate_check_fds: the D1_NETGUARD_FD exemption is gone; any socket of any family refuses | fixed |
| A2 named denies, exec paths, Mach rights, initializers | none; the interim set is a blacklist by design | design, deferred to the Go launcher |
| A3 broad temporary trees | all three build.rs and fntest.rs:repo_root refuse a repository root under /private/tmp or /private/var/folders | fixed |
| B1 refusal through a socket | d1netgate.c:d1_netgate exits 2 silently if fd 2 is a socket or closed; an apply failure refuses at once, with no probes; netgate_fail ignores SIGPIPE | fixed |
| B2 repository probes, `asked` | d1netgate.c:netgate_writes/netgate_write_denied: required paths must exist and read denied, optional ones are skipped only on ENOENT, stat not lstat, truncation fails, `asked` removed | fixed |
| B3 profile parser | d1netgate.c: netgate_clause and the parsing are removed; explicit delegate and exec arrays are checked against the profile text, with the name count pinning both directions | fixed |
| B4 absent service counted as denied | d1netgate.c:netgate_delegates_and_exec uses sandbox_check mach-lookup with filter 2 and requires exactly 1; bootstrap_look_up and the Mach headers are removed | fixed |
| B5 descriptor scan fails open | d1netgate.c:netgate_check_fds streams /dev/fd, skips dirfd, separates EOF from a readdir error, and fails on any fstat error; the 4096 array is removed | fixed |
| B6 socket options, diagnostics | d1netgate.c:netgate_sockopt now also probes IP_TTL (IPv4) and IPV6_UNICAST_HOPS (IPv6); a refused socket() passes; own-address items carry the numeric address | fixed |
| C1 repository path quoting | all three build.rs and fntest.rs:repo_root: canonicalize or fail, and refuse non-UTF-8, `"`, `\` or a control character; fntest escaping removed, so both routes pass the identical `-DD1_REPO` | fixed |
| C2 truncation, fcntl | d1netgate.c: netgate_sock checks all three fcntl calls, and every probed path or profile needle checks snprintf truncation | fixed |
| C3 startup-only contract | d1netgate.c header: startup only and first, not thread-safe or async-signal-safe, a second call proves again | fixed |
| D owner's budget | d1netgate.c: the parser, the array and the history are gone and netgate_open is renamed netgate_failures; the file is 290 lines | partly fixed: 40 over the 250 target, see below |
| E1 the two profiles differ | none | design, deferred to the Go launcher |
| E2 drift tests | none | deferred to the netguard owner |
| F1 to F6 | as A1, B1, B5, B2 with B4, B3, C1 above | fixed |
| F7 drift controls and game.sb | none; Go tests and game.sb are not touched | deferred to the netguard owner |
| F7 C budget | as D | partly fixed |

**Budget (first pass; the second pass below supersedes it).** The file had 290 physical lines, against a target of 250. No statements were compressed
and no checks were dropped to save lines. The new checks the review asked for cost about 35 lines,
for B1, B2, B3's arrays and count, B5's error paths, B6 and C2. The profile macro takes 22 lines
and the includes take 16. Rule 2 also asks for a comment above every function, and five were added.
The rule says to cut features, not readability, when the budget is too tight. These features are
the owner's to cut:

* the own-address numeric diagnostic, 3 lines;
* the optional write paths, 2 lines;
* the separate IPv6 socket-option probe, 1 line.

Cutting all three still leaves the file over 250.

**Naming.** The failure counter is `netgate_failures`, not `failures`. Every static in this file
carries the `netgate_` prefix because d1run.c `#include`s it into one translation unit.

## Second pass (REVIEW-gpt-6-astra-c-gate-2-2026-10-16)

Review: `containment/reviews/REVIEW-gpt-6-astra-c-gate-2-2026-10-16.md`, on commit 26382bb. The profile
text is still byte-identical. The file is now 265 lines.

| item | what changed (file:function, one line) | status |
|---|---|---|
| New defect 1: `.git/config` refuses a worktree | d1netgate.c:netgate_writes probes `D1_REPO "/.git"`, the entry itself, which is a directory or a worktree's gitfile | fixed, smaller than proposed |
| New defect 2: the delegate counter reads the repo root | d1netgate.c:netgate_delegates_and_exec counts `(global-name "` with the quote, which no accepted root can contain | fixed |
| Remaining 1: the false refusals | as the two defects above | fixed |
| Remaining 2: the exact main.rs probe | d1netgate.c:netgate_writes probes `/d1-server/crates/d1-recomp/src/main.rs` as required again | fixed |
| Remaining 3: executable drift controls and write-exclusion fixtures | none; Go tests with fixtures under containment/go | deferred: owner's decision, netguard owner's directory |
| Remaining 4: the 250-line reduction | d1netgate.c: every row of the table except the first; 290 lines down to 265 | fixed, except the counter row |

**Why `.git` and not the resolved config path.** The review proposed resolving the real config path
at build time and passing it in. That would add a second compiled-in path with its own encoding
rule in all four build routes. Probing the `.git` entry needs nothing at build time and works in
both layouts. A directory path reads as write-denied the same way `/design` does. It covers the
metadata entry in place, not the config file of a linked worktree's common directory.

**Why the counter stays.** The owner wants one REFUSED line that lists every open item, not only
the first failure. The table's first row would remove that, so it is the one row not applied.
The remaining 15 lines over 250 are that counter and its summary.

**B1 reversed on purpose (after the d1-nonet launcher landed).** When the apply fails, d1_netgate now runs every probe and refuses only if one fails, with the apply reason as the first item; B1 assumed the gate was the only thing applying a profile, and under the launcher's game.sb the kernel refuses the apply while the probes still hold.

**Apply skipped when already sandboxed.** d1_netgate asks `sandbox_check(getpid(), NULL, 0)` first and, when it answers 1 (inside the launcher's profile), skips sandbox_init, so libsandbox's own "sandbox initialization failed" line no longer appears on a contained run; the probes still decide, and a failed probe's REFUSED line leads with "already inside another sandbox".

**Both reverted: one policy text, applied identically (after REVIEW-gpt-6-astra-go-nonet, findings 1 and 2).** The two paragraphs above are reverted. Probes that pass under some existing sandbox do not show that the sandbox is the reviewed one: a profile that adds one allowed port passes every probe. The C gate no longer holds its own profile. The build compiles in the normalized text of containment/go/profiles/game.sb: d1-recomp/netgate_profile.rs, included by the three build.rs files and fntest.rs, is byte-identical to gate.Normalize. d1_netgate applies that text without exception. Bare, it applies. Under d1-nonet the same bytes are already applied, so the apply stacks. Under any other sandbox the kernel refuses the apply, and the gate refuses at once without probing, as in the second pass. B1 stands again. The delegate list gains the two names game.sb added, opendirectoryd.membership and SystemConfiguration.configd, which makes 14.

**Controls run inside the agent sandbox.** All of these were run on this revision:
* the smoke harness exits 2, with the apply failure as the only item;
* with sandbox_init stubbed, every probe still runs;
* a profile copy without one delegate fails both the count and the presence check;
* a root of `/tmp/x (global-name y` raises no consistency item, and the old counter fails on it;
* a fake root whose `.git` is a gitfile probes cleanly, where 26382bb gave "Not a directory".
