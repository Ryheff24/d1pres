**Verdict: not yet.** Commit `26382bbc42f432bb6755673ec7419142ef5a44d9` fixes the original socket and descriptor failures, but introduces two false refusals and leaves write coverage and automated drift controls incomplete.

Read-only review; no files changed. I read the requested diff and all 290 lines of [d1netgate.c](/Users/ryanheffernan/Documents/projects/d1preservation/containment/c/d1netgate.c). I accept the supplied measurements and have not re-reviewed the unchanged profile text. Crate paths below are relative to `d1-server/crates/`.

The seven original must-fix items now stand as follows.

| # | Status | Evidence and remaining work |
|---|---|---|
| 1. Remove the broker-fd exception | **Fixed** | `d1netgate.c:93–113`: every socket refuses; no environment-selected exemption remains. The supplied fd-57 result confirms detection. |
| 2. Safe diagnostics; stop on apply failure | **Fixed** | `d1netgate.c:263–280`: fd 2 is inspected before diagnostics; a socket or inspection failure exits silently. Failed application never enters the probe block. The supplied socketpair and nested-sandbox measurements confirm both behaviors. |
| 3. Fail closed on descriptor errors | **Fixed** | `d1netgate.c:94–113`: enumeration stays open, its own fd is skipped, `readdir` errors are distinguished from EOF, and `fstat` failures refuse. This is fine under the documented startup-only contract. |
| 4. Restore write coverage; distinguish absence/errors from denial | **Partly fixed** | `d1netgate.c:223–257`: required paths, `stat`, truncation checks, and explicit optional absence replace `asked`. `d1netgate.c:194–195` correctly requires Mach result **1**. However, the specifically requested `d1-recomp/src/main.rs` probe remains absent: checking `/d1-server/crates` does not establish protection of each descendant. Neither `.sb` nor absent Claude-state protection has an independent rule/fixture check. |
| 5. Replace the fragile parser with independent expectations | **Fixed for the existing probe set** | `d1netgate.c:63–69,186–204`: explicit lists survive removal of an entry from the profile, and queries require exact denial. The supplied removed-delegate control is useful evidence. Reverse exec-list consistency still belongs in item 7; only delegates receive a count check. |
| 6. Consistent repository-path encoding | **Fixed** | `d1-recomp/build.rs:18–31`, `d1-oracle/build.rs:18–31`, `d1-replay/build.rs:18–31`, and `d1-recomp/src/fntest.rs:543–555,578`: canonicalization failures, unsupported characters, non-UTF-8, and the two writable temporary roots are rejected consistently. |
| 7. Drift controls, shared-profile reconciliation, review budget | **Partly fixed** | `d1netgate.c:1–290`: 16 lines shorter, still 40 over target. No automated C profile/probe controls were added; `containment/go/harness_test.go:55–69` still builds the Go helper only. Shared-profile reconciliation remains deferred. That reconciliation must precede the Go takeover; completing the launcher is not a prerequisite for shipping the interim gate. |

The checked `fcntl` calls, added IPv4/IPv6 options, and numeric interface diagnostics are fine (`d1netgate.c:131–142,174–178,276–278`).

Two new defects, most severe first:

1. **Medium — Required `.git/config` rejects correct Git worktrees.**  
   **Location:** `d1netgate.c:239,247`, through `228–230`.

   In a linked worktree, `.git` is a regular indirection file, so `stat(D1_REPO "/.git/config")` returns `ENOTDIR`. The gate refuses even when its profile applied correctly and every protection holds. Submodule checkouts using a gitfile have the same problem. This layout is explicitly supported by [Git’s repository-layout documentation](https://git-scm.com/docs/gitrepository-layout).

   **Smallest fix retaining config coverage:** Resolve the actual Git configuration pathname during compilation and pass that canonical, validated pathname to the probe. Apply the same encoding validation in all compilation routes. Do not globally treat `ENOTDIR` as optional absence.

2. **Low — The delegate counter interprets repository-path contents as policy syntax.**  
   **Location:** `d1netgate.c:188–190`; repository interpolation at `58`.

   A valid root such as `/Users/reviewer/(global-name checkout` passes the new path guards. Its quoted `runs` pathname nevertheless contributes another match to `strstr(p, "(global-name ")`. In-memory expansion of the current macro produces **13 matches for 12 delegates**, causing refusal with the correct profile.

   **Smallest fix:** Count `"(global-name \""`, including the opening quote. Accepted roots cannot contain that quote, so pathname text cannot contribute a match. Add this root as a regression case.

I found no demonstrated new fail-open path in the reviewed configuration.

The **250-line target is reachable without dropping a check**. I counted the following refactor in memory; it was not applied or compiled. Line numbers refer to the current file.

| Current lines/construct | Concrete reduction | Lines saved |
|---|---|---:|
| `77`, `80–89`, `261–290` | Remove the failure counter; make `netgate_fail` immediately print the reason/procedure and `_exit(2)` in a nine-line helper. Replace the entry point with a seventeen-line linear apply/check sequence. Keep fd-2 validation and immediate application refusal. | 15 |
| `123–143`, `151–155`, `173–179` | Let `netgate_sock` receive the diagnostic subject and refuse directly, removing its `how` output parameter and Boolean-return wrappers. The blocks become 17, 4, and 4 lines. Preserve every socket/setup/error check and numeric interface address. | 8 |
| `100–103`, `113` | Use `if (!e) break;`, then check `errno` immediately after the loop, before `closedir`. Preserve the reset immediately before every `readdir`. | 2 |
| `4–11`, `34–38` | Shorten the introduction from eight lines to four and the profile commentary from five to two. Retain the startup/repeated-call contract, query semantics, documentation reference, and multicast rationale. | 7 |
| `91–92`, `184–185`, `220–222` | Shorten these function comments to one, one, and two lines respectively. | 3 |
| `3`, `251` | Delete the separator-only comment and redundant Claude-path commentary. | 2 |
| `30–33` | Remove the custom undefined-`D1_REPO` diagnostic and its separator. A missing macro still produces a hard compiler error where the profile is constructed. | 4 |
| `73` | Remove the unused `sandbox_free_error` declaration. The revised entry point exits on failure; on success the API guarantees a null error buffer. | 1 |
| **Total reduction** | **290 → 248** | **42** |

Then add **one line** restoring the exact `main.rs` probe and **one line** probing the build-resolved Git config, removing the incorrect `/.git/config` array entry. The delegate-counter correction adds no line. **Final C count: 250.** Build-script changes and tests are outside that C-file count.

This preserves the optional write paths, all three socket-option probes, every runtime consistency check, and every refusal condition. Reporting only the first failure reduces diagnostic aggregation, not protection.

Remaining must-fix work before shipping the interim gate:

1. Correct the Git-worktree and repository-name false refusals.
2. Restore the exact `main.rs` write probe.
3. Add executable drift controls for both expectation lists and required clauses, plus existing-file fixtures for the two write exclusions. Include the supplied failure controls and the two new counterexamples; application failure must not count as catching a weakened profile.
4. Apply the 250-line reduction above, or an equally readable reduction preserving the checks.

The existing policy limitations remain accepted limits of the interim design. They do not require another profile rewrite in this pass.