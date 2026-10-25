# Review: LaunchServices under the game policy (2026-10-17, 00:05 to 00:25)

**Asked by:** the game session, through the owner: what does allowing `mach-lookup` of
`com.apple.coreservices.launchservicesd` in `game.sb` expose? The recompiled game's AppKit window
cannot become active or key under the policy, so keyboard and mouse never reach it.

**Found instead:** ⛔ **the current `game.sb` lets a process launch any installed application by path
and open any document with its default handler.** Calculator and TextEdit started on every attempt,
outside the sandbox, with full network. The four LaunchServices denies (T4) stop the check-in and
the running-application list; the launch itself takes a fallback through
`com.apple.coreservices.quarantine-resolver`, which the policy does not name. `local.sb` has the
same four denies and therefore the same gap. **Fix (staged, one line in each policy, one name in the
C gate's probe list):** `(deny mach-lookup (global-name "com.apple.coreservices.quarantine-resolver"))`.

Reach: `observed-live` on this Mac (macOS Darwin 27.2.0), run by the owner in their own terminal,
because the hook admits no sandbox-off command of an agent's that is not a launcher, and a second
policy cannot be applied inside the agent sandbox (`sandbox_apply: Operation not permitted`). Every
table below is pasted output from those runs. Probe and scripts: the lead session's scratchpad,
`lsprobe/` (`probe.swift`, `runner.sh` to `runner7.sh`; session-local, not part of the tree).

## Method

A 90-line Swift program, one mode per process, run with `sandbox-exec -D REPO=... -f POLICY`:

| mode | what it tries |
|---|---|
| `checkin` | `NSApplication` regular policy, a window, `activate`; reports `isActive` and `isKeyWindow` after 1.5 s (what the game needs) |
| `running` | `NSWorkspace.runningApplications.count`, frontmost bundle id |
| `activate-other` | `NSRunningApplication.activate` on Finder |
| `launch-app` | `NSWorkspace.openApplication(at: Calculator.app)` |
| `ls-open-app` | `LSOpenCFURLRef(Calculator.app)` |
| `open-doc` | `NSWorkspace.open(doc.txt)`, the default-handler path |
| `launch-legacy` | the deprecated `launchApplication(at:options:configuration:)` |
| `open-with-app` | `NSWorkspace.open([doc], withApplicationAt: TextEdit.app)` |

After each probe the script counted Calculator and TextEdit processes and quit them. Policies:
`base` is `game.sb`'s rules with comments removed; `optA` is base minus the launchservicesd deny;
`optA2` is optA minus `lsd.mapdb`; `-qr` adds the quarantine-resolver deny; `denyall` is
`(allow default)` plus `(deny mach-lookup)`.

## Measurements

### 1. The gap (runner.sh, 00:04)

| policy | checkin | running | activate Finder | launch-app | ls-open-app | open-doc |
|---|---|---|---|---|---|---|
| base (current game.sb) | active=false key=false | count=0 | no finder | **LAUNCHED** (Calculator 0→1) | **LAUNCHED** (0→1) | **OPENED** (TextEdit 0→1) |
| optA | active=true key=true | count=124 | ACTIVATED | LAUNCHED | LAUNCHED | OPENED |
| optA2 | active=true key=true | count=125 | ACTIVATED | LAUNCHED | LAUNCHED | (owner stopped the run) |

### 2. It is a Mach service (runner2.sh, 00:10)

| policy | launch-app | open-doc |
|---|---|---|
| denyall | refused (`kLSNoExecutableErr`, `_LSOpenStuffCallLocal`) | refused |
| base | LAUNCHED | OPENED |

The kernel wrote no sandbox denial lines to the unified log for these runs (with and without
`sudo`, with and without `(with report)`), and the profile `(trace ...)` directive wrote no file.
Both methods were abandoned for a bisection.

### 3. Which service (runner4.sh, 00:15)

Candidates: the LaunchServices and RunningBoard names `launchctl print system` and `gui/501`
register on this Mac that `game.sb` does not already deny. Each variant is base plus one deny.

| added deny | launch-app | open-doc |
|---|---|---|
| all nine at once (control) | refused | refused |
| `com.apple.lsd.openurl` | LAUNCHED | OPENED |
| `com.apple.lsd` | LAUNCHED | OPENED |
| `com.apple.runningboard` | LAUNCHED | OPENED |
| `com.apple.runningboardd` | LAUNCHED | OPENED |
| `com.apple.coreservicesd` | LAUNCHED | OPENED |
| `com.apple.CoreServices.coreservicesd` | LAUNCHED | OPENED |
| `com.apple.lsd.plugin` | LAUNCHED | OPENED |
| `com.apple.lsd.extensions` | LAUNCHED | OPENED |
| **`com.apple.coreservices.quarantine-resolver`** | **refused** (`kLSNoExecutableErr`) | **refused** |

### 4. The fix under option A, and the check-in (runner5.sh, runner6.sh, 00:19 to 00:22)

| policy | launch-app | ls-open-app | open-doc | activate Finder | checkin |
|---|---|---|---|---|---|
| optA-qr | refused | refused (status -10661) | refused | ACTIVATED | active=true key=true (3 of 3, probe first in its process) |
| base-qr | | | | | active=false key=false |

A first `checkin` under optA-qr read false; it had run right after the Finder activation in the
same script. Run first and alone it read true three times, with optA (no fix) as the control also
true. The false was order, not policy.

### 5. The older launch routes (runner7.sh, 00:25)

| policy | launch-legacy | open-with-app |
|---|---|---|
| optA-qr | refused | refused |
| base-qr | refused | refused |

## Findings

1. ⛔ **T4 gap in `game.sb` and `local.sb` (measured).** App launch and document open succeed under
   the current policy. The T4 row of `netguard-requirements.md` ("lookup of each listed service is
   denied") was true and insufficient: the list lacked the service that does the launching when the
   listed ones are denied. The gate's probes passed because they probe the list.
2. **Fix (measured):** denying `com.apple.coreservices.quarantine-resolver` closes `launch-app`,
   `ls-open-app`, `open-doc`, `launch-legacy` and `open-with-app`, under the current policy and
   under option A. No other candidate had any effect alone.
3. **Option A (allow launchservicesd), with the fix in place:** the process becomes active and key
   (what the game needs), and in addition can read the running-application list with bundle ids
   and bring another application to the front. It cannot launch or open anything by any of the
   five routes tried. The two additions are information about this Mac's desktop and a focus
   nuisance, not an escape. `lsd.mapdb` stays denied; the check-in does not need it.
4. **Not measured, `[I]`:** opening an `https:` URL (it would have opened the owner's browser). The
   URL path is `lsd.open`, denied, with the same `_LSOpenStuffCallLocal` fallback that the fix
   closes; the five measured routes make the inference strong but it is still an inference. Also
   unmeasured: any launchservicesd message beyond those AppKit sends for check-in, activation and
   enumeration.

## Recommendation

- **Apply the fix regardless of the input decision.** It is one deny line in each policy and one
  name in `netgate_delegates` (the gate refuses when the counts differ). Staged in the lead
  session's `scratchpad/window2/` as full files at repo-relative paths. Procedure for the owner:
  copy, rebuild the three gated crates (the policy is compiled in; a stale binary is refused by
  `TestBuiltGateStacks`), reinstall.
- **Option A is acceptable after the fix,** as a second line change (remove the launchservicesd
  deny and its `netgate_delegates` entry), if the owner wants native keyboard and mouse in the game
  window. Conditions: the fix lands first; the T4 row is reworded to name the running-application
  list and focus as accepted exposure; the game session's gate test adds one launch attempt that
  must fail (`sandbox_check(mach-lookup, quarantine-resolver)` already covers the policy shape;
  an actual `openApplication(at:)` that must return an error covers the behaviour).
- **Option B (viewer process, shared frames)** remains the choice that gives the game process
  nothing new, at the cost of a frame copy and input latency. The measurements make A defensible;
  they do not make B wrong.

## Correction to the review of 2026-10-16

`REVIEW-claude-one-policy-2026-10-16.md` and the C-gate reviews accepted the T4 denies as covering
"launching apps". They covered the check-in. This review supersedes that reading; the comment on
the new line in `game.sb` says why it is there.
