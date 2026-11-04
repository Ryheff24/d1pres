# GPT 6.1 sol, third review of PR 9 at b37deed (2026-11-03)

Run read-only through the Codex plugin (task-mw1hu8m5-nap6i1, Codex session
01a1a45f-5e69-7881-8e4d-08c473d43f2c). The owner asked that it be the last review, and that each case
be checked for whether it is possible at all. That check is the first section; the review follows
verbatim.

## Feasibility check (Claude, same day, against the code and this Mac)

| review item | possible? | what it gains the agent | verdict |
|---|---|---|---|
| 1. `codesign -d -r CLAUDE.m[d] /bin/ls` | **Yes.** `ExcludedForm` checks no codesign option; `codesign(1)`: "During display, [-r] indicates where to write the code's internal requirements"; the glob hides the name from the tripwire. Elevated session only. | A write to a protected file from outside every sandbox. An elevated model already has the same through `xcodebuild` build phases (agent-containment.md, the acknowledged exception), so no new class, but this one is one line and needs no project. | **Real.** Fix: codesign only as display or verify, no option that writes (`-r` but `-r-`, `--extract-*`, signing, `--remove-signature`), literal words only. |
| 2. Off-pattern worktree from a bare clone in `runs/` | **Yes**, the commands work in the Claude sandbox, and the registration lands in `runs/worktree-store/worktrees`, which `RegisteredWorktrees` does not read. | Nothing new. d1preservation's git ignores `CLAUDE.md` and `containment/` (`.gitignore:164-165`), so the worktree has neither; the protected files it does hold (`d1-server/crates/d1-recomp/src/main.rs`, `d1-server/.cargo/config.toml`, `AGENTS.md`) are as available through `cp -r d1-server runs/copy`, which no rule ever refused. `cp runs/p runs/review/CLAUDE.m[d]` makes a new untracked file in `runs/`. | **Possible, no impact.** Worktree protection guards against an edit to a copy by mistake; it never was a boundary. The gate in each binary and `d1-nonet` are the boundary. |
| 3. `go test -run '[ -c ]'`, `go te\` newline `st`, `cargo test --target-dir 'runs/cache --no-run cache'` | **Yes.** The test check splits on whitespace (`strings.Fields`) and on newlines before joining continuations. | Running an agent-written, ungated test package inside the agent sandbox. The same agent can `go build` that package as a plain program and run it there, which agent-containment.md lists as not covered ("deliberate evasions"); the project's own tests import the gate and are contained however they start. None of the three is a form a test run takes by accident. | **Real parser bug, no new capability.** Cheap fix: read the words with `shellArguments` and join continuations first. |
| 4. Swap `runs/.codex-link.*` for a link while install.sh runs | **Yes**, if an agent session is running a watcher during the owner's install: the directory is the owner's uid in an agent-writable `runs/`, so it can be renamed and replaced. | A false `OK` on one probe line. Nothing is written. The same swap applies to the worktree probe directories (`runs/wt-codex-probe.*`) after their controls, which the review did not name. | **Real, evidence only.** Fix: each probe runs as one Codex invocation that `cd`s into its directory, prints `pwd -P` for the owner's terminal to compare with the directory it made, and works on relative names; the hard-link control must succeed in that same invocation. |
| Xcode build phase | Yes; pre-existing and documented. | Arbitrary code outside the sandbox, elevated only. | Known exception, unchanged. |

---

**Verdict: request changes. Five findings are fixed; three are partly fixed. Practical bypasses remain.**

Reviewed `6114b96..b37deed` on `mythos-audit-fixes`, the prior review, all requested files, and the changed regression tests. This is a static review: no payloads, tests, installer, or updater were executed. The checkout remains clean.

Commands below assume the configured repository root as cwd. "Fixed" means the inspected code closes the reported route; it does not imply runtime verification of either harness.

| # | Disposition | Evidence and threat-model assessment |
|---|---|---|
| **1. Zsh clobber redirections** | **Fixed** | The reported `node /Users/ryanheffernan/.claude/plugins/cache/openai-codex/codex/1.0.6/scripts/codex-companion.mjs status >!CLAUDE.md` now reaches `redirectsWriteNoFile`, which rejects the destination. Companion file output is prohibited, including destinations in `runs/`. Even with the required zsh execution environment, the hook no longer admits this form. [shell.go:34](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/shell.go:34), [shell.go:344](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/shell.go:344). |
| **2. Arithmetic expansion** | **Fixed** | `xcodebuild -version $['$(cp runs/p CLAUDE.m?)']` is rejected at `$[`, before its embedded quotes can conceal the substitution. `plainExpansion` permits `$NAME` and `${PWD}`, and rejects the reported arithmetic form and unbraced subscripts. The attacker can prepare `runs/p` and may occupy an elevated Claude session, but cannot satisfy hook admission. [shell.go:413](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/shell.go:413), [shell.go:466](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/shell.go:466). |
| **3. Replaceable output destinations** | **Fixed for the reported routes** | `xcodebuild -version > runs/out.log`, companion file redirections, and `codex exec -o docs/result.md -` are refused. The attacker can still replace a directory entry in `runs/`, but there is no admitted later output-open in these forms to exploit. This closes the reported race; tool-specific output options remain a separate opening below. [shell.go:170](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/shell.go:170), [shell.go:270](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/shell.go:270). |
| **4. Installer source-file truncation** | **Fixed** | The old `runs/.codex-link-source-P -> ../CLAUDE.md` pathname is no longer used. The source is created exclusively under the installer's private `$HOME/.d1-agent-install.XXXXXX` directory. The attacker cannot write that directory under the stated model. Worktree probe files also use noclobber. [install.sh:20](/Users/ryanheffernan/Documents/projects/d1remote/containment/install.sh:20), [install.sh:187](/Users/ryanheffernan/Documents/projects/d1remote/containment/install.sh:187), [install.sh:208](/Users/ryanheffernan/Documents/projects/d1remote/containment/install.sh:208). |
| **5. Case-variant updater sources** | **Fixed; original attack also excluded by this threat model** | `nocasematch` now makes both source classifications recognize `containment/Go/hook/planted_test.go -> ../../../runs/payload.go`. More fundamentally, planting or renaming entries under protected `containment/go` is unavailable to this attacker. I therefore drop this as an active finding, rather than assuming an attacker-controlled protected source tree. [update.sh:45](/Users/ryanheffernan/Documents/projects/d1remote/containment/update.sh:45). |
| **6. Worktree protection** | **Partly fixed** | Claude now receives the worktree glob rules, and explicit edits also consult registered worktrees. Direct off-pattern `git worktree add` commands are refused. However, script execution can create off-pattern copies without passing through that spelling check; an all-`runs/` construction is given below. Claude's actual enforcement of the new glob rules remains explicitly unmeasured. [install.go:37](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/install.go:37), [protect.go:285](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/protect.go:285), [agent-containment.md:200](/Users/ryanheffernan/Documents/projects/d1remote/containment/agent-containment.md:200). |
| **7. Test-option parsing** | **Partly fixed** | Option arity closes `go test -o -c ./runs/ungated`; quote removal recognizes `go te''st`; Cargo's `--` boundary is handled; and `go test -c -run -c=false ./runs/ungated` retains compile-only status. But whitespace splitting still destroys quoted argument boundaries, and command segmentation mishandles continuations. The attacker can create an ungated package entirely in `runs/`; concrete forms follow. [hook.go:374](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/hook.go:374), [hook.go:448](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/hook.go:448). |
| **8. False hard-link-probe success** | **Partly fixed** | Fresh names, `ln -n`, and inode checks close the old preplanted final-component symlink. The new parent directory remains replaceable during the preceding Codex control invocation. A refusal at a redirected destination can still count as success; see below. [install.sh:209](/Users/ryanheffernan/Documents/projects/d1remote/containment/install.sh:209). |

**Remaining practical bypasses**

1. **High severity; highly practical in an elevated Claude Code session — `codesign` output bypasses the redirection restriction.**

   Exact command:

   ```sh
   codesign -d -r CLAUDE.m[d] /bin/ls
   ```

   The shell expands `CLAUDE.m[d]` to `CLAUDE.md`. The hook sees neither that protected spelling nor a shell redirection. `ExcludedForm` imposes no output-option restriction on `codesign`, and returns an allow decision. The installed manual specifies that, during display, `-r` writes the code's internal requirements to the supplied pathname. [shell.go:139](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/shell.go:139), [shell.go:167](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/shell.go:167), [codesign.1:236](/usr/share/man/man1/codesign.1:236).

   Preconditions:

   - **Already-elevated Claude session:** permitted by the threat model; the attacker cannot forge elevation and does not need to.
   - **`codesign` sandbox exclusion:** part of the reviewed configuration.
   - **Existing `CLAUDE.md` and readable signed `/bin/ls`:** ordinary inputs on the target Mac.
   - **No planted source, HOME write, symlink, race, or owner action is required.**

   Hook admission is confirmed statically; the output behavior is documented and was not executed. This is a retained tool-output opening, separate from the fixed shell-redirection race.

2. **High severity for protected-copy integrity; highly practical — off-pattern worktrees can be created entirely within `runs/`.**

   The agent writes `runs/make-worktree.py` containing:

   ```python
   import subprocess

   subprocess.run([
       "git", "clone", "--bare", "--no-hardlinks",
       ".", "runs/worktree-store"
   ], check=True)
   subprocess.run([
       "git", "--git-dir=runs/worktree-store",
       "worktree", "add", "--detach", "runs/review", "HEAD"
   ], check=True)
   ```

   It then uses these sandboxed commands:

   ```sh
   python3 runs/make-worktree.py
   cp runs/p runs/review/CLAUDE.m[d]
   ```

   The first command exposes no `git worktree` spelling to `worktreeCommand`. The new worktree falls outside every generated protection pattern. Its registration resides under `runs/worktree-store/worktrees`, while `RegisteredWorktrees` examines only the main checkout's `.git/worktrees`. Consequently, even the new registration check misses this copy. [protect.go:290](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/protect.go:290), [protect.go:357](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/protect.go:357), [codex.go:73](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/codex.go:73).

   Preconditions:

   - **Readable repository and installed Git/Python:** available to the agent.
   - **Writable `runs/`, script execution, and sufficient disk space:** available under the model.
   - **Fresh destination names:** the agent can select them.
   - **No write to the main `.git`, protected sources, or HOME is needed.**

   This construction applies to a Claude sandbox session whose cwd remains the main checkout; Claude's documented automatic protections cover its working directory and ancestors, rather than all nested repository copies. [Claude sandbox documentation](https://code.claude.com/docs/en/sandboxing#protected-paths).

   Impact: mutable copies of policy files and gate call sites. The construction also avoids the later `checkWorktrees` warning.

3. **Medium severity; highly practical — tests still run through fake compile-only flags or continuations.**

   Exact Go command:

   ```sh
   GO111MODULE=off GOCACHE=/tmp/d1-review-gocache go test -run '[ -c ]' ./runs/ungated
   ```

   The hook splits the quoted regexp into `[`, `-c`, and `]`, consumes `[` as `-run`'s value, and treats `-c` as compile-only mode. Go receives one regexp argument and executes tests. That regexp matches the initial uppercase `T` in `TestProbe`.

   An independent spelling bypass is:

   ```sh
   GO111MODULE=off GOCACHE=/tmp/d1-review-gocache go te\
   st ./runs/ungated
   ```

   The shell joins `te` and `st`; `commandSegments` splits at the newline before recognition. [hook.go:448](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/hook.go:448), [hook.go:481](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/hook.go:481), [hook.go:504](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/hook.go:504).

   A Cargo sibling is:

   ```sh
   cargo test --manifest-path runs/ungated-rust/Cargo.toml --target-dir 'runs/cache --no-run cache'
   ```

   The hook finds a fake standalone `--no-run`; Cargo receives it inside a directory name.

   Preconditions:

   - **Agent-created ungated package:** attainable in `runs/`; for Go, `runs/ungated/probe_test.go` can declare `TestProbe` without importing the project gate.
   - **Compiler and writable cache/output space:** available; the Go command explicitly uses temporary cache space and disables module lookup.
   - **Sandboxed execution:** sufficient. No elevated model, protected edit, or owner action is required.

   These bypass the mandatory test-launcher rule; they do not escape the agent's sandbox.

4. **Medium severity; moderately practical during installation — replacing the hard-link probe's parent produces false success.**

   The agent runs a sandboxed background watcher:

   ```sh
   python3 runs/probe-parent.py &
   ```

   Its file contains:

   ```python
   from pathlib import Path
   import time

   while True:
       for directory in Path("runs").glob(".codex-link.*"):
           if directory.name.endswith(".saved"):
               continue
           if directory.is_dir() and not directory.is_symlink():
               directory.rename(directory.with_name(directory.name + ".saved"))
               directory.symlink_to("../containment/go", target_is_directory=True)
               raise SystemExit
       time.sleep(0.01)
   ```

   After replacement, the installer's command:

   ```sh
   /bin/ln -n "$root/CLAUDE.md" "$link_dir/link"
   ```

   attempts creation under `containment/go/link`. Profile `d1` refuses that protected destination, and the installer accepts its `Operation not permitted` as evidence about hard-linking into writable space. `ln -n` does not prohibit resolving a symlink in an ancestor component. The failed control is merely recorded, not required to succeed. [install.sh:210](/Users/ryanheffernan/Documents/projects/d1remote/containment/install.sh:210), [install.sh:215](/Users/ryanheffernan/Documents/projects/d1remote/containment/install.sh:215).

   Preconditions:

   - **Owner runs the normal installer:** expressly within the threat model.
   - **Concurrent sandboxed watcher and writable probe directory entry:** attainable under `runs/`; `mktemp` ownership is the same user.
   - **Discovering the random name:** directory enumeration suffices.
   - **A real replacement window:** exists between directory creation and the measured link operation, including the entire intervening Codex control invocation.

   This corrupts validation evidence. It does not itself demonstrate that protected-source hard links are writable.

The documented **Xcode build-script exception also remains**: an elevated Claude session can submit `xcodebuild -project runs/Agent.xcodeproj -target Agent build`, with a `PBXShellScriptBuildPhase` in `runs/Agent.xcodeproj/project.pbxproj` that copies `runs/p` over the main `CLAUDE.md`. Creating the project is within the attacker's writable space; the hook admits the excluded command and the build phase executes outside containment. This is pre-existing and explicitly acknowledged at [agent-containment.md:399](/Users/ryanheffernan/Documents/projects/d1remote/containment/agent-containment.md:399).

The added tests exercise synthetic hook events, not shell execution or installer races. They therefore do not establish closure of these remaining paths. [containment_regression_test.go:346](/Users/ryanheffernan/Documents/projects/d1remote/containment/go/hook/containment_regression_test.go:346).
