**BLOCKING — v3 closes the earlier literal examples, but still admits commands that bypass `ProfilerForm`, and does not enforce the promised project-only read boundary.**

This is a static review of both earlier reports, the supplied diff, the revised and base sources, and installed manual files. No tests, profilers, attack commands, or network operations were executed; no files were changed. The initial `git status` reported denied temporary-cache creation attempts. Three inspection searches were refused by the installed hook.

Source references below target `runs/hs-v2/containment`. `[C]` means confirmed by source or installed documentation; `[I]` means a conditional consequence; `[U]` means runtime behavior remains unverified. Example PID `4001` assumes an otherwise qualifying project process.

1. **Blocking — the shared heredoc parser still hides executable commands. [C]**

   Exact admitted form, with the explicit sandbox-off flag, for **every model**:

   ```bash
   node /Users/ryanheffernan/.claude/plugins/cache/openai-codex/codex/1.0.6/scripts/codex-companion.mjs status <<'EOF'x
   EOFx
   exec /usr/bin/sample 4001 1 -e
   EOF
   ```

   Bash’s delimiter is `EOFx`: quote removal applies to the **whole delimiter word**. The hook records only `EOF`, stopping at the closing quote and ignoring the adjoining `x`.

   Consequently:

   - `withoutHeredocBody` removes everything through the final `EOF`.
   - `isCompanion` selects the earlier companion branch.
   - `CompanionForm` accepts the same incorrectly delimited body.
   - Neither `ProfilerForm` nor `Tripwire` runs.
   - Bash ends its actual heredoc at `EOFx`, then executes `sample -e`, which can open TextEdit.

   Replacing the payload with `exec /usr/bin/true` demonstrates the same admission of another executable. No profiler-specific option check can protect that route.

   Another accepted header with the same defect is:

   ```bash
   node /Users/ryanheffernan/.claude/plugins/cache/openai-codex/codex/1.0.6/scripts/codex-companion.mjs status << -'EOF'
   ```

   Here Bash uses `-EOF`; the hook incorrectly skips the `-` and uses `EOF`. A body beginning with `-EOF`, followed by executable commands and a final `EOF`, produces the same escape.

   This flaw is **inherited**, rather than introduced by v3. The new comment refusal closes the earlier comment examples, but does not make heredoc stripping sound.

   Sources: [shell.go:216](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/shell.go:216), [shell.go:237](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/shell.go:237), [shell.go:258](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/shell.go:258), [hook.go:116](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/hook.go:116), [hook.go:124](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/hook.go:124), [bash.1:3096](/usr/share/man/man1/bash.1:3096).

2. **Blocking — the strict profiler path still permits system-wide and unrelated-process data. [C]**

   These exact forms pass without any project-process check:

   ```bash
   /usr/bin/log show --last 1m --info --debug
   /usr/bin/log stream --process Safari --timeout 1s
   /usr/bin/metalperftrace listen --json
   ```

   `log`’s `--process` remains a generic, nonempty `valueWord`, accepting names and arbitrary PIDs. It is optional. `metalperftrace listen` validates `--pid` **when supplied**, but does not require it.

   The manuals establish that `log show` defaults to the system datastore, `log stream` defaults to system-wide streaming, and Metal metrics cover all Metal layers unless filtered. This directly contradicts “only this project’s processes by PID.”

   This form additionally requests machine-wide auxiliary memory data despite supplying a valid project PID:

   ```bash
   /usr/bin/footprint --pid 4001 --sysFootprint
   ```

   `vmmap -allSplitLibs 4001`, also admitted, exposes shared-library mapping information even for libraries not loaded by that target. That is system metadata rather than another process’s heap contents, but it is broader than a literal project-only data promise.

   Sources: [profiler.go:77](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/profiler.go:77), [profiler.go:86](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/profiler.go:86), [profiler.go:93](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/profiler.go:93), [log.1:399](/usr/share/man/man1/log.1:399), [log.1:599](/usr/share/man/man1/log.1:599), [metalperftrace.1:47](/usr/share/man/man1/metalperftrace.1:47), [metalperftrace.1:229](/usr/share/man/man1/metalperftrace.1:229), [footprint.1:60](/usr/share/man/man1/footprint.1:60), [vmmap.1:60](/usr/share/man/man1/vmmap.1:60).

3. **Blocking — `log` loads additional options from outside the checked command. [C; conditional on configuration]**

   Exact admitted command:

   ```bash
   /usr/bin/log show --last 1m
   ```

   The installed manual documents `/Users/ryanheffernan/.logrc`: its `show:` and `stream:` sections supply options as though entered on the command line. Explicit command options override corresponding configuration options; they do not disable configuration generally.

   For example, a configuration containing:

   ```text
   show:
       --archive /Users/ryanheffernan/private/session.logarchive
       --pager
   ```

   reintroduces two explicitly forbidden capabilities without either appearing in the hook input: an outside-repository diagnostic input and pagination through `less`. Configuration can likewise supply a predicate.

   I did **not** inspect or modify the owner’s `.logrc`; its current contents are unknown. The finding is that the gate’s guarantee depends on an unchecked, documented configuration source. No predicate-based execution exploit is claimed.

   Sources: [profiler.go:77](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/profiler.go:77), [log.1:955](/usr/share/man/man1/log.1:955), [log.1:988](/usr/share/man/man1/log.1:988), [log.1:1015](/usr/share/man/man1/log.1:1015), [log.1:424](/usr/share/man/man1/log.1:424).

4. **Blocking — repository input confinement remains a preflight check, with the same race structure rejected for outputs. [C/I]**

   Exact initially admitted form:

   ```bash
   /usr/bin/metalperftrace overview /Users/ryanheffernan/Documents/projects/d1preservation/runs/race.atrc
   ```

   Preconditions: `race.atrc` initially resolves to an existing repository file. After `EvalSymlinks` and `Stat`, but before the profiler opens it, an actor able to replace that entry or a writable parent substitutes a symlink to a supported diagnostic file outside the repository.

   The tool receives the **original pathname**, not a retained descriptor to the checked object. The same issue affects:

   ```bash
   /Applications/Xcode.app/Contents/Developer/usr/bin/xctrace export --input /Users/ryanheffernan/Documents/projects/d1preservation/runs/race.trace --toc
   ```

   Stable outward symlinks are correctly rejected. Missing inputs are rejected. Neither closes replacement after checking.

   Additional limits:

   - Only the top-level input is checked; confinement of later opens inside a trace bundle is not enforced.
   - Hard links do not establish that diagnostic content originated in this project.
   - `Stat` does not establish a supported input type, regular file, or readable contents.
   - No local-volume check excludes network-backed mounts.

   Successful disclosure requires a supported outside input and appropriate access; this is not an arbitrary-text-file reader. No race was executed.

   Source: [profiler.go:248](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/profiler.go:248).

5. **Blocking — the inherited Copilot boundary still checks raw words rather than Bash arguments. [C, static admission]**

   Exact admitted forms for an elevated session:

   ```bash
   copilot -p x '--allow-all-tools'
   copilot -p x --allow-a''ll-tools
   ```

   `scanShell` accepts these quotations, but `ExcludedForm` compares the undecoded `strings.Fields` words against `copilotBlanket`. Bash subsequently supplies a real `--allow-all-tools`.

   This repeats the first revision’s quoted-option defect in another security-sensitive branch. The source explicitly identifies Copilot’s tool permissions as its boundary because it lacks its own sandbox. Execution depends on an installed Copilot resolving on the shell’s PATH; I did not run or validate the CLI.

   Independently, this passes despite the documented requirement for an explicit allow-tool list:

   ```bash
   copilot -p x
   ```

   The code checks for selected forbidden spellings; it never requires `--allow-tool`.

   Sources: [shell.go:62](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/shell.go:62), [shell.go:85](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/shell.go:85), [shell.go:98](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/shell.go:98).

6. **Should-fix — `projectProcess` does not bind the checked identity to the inspected process. [C/I]**

   Exact form:

   ```bash
   /usr/bin/sample 4001 1
   ```

   There are three separate windows:

   - `ps` supplies the executable, then a separate `lsof` supplies cwd. Exit and PID reuse between them can combine observations from different process instances.
   - Exit, reuse, `exec`, or cwd changes can occur after validation and before attachment.
   - A PID filter in a long-running stream can outlive the checked process and later match a reused PID.

   No start identity, retained task identity, or atomic executable/cwd observation is recorded.

   The membership rule is also a heuristic: executable location **or** basename, plus cwd. It does not establish build provenance. For example, if PID `4001` runs a copied executable at:

   ```text
   /Users/ryanheffernan/Documents/projects/d1preservation/runs/codex
   ```

   with repository cwd, it passes the `inRoot(program)` alternative. There is no explicit exclusion for agent executable names, despite the comment’s “agent sessions themselves … never.”

   These are inherited `projectProcess` limitations newly used as the confidentiality boundary for every model’s profilers. No reuse race was reproduced.

   Sources: [profiler.go:220](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/profiler.go:220), [elevated.go:379](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/elevated.go:379), [elevated.go:404](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/elevated.go:404).

7. **Should-fix — the zero-file-write claim is false for deliberately retained `sample`. [C]**

   Exact admitted form:

   ```bash
   /usr/bin/sample 4001 1
   ```

   The installed manual says this writes both stdout and a randomly named report under `/tmp`. It also periodically suspends and resumes the target.

   The revised documentation acknowledges the `/tmp` report immediately after saying “nothing written to a file.” This is therefore a **knowingly retained exception**, not an overlooked explicit output option. It still contradicts the proposal’s unqualified no-file-write requirement.

   Duration and interval have no positive bounds. Streaming commands can run indefinitely. These are measurement effects and resource-use limits, not evidence of an additional arbitrary mutation switch.

   Sources: [profiler.go:83](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/profiler.go:83), [profiler.go:230](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/profiler.go:230), [sample.1:18](/Applications/Xcode.app/Contents/Developer/usr/share/man/man1/sample.1:18), [sample.1:77](/Applications/Xcode.app/Contents/Developer/usr/share/man/man1/sample.1:77), [agent-containment.md:200](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/agent-containment.md:200).

8. **Should-fix — the shell changes improve specific cases, but do not implement Bash’s quoting rules completely. [C]**

   Removing an **unquoted** backslash-newline without inserting a space is correct. The implementation also removes that pair inside single quotes, where Bash preserves it literally.

   Exact form:

   ```bash
   node /Users/ryanheffernan/.claude/plugins/cache/openai-codex/codex/1.0.6/scripts/codex-companion.mjs 'sta\
   tus'
   ```

   The hook checks the subcommand `status`; Bash supplies a different argument containing the backslash and newline. No new arbitrary-execution consequence from this particular change was established.

   The requested ordinary forms remain admissible by static tracing:

   ```bash
   node /Users/ryanheffernan/.claude/plugins/cache/openai-codex/codex/1.0.6/scripts/codex-companion.mjs task 'Review #42'
   ```

   ```bash
   codex exec -s read-only - <<'EOF'
   # Review this prompt
   log show --last 1m
   EOF
   ```

   ```bash
   copilot -p 'Review #42' --allow-tool 'shell(ls)'
   ```

   Quoted `#` characters remain data. A genuine quoted heredoc body is removed before routing, preserving Codex prompts.

   There is, however, a new routing false positive for ordinary quoted argument text:

   ```bash
   codex exec -s read-only 'Explain this example; /usr/bin/sample 4001 1'
   ```

   `RoutesToProfiler` splits at the semicolon **inside the quoted prompt**, sees `sample`, and sends the whole command to `ProfilerForm`, which refuses `codex`. Bash would execute only Codex.

   Sources: [shell.go:144](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/shell.go:144), [shell.go:164](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/shell.go:164), [profiler.go:109](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/profiler.go:109), [bash.1:905](/usr/share/man/man1/bash.1:905), [bash.1:913](/usr/share/man/man1/bash.1:913).

9. **Should-fix — the unchanged suite contains incompatible expectations, and the new tests do not establish the advertised guarantees. [C]**

   These existing `TestHookBash` cases now disagree with v3:

   | Exact command | Existing expectation | V3 source result |
   |---|---|---|
   | `log show --last 1m` | Admission | Refuses bare executable path |
   | `log erase --all` | Old `ExcludedForm` subcommand refusal | Earlier `ProfilerForm` path refusal |

   These are source-demonstrated expectation conflicts; the suite was not run.

   Missing controls include the delimiter-word escapes in finding 1, Copilot quote removal, `.logrc`, required project filters, input replacement, PID identity changes, and the quoted-prompt false positive.

   Other validation gaps:

   - Most profiler probes use only one sandbox flag; every case is not crossed with both flags and both event representations.
   - Process membership is mocked. The real process-reader test can skip when process information is hidden.
   - Options are unique by spelling, not semantic alias. For example, this passes with the same setting supplied twice:

     ```bash
     /usr/bin/metalperftrace listen --pid 4001 -i 1 --interval 2
     ```

   - There is no minimum positional count for tools that require a target/input. `/usr/bin/vmmap` and `/usr/bin/metalperftrace overview` pass hook validation although their manuals require an operand.
   - A matrix “yes” requires at least one positive probe. Matching the generated documentation text does not prove its qualifiers.

   Sources: [hook_test.go:192](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook_test.go:192), [hook_test.go:210](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook_test.go:210), [matrix_test.go:49](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/matrix_test.go:49), [matrix_test.go:71](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/matrix_test.go:71), [profiler.go:173](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/profiler.go:173), [profiler.go:199](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/profiler.go:199).

10. **Should-fix — the three documentation surfaces still overstate enforcement. [C]**

    The examples above disprove “this project’s PIDs,” “files in the repository only,” “no output files,” and the unconditional “only listed options” promise.

    Additional concrete mismatches:

    - README’s code map still says `xcrun` admits `xctrace` without `--launch`.
    - The matrix requires a Copilot allow-tool list; the code does not.
    - The parser description claims Bash-equivalent continuations despite finding 8.
    - “Every form those reviews found is a refusal in `TestAccessMatrix`” overstates exact coverage; `sample`’s ordinary default write remains positively admitted.
    - The bare-name PATH-check description does not describe `ExcludedForm` or the companion’s bare `node`: neither uses `acceptedPath`.
    - `task-resume-candidate` is admitted by `companionCommands` but omitted from the companion matrix row.

    The earlier elevated-only wording and README’s main profiler-routing paragraph **have** been updated; those particular v2 mismatches are closed.

    Sources: [README.md:90](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/README.md:90), [README.md:183](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/README.md:183), [matrix.go:39](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/matrix.go:39), [matrix.go:43](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/matrix.go:43), [agent-containment.md:197](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/agent-containment.md:197), [agent-containment.md:207](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/agent-containment.md:207), [agent-containment.md:225](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/agent-containment.md:225).

Every item from the [first review](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hookstage/REVIEW-profilers-gpt-6.1-sol-2026-10-28.txt:293) has the following disposition:

| First-review item | V3 disposition |
|---|---|
| 1. Comment/heredoc/continuation escapes | Original examples closed, including companion comments. General heredoc boundary remains open: finding 1. |
| 2. Quoted launch / false attach | Closed on the direct routes: recording removed, `xcrunTools` no longer includes `xctrace`. |
| 3. Quoted/split `sample -file` and `-e` | Closed within `ProfilerForm`; finding 1 still permits execution outside it. |
| 4. Unrestricted output arguments | Explicit interfaces removed. Default `/tmp` sampling report knowingly retained. |
| 5. Input/network redirection | Closed within `ProfilerForm`. Still admitted by companion/excluded forms, discussed below. |
| 6. Bare executable/PATH | Closed for strict profiler commands, including direct pinned `xctrace`. Inherited bare-name exceptions remain elsewhere. |
| 7. Pager, notification, corpse, device, package | Explicit options removed. `.logrc` can restore pager/predicate behavior; default import configuration remains a trust dependency. |
| 8. Coverage gaps | Improved substantially; finding 9 remains. |
| 9. Documentation mismatch | Partly corrected; finding 10 remains. |
| 10. No general direct grant to other programs | Still true of `ProfilerForm` itself. False as an end-to-end guarantee because of finding 1. |
| 11. Predicate/default-output limits | Explicit predicates refused; configuration can supply one. Default sampling output knowingly remains. |

Every item from the [second review](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hookstage/REVIEW-profilers-v2-gpt-6.1-sol-2026-10-28.txt:406) has the following disposition:

| Second-review item | V3 disposition |
|---|---|
| 1. Continued `xcrun xctrace` bypass | Original form closed: routing removes continuation and old handler no longer admits the tool. |
| 2. Companion fake heredoc | Original comment form closed; different delimiter mismatches still escape. |
| 3. Output-path races/root symlink/hard links | Explicit output-path mechanism removed. `sample` exception remains; analogous input race remains. |
| 4. `malloc_history -showContent` | Explicit option removed; target restricted to checked PID. |
| 5. `metalperftrace collect --prefix` | Closed by removing `collect`. |
| 6. Arbitrary templates/instruments/inputs/targets | Recording selectors removed. Inputs and targets now checked, but findings 2–4 and 6 limit the boundary. |
| 7. Environment-selected `xctrace` | Closed on strict path by direct absolute executable. |
| 8. Process effects/unbounded operation | `-wait`, broad footprint targeting and footprint sampling removed. Sampling suspension and indefinite streams knowingly remain. |
| 9. Restricted tokenizer assessment | No new executable-injection defect found inside `literalWords`; surrounding routing is not a complete shell parser. |
| 10. Test gaps | Partly closed; stale suite and remaining gaps in finding 9. |
| 11. Documentation mismatch | Partly corrected; finding 10 remains. |

The remaining routing paths have these consequences:

| Path | Assessment |
|---|---|
| `CompanionForm` | Earlier than profiler routing; skips `Tripwire`. Finding 1 is a confirmed arbitrary-command admission. |
| `ExcludedForm` | Elevated-only, but also skips `Tripwire`; retains raw-word option checks and general redirections. |
| Elevated tools | `sample` and `vmmap` are removed from the grant table. Their old direct elevated route is closed. `splitPlain` rejects executable shell syntax and permits only the listed pipeline readers. |
| `Tripwire` | Adds refusals after successful strict profiler validation. It cannot repair earlier branch returns, effective tool configuration, or races. |
| `withoutHeredocBody` | Security-sensitive preprocessing before game/profiler routing; finding 1 shows that it can erase executable text. |
| `firstWordMatching` | Remains spelling-based. It is not independently sufficient to establish what Bash executes. |
| `RoutesToProfiler` | Covers the earlier direct quote/continuation examples, but splits quoted data and does not recognize every possible shell spelling. |
| `LauncherForm` | No new unrestricted escape found. A profiler supplied to `d1-localonly` bypasses `ProfilerForm` but remains under the launcher’s kernel policy. |

Two inherited cases deserve explicit separation from the strict profiler grant:

```bash
node /Users/ryanheffernan/.claude/plugins/cache/openai-codex/codex/1.0.6/scripts/codex-companion.mjs status 3< /dev/tcp/example.com/443
```

This is statically admitted by the companion branch. Bash can initiate the connection while preparing redirection. It is the earlier network-redirection problem through another admitted entry point. General redirection permission is documented; unrestricted network redirection is not consistent with the stated containment intent. Sources: [shell.go:29](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/shell.go:29), [shell.go:158](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/shell.go:158), [bash.1:2980](/usr/share/man/man1/bash.1:2980).

```bash
/usr/bin/xcrun --find --run python3 -c 'print(1)'
```

The hook admits this for elevated sessions because `xcrunForm` validates only the leading query selector. The installed manual documents `--run` as execution mode. **Admission is confirmed; precedence of these conflicting mode switches was not established**, so I do not count this as a demonstrated launch. The query form does not constrain its complete argument grammar. Sources: [shell.go:124](/Users/ryanheffernan/Documents/projects/d1preservation/runs/hs-v2/containment/go/hook/shell.go:124), [xcrun.1:110](/Applications/Xcode.app/Contents/Developer/usr/share/man/man1/xcrun.1:110).

Also, `xc''run xctrace list templates` does not reach `ProfilerForm`: the xcrun-name test trims edge quoting rather than decoding internal quoting. With explicit sandbox-off it is subsequently refused by `LauncherForm`; without that flag, whether an excluded-command spelling runs unsandboxed depends on harness matching, which was not validated. Thus “any spelling routes to `ProfilerForm`” is false, without establishing an additional unrestricted execution here.

**Note:** `xcodebuild` executing build scripts and the retained `simctl`/`devicectl` commands are existing owner-approved capabilities, not new read-only profiler grants. They prevent a literal system-wide “no other program ever runs unsandboxed” claim. The relevant narrower requirement is that a profiler grant must not carry additional execution.

The installed manuals give this assessment of all strict-path options and positional forms:

| Tool | Admitted interface | Documented effects and limits |
|---|---|---|
| `log show` | Flags: `--source`, `--info`, `--no-info`, `--debug`, `--no-debug`, `--signpost`, `--no-signpost`, `--last24`, `--today`, `--yesterday`, `--no-pager`, `--metric`. Values: `--process`, `--style`, `--color`, `--start`, `--end`, `--last`. No positionals. | Selection and formatting. Defaults to system datastore; process unrestricted. `.logrc` changes effective options. Pager disabled only when explicitly requested or otherwise configured that way. |
| `log stream` | Flags: `--source`, `--mach-continuous-time`, `--unreliable`, `--ignore-dropped`. Values: `--color`, `--level`, `--process`, `--style`, `--timeout`, `--type`. No positionals. | Streams system-wide by default; optional process filtering does not validate membership. Timeout optional. `.logrc` applies. |
| `xctrace export` | `--toc`, `--quiet`; `--xpath VALUE`; required checked `--input PATH`. | Exports XML to stdout without `--output`. Supported non-trace inputs are imported **in memory**, using default-template selection. No documented explicit recording or target mutation in this admitted interface. |
| `xctrace list` | Exactly `templates` or `instruments`. | Reads installed configuration metadata, including custom templates in Application Support. No recording requested. |
| `sample` | `-mayDie`, `-fullPaths`; checked PID, optional numeric duration and interval. | Suspends/resumes target; reads stacks/symbols; writes default `/tmp` report and stdout. `-fullPaths` reveals recorded source paths. |
| `vmmap` | `-s`, `-sortBySize`, `-w`, `-wide`, `-v`, `-verbose`, `-attributes`, `-pages`, `-interleaved`, `-submap`, `-allSplitLibs`, `-noCoalesce`, `-summary`; checked PID and optional hexadecimal address. | Displays mappings and metadata. `-allSplitLibs` includes system shared libraries not loaded by target. No admitted explicit output/launch/corpse option. |
| `footprint` | `-v`, `-w`, `--wide`, `--swapped`, `--wired`, `--vmObjectDirty`, `--sysFootprint`; values for `-f`, `--format`, `--sort`, `--minFootprint`; checked `--pid` and up to eight checked PID positionals. | Memory accounting and display. `--sysFootprint` deliberately includes system auxiliary data. Explicit JSON output, child/all-process targeting, corpse and sampling modes excluded. |
| `malloc_history` | `-allByCount`, `-allBySize`, `-allEvents`, `-callTree`, `-chargeSystemLibraries`, `-collapseRecursion`, `-highWaterMark`, `-ignoreThreads`, `-invert`, `-virtual`; checked PID followed by hexadecimal addresses, at most eight positionals total. | Reads allocation histories/backtraces, requiring malloc stack logging. Explicit content display and corpse option excluded. Class-pattern forms are not admitted. |
| `metalperftrace overview` | `--json`, `--json-include-timeline`, `--include-state-transitions`, `--aggregate`; values for `--start`, `--end`, `--domain`, `--state-label`; at most one checked input path. | Reads collected metrics/state and emits text/JSON. No explicit output-file option. Required file operand is not required by the hook. |
| `metalperftrace listen` | `--json`; values for `--interval`, `-i`; checked optional `--pid`. | Streams existing metrics. Without PID it is unfiltered. No admitted output file or setup/mutation operation; no duration bound. |

Manual evidence: [log.1:399](/usr/share/man/man1/log.1:399), [log.1:599](/usr/share/man/man1/log.1:599), [xctrace.1:184](/Applications/Xcode.app/Contents/Developer/usr/share/man/man1/xctrace.1:184), [xctrace.1:294](/Applications/Xcode.app/Contents/Developer/usr/share/man/man1/xctrace.1:294), [sample.1:18](/Applications/Xcode.app/Contents/Developer/usr/share/man/man1/sample.1:18), [vmmap.1:39](/usr/share/man/man1/vmmap.1:39), [footprint.1:56](/usr/share/man/man1/footprint.1:56), [malloc_history.1:47](/usr/share/man/man1/malloc_history.1:47), [metalperftrace.1:128](/usr/share/man/man1/metalperftrace.1:128).

**Note:** removing explicit template/package options does not establish that every installed importer or configuration loaded by `xctrace` is harmless. The manual establishes default import/configuration loading, not arbitrary execution or network activity. Those effects remain unverified; they are not counted as demonstrated exploits.

**Verdict: BLOCKING — do not approve v3; shared-parser execution escapes, unchecked effective log options, and unenforced project-read boundaries remain.**


Codex session ID: 01a183e5-5c5d-7862-b06e-4566ace37f09
Resume in Codex: codex resume 01a183e5-5c5d-7862-b06e-4566ace37f09
