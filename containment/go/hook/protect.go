package hook

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"d1preservation/netguard/gate"
)

// ProtectedPaths are the absolute paths no agent edits: this repository's gate.ProtectedFiles and
// the owner's ~/.claude/settings.json, where this hook is configured.
func ProtectedPaths(config Config) []string {
	var paths []string
	for _, name := range gate.ProtectedFiles {
		paths = append(paths, filepath.Join(config.Root, name))
	}
	return append(paths, filepath.Join(config.Home, ".claude", "settings.json"))
}

// decideEdit refuses an edit of a protected file, from any session.
func decideEdit(tool string, input toolInput, cwd string, config Config) string {
	path := input.FilePath
	if path == "" {
		path = input.NotebookPath
	}
	if path == "" {
		return tool + ": no file path in the event"
	}
	why := ProtectedTarget(path, cwd, config)
	if why == "" {
		return ""
	}
	return tool + " of " + path + " refused: " + why
}

// patchFileMarkers start the lines of a Codex apply_patch that name a file it adds, changes,
// deletes or renames to.
var patchFileMarkers = []string{"*** Add File:", "*** Update File:", "*** Delete File:", "*** Move to:"}

// decidePatch refuses a Codex apply_patch that writes a protected file, from any session. The
// patch text is in tool_input.command. Every file line is checked; a patch that names no file
// is refused, since what it writes cannot be told. A marker inside a hunk's content starts with
// "+", "-" or a space, so it is not read as a file line.
func decidePatch(input toolInput, cwd string, config Config) string {
	if input.Command == nil {
		return "apply_patch: no patch text in the event"
	}
	var paths []string
	for _, line := range strings.Split(*input.Command, "\n") {
		for _, marker := range patchFileMarkers {
			if strings.HasPrefix(line, marker) {
				paths = append(paths, strings.TrimSpace(strings.TrimPrefix(line, marker)))
			}
		}
	}
	if len(paths) == 0 {
		return "apply_patch: the patch names no file, so what it writes cannot be checked"
	}
	for _, path := range paths {
		if path == "" {
			return "apply_patch: a file line names no path"
		}
		why := ProtectedTarget(path, cwd, config)
		if why != "" {
			return "apply_patch of " + path + " refused: " + why
		}
	}
	return ""
}

// ProtectedTarget returns "" when path writes no protected file, else which one it writes or why
// it cannot tell.
// Paths are compared as the volume stores them: each side is resolved to its deepest part that
// exists (symbolic links followed), compared by device and inode (so case, links and hard links do
// not matter; macOS realpath keeps the caller's case), and the names below it without case.
func ProtectedTarget(path string, cwd string, config Config) string {
	if !filepath.IsAbs(path) && !filepath.IsAbs(cwd) {
		return path + " (a relative path, and no working directory to resolve it)"
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(cwd, path)
	}
	target, err := locate(filepath.Clean(path))
	if err != nil {
		return err.Error()
	}
	for _, protected := range ProtectedPaths(config) {
		candidate, err := locate(protected)
		if err != nil {
			return protected + " cannot be resolved (" + err.Error() + "), so no edit can be checked against it"
		}
		if sameLocation(target, candidate) {
			return protected + " is protected: only the owner edits it, outside agent sessions; show the owner the change " +
				"instead (containment/agent-containment.md, point 5)"
		}
	}
	return ""
}

// location is a path as its deepest existing part and the names below it that do not exist yet.
type location struct {
	existing os.FileInfo
	missing  []string
}

// locate resolves path to a location. A symbolic link to nothing is refused: a write through it
// would create its target, wherever that is.
func locate(path string) (location, error) {
	var missing []string
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Stat(current)
		if err == nil {
			return location{existing: info, missing: missing}, nil
		}
		_, linkError := os.Lstat(current)
		if linkError == nil {
			return location{}, fmt.Errorf("%s is a symbolic link to nothing, and a write through it would create its target", current)
		}
		if current == filepath.Dir(current) {
			return location{}, fmt.Errorf("no part of %s exists", path)
		}
		missing = append([]string{filepath.Base(current)}, missing...)
	}
}

// sameLocation reports whether two locations are the same existing file or directory with the
// same missing names below it, compared without case. A missing name that is not ASCII counts as
// the same: the volume folds Unicode in ways a plain comparison does not.
func sameLocation(first location, second location) bool {
	if !os.SameFile(first.existing, second.existing) || len(first.missing) != len(second.missing) {
		return false
	}
	for index, name := range first.missing {
		ascii := strings.IndexFunc(name, func(character rune) bool { return character > 127 }) < 0
		if ascii && !strings.EqualFold(name, second.missing[index]) {
			return false
		}
	}
	return true
}

// tripwireOperators are the shell text that can write a file or start a second program: the Rust
// hook's list (archive/d1-netgate-rust/src/hook.rs). A newline counts, so every heredoc does.
var tripwireOperators = []string{";", "&", ">", "<", "`", "$(", "\n", "tee"}

// readers are the programs that only read; gitReaders and cargoReaders are the read-only
// subcommands of git and cargo (not clippy: clippy --fix writes sources). The Rust hook's lists.
var readers = []string{"cat", "head", "tail", "grep", "rg", "wc", "ls", "diff", "stat", "file", "less"}
var gitReaders = []string{"diff", "log", "show", "status", "blame", "grep", "ls-files"}
var cargoReaders = []string{"build", "test", "check", "doc", "tree", "metadata"}

// Tripwire returns "" unless command names a protected file and is not a pure read: no
// tripwireOperators, and every | segment a reader. It is a tripwire, spelling-based: it reads the
// command's text, so a command that reaches a file without spelling its name passes. The edit
// rule and the deny rules are what stop writes; this catches the plain spelling of one in Bash.
func Tripwire(command string) string {
	name := namedProtectedFile(command)
	if name == "" {
		return ""
	}
	why := ""
	for _, operator := range tripwireOperators {
		if strings.Contains(command, operator) {
			why = fmt.Sprintf("it contains %q", operator)
			break
		}
	}
	for _, segment := range strings.Split(command, "|") {
		if why == "" && !readsOnly(segment) {
			why = fmt.Sprintf("%q is not one of the reading programs", strings.TrimSpace(segment))
		}
	}
	if why == "" {
		return ""
	}
	return "this command names " + name + ", which is protected, and is not a pure read (" + why +
		"): only the owner edits it, outside agent sessions; show the owner the change instead " +
		"(containment/agent-containment.md, point 5)"
}

// namedProtectedFile returns the protected file whose spelling (from tripwireSpellings) occurs in
// command, ignoring case, or "". Of several, the longest spelling wins, so it names the right one.
func namedProtectedFile(command string) string {
	lower := strings.ToLower(command)
	named := ""
	longest := 0
	for name, spelling := range tripwireSpellings() {
		if len(spelling) > longest && strings.Contains(lower, strings.ToLower(spelling)) {
			named = name
			longest = len(spelling)
		}
	}
	return named
}

// tripwireSpellings maps each of gate.ProtectedFiles to the text that names it: its basename,
// unless another protected file shares it or it is a bare word (no "." or "-", like config), then
// the shortest trailing path that is neither. So d1-nonet's main.go is spelled d1-nonet/main.go
// and a Bash edit of another crate's main.go is not refused, while CLAUDE.md, game.sb and
// settings.json (which also names the owner's ~/.claude/settings.json) match by name alone.
func tripwireSpellings() map[string]string {
	spellings := map[string]string{}
	for _, name := range gate.ProtectedFiles {
		parts := strings.Split(name, "/")
		spelling := name
		for count := 1; count < len(parts); count++ {
			candidate := strings.Join(parts[len(parts)-count:], "/")
			if strings.ContainsAny(candidate, ".-") && !sharedSuffix(name, candidate) {
				spelling = candidate
				break
			}
		}
		spellings[name] = spelling
	}
	return spellings
}

// sharedSuffix reports whether a protected file other than name ends with suffix.
func sharedSuffix(name string, suffix string) bool {
	for _, other := range gate.ProtectedFiles {
		if other != name && (other == suffix || strings.HasSuffix(other, "/"+suffix)) {
			return true
		}
	}
	return false
}

// readsOnly reports whether segment starts a reading program, spelled bare (no path, no NAME=
// assignment before it, so a planted program or PATH= cannot stand in), with no option that
// makes it write a file or run a program (--output, --pre, git's -O pager, less's -o log file).
func readsOnly(segment string) bool {
	words := strings.Fields(segment)
	if len(words) == 0 {
		return false
	}
	for _, word := range words[1:] {
		if writesThroughOption(words[0], word) {
			return false
		}
	}
	switch words[0] {
	case "git":
		return gitReads(words)
	case "cargo":
		return len(words) > 1 && slices.Contains(cargoReaders, words[1])
	}
	return slices.Contains(readers, words[0])
}

// gitReads reports whether words (git first) runs a read-only git subcommand: the first word
// after git and after any "-C <directory>" pairs must be in gitReaders. Any other option before
// the subcommand (-c, --exec-path, --git-dir) makes it not a reader.
func gitReads(words []string) bool {
	index := 1
	for index+1 < len(words) && words[index] == "-C" {
		index += 2
	}
	return index < len(words) && slices.Contains(gitReaders, words[index])
}

// writesThroughOption reports whether word, an argument of program, makes a reader write a file
// or run another program: git diff --output, rg --pre, git grep -O or --open-files-in-pager,
// less -o or -O (a log file), and git's -o, --ext-diff, and -c or --config-env (which set
// config, so a pager or diff program). Refusing these keeps the reader list a list of readers.
func writesThroughOption(program string, word string) bool {
	for _, prefix := range []string{"--output", "--pre", "--open-files-in-pager", "--log-file"} {
		if strings.HasPrefix(strings.ToLower(word), prefix) {
			return true
		}
	}
	switch program {
	case "git":
		return strings.HasPrefix(word, "-O") || strings.HasPrefix(word, "-o") || word == "-c" ||
			strings.HasPrefix(word, "--ext-diff") || strings.HasPrefix(word, "--config-env")
	case "less":
		return strings.HasPrefix(word, "-O") || strings.HasPrefix(word, "-o")
	}
	return false
}
