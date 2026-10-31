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

// ProtectedTreePaths are the absolute directories whose every file is protected, present or not
// (gate.ProtectedTrees).
func ProtectedTreePaths(config Config) []string {
	var paths []string
	for _, name := range gate.ProtectedTrees {
		paths = append(paths, filepath.Join(config.Root, name))
	}
	return paths
}

// decideEdit refuses an edit of a protected file or of the harness's session records, from any
// session. The records are refused because the elevated check reads the model from them
// (SessionModel): a session that could edit its own transcript could name itself an elevated model.
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
		why = RecordsTarget(path, cwd, config)
	}
	if why == "" {
		return ""
	}
	return tool + " of " + path + " refused: " + why
}

// patchFileMarkers start the lines of a Codex apply_patch that name a file it adds, changes,
// deletes or renames to.
var patchFileMarkers = []string{"*** Add File:", "*** Update File:", "*** Delete File:", "*** Move to:"}

// decidePatch refuses a Codex apply_patch that writes a protected file or a session record, from
// any session. The patch text is in tool_input.command. Every file line is checked; a patch that
// names no file is refused, since what it writes cannot be told. A marker inside a hunk's content
// starts with "+", "-" or a space, so it is not read as a file line.
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
		if why == "" {
			why = RecordsTarget(path, cwd, config)
		}
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
// Three rules, in order: the named files (gate.ProtectedFiles and ~/.claude/settings.json), the
// protected trees (gate.ProtectedTrees, which also cover a file nobody has listed yet), and the
// same two against the repository-relative name a path has inside a worktree, where the gate call
// sites and the containment sources are copied (audit 2026-10-31, N6).
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
			return refusedAs(protected)
		}
	}
	canonical, err := canonicalPath(filepath.Clean(path))
	if err != nil {
		return err.Error()
	}
	for _, tree := range ProtectedTreePaths(config) {
		root, err := canonicalPath(tree)
		if err != nil {
			return tree + " cannot be resolved (" + err.Error() + "), so no edit can be checked against it"
		}
		if underPath(canonical, root) {
			return refusedAs(tree) + " (every file under it is protected: install.sh builds and tests " +
				"this tree in the owner's terminal, and git and Claude Code run what is in a hooks directory)"
		}
	}
	return worktreeTarget(canonical, config)
}

// refusedAs is the refusal for a protected path, with what to do instead.
func refusedAs(protected string) string {
	return protected + " is protected: only the owner edits it, outside agent sessions; show the owner the change " +
		"instead (containment/agent-containment.md, point 5), or stage a complete file under your scratchpad " +
		"window directory for the owner's editor"
}

// worktreeRoots are the repository-relative directories that hold worktrees: Claude Code's
// .claude/worktrees/<name> and d1's runs/wt-<name>. A worktree holds its own copy of the gate call
// sites and (where one was copied in) of containment/, and a rebuilt gate-less copy can be run bare
// inside the agent sandbox, where loopback is open.
var worktreeRoots = []string{".claude/worktrees", "runs"}

// worktreeTarget returns "" unless canonical, an absolute resolved path, is a copy of a protected
// file or a file in a protected tree inside one of this repository's worktrees, then why it is
// refused. The worktree's own name is skipped and the rest of the path is read as a
// repository-relative name.
func worktreeTarget(canonical string, config Config) string {
	root, err := canonicalPath(config.Root)
	if err != nil {
		return ""
	}
	for _, parent := range worktreeRoots {
		prefix := filepath.Join(root, parent) + string(filepath.Separator)
		if !underPath(canonical, filepath.Join(root, parent)) {
			continue
		}
		rest := strings.Split(strings.TrimPrefix(canonical, prefix), string(filepath.Separator))
		if len(rest) < 2 || parent == "runs" && !strings.HasPrefix(rest[0], "wt-") {
			continue
		}
		relative := strings.Join(rest[1:], "/")
		for _, name := range gate.ProtectedFiles {
			if strings.EqualFold(relative, name) {
				return "this is " + name + " in the worktree " + rest[0] + ", and a worktree's copy of a protected file is " +
					"protected too: the gate call sites and the containment sources are what a worktree copy would drop " +
					"(containment/agent-containment.md, point 5)"
			}
		}
		for _, tree := range gate.ProtectedTrees {
			if strings.EqualFold(relative, tree) || hasPrefixFold(relative, tree+"/") {
				return "this is under " + tree + " in the worktree " + rest[0] + ", and a worktree's copy of a protected " +
					"tree is protected too (containment/agent-containment.md, point 5)"
			}
		}
	}
	return ""
}

// canonicalPath is path with its deepest existing part resolved (symbolic links followed) and the
// names below it appended, so two spellings of one file are one string.
func canonicalPath(path string) (string, error) {
	where, err := locate(path)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(existingPath(path, len(where.missing)))
	if err != nil {
		return "", fmt.Errorf("%s cannot be resolved (%v)", path, err)
	}
	return filepath.Join(append([]string{real}, where.missing...)...), nil
}

// existingPath is path with its last missing names removed.
func existingPath(path string, missing int) string {
	for range missing {
		path = filepath.Dir(path)
	}
	return path
}

// underPath reports whether path is root or below it, compared without case (the volume folds it).
func underPath(path string, root string) bool {
	return strings.EqualFold(path, root) || hasPrefixFold(path, root+string(filepath.Separator))
}

// hasPrefixFold is strings.HasPrefix without case.
func hasPrefixFold(text string, prefix string) bool {
	return len(text) >= len(prefix) && strings.EqualFold(text[:len(prefix)], prefix)
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

// readers are the programs that only read; gitReaders and cargoReaders are the read-only
// subcommands of git and cargo (not clippy: clippy --fix writes sources). The Rust hook's lists.
var readers = []string{"cat", "head", "tail", "grep", "rg", "wc", "ls", "diff", "stat", "file", "less"}
var gitReaders = []string{"diff", "log", "show", "status", "blame", "grep", "ls-files"}
var cargoReaders = []string{"build", "test", "check", "doc", "tree", "metadata"}

// Tripwire returns "" unless command names a protected file or tree and is not a pure read: no
// operator that writes a file or starts another program, and every "|" segment a reader. It is a
// tripwire, spelling-based: it reads the command's text, so a command that reaches a file without
// spelling its name passes. The edit rule and the deny rules are what stop writes; this catches the
// plain spelling of one in Bash.
//
// The command is read as bash reads it (readForTripwire), so quotes, escapes and descriptor merges
// mean what they mean: a "|" inside a grep alternation is text, a "\|" is text, "2>&1" writes no
// file, and "tee" is a word, not the letters inside "steering". Before that (F5 of the 2026-10-27
// review) 438 of 849 refusals in the session logs were pure reads, and agents learned to route
// around the tripwire by spelling the name another way, which is worse than the read.
func Tripwire(command string, config Config) string {
	name := namedProtectedFile(command, config)
	if name == "" {
		return ""
	}
	read := readForTripwire(command)
	why := read.operator
	if why == "" {
		for _, segment := range read.segments {
			if !readsOnly(segment) {
				why = fmt.Sprintf("%q is not one of the reading programs", strings.Join(segment, " "))
				break
			}
		}
	}
	if why == "" {
		return ""
	}
	return "this command names " + name + ", which is protected, and is not a pure read (" + why + "). " + howToRead(name)
}

// howToRead is the allowed form, in the refusal itself: agents that are told only "not allowed"
// stop or start spelling the name another way (F7 and section 4 of the 2026-10-27 review).
func howToRead(name string) string {
	return "To read it: the Read tool, or one of " + strings.Join(readers, ", ") +
		", git " + strings.Join(gitReaders, "/") + ", cargo " + strings.Join(cargoReaders, "/") +
		", alone or piped into another of those, with no \";\", \"&\", \"&&\", \">\", \"`\", \"$(\", heredoc or tee" +
		" (a descriptor merge such as 2>&1 is fine, and a quoted or escaped \"|\" is text). " +
		"To change it: show the owner the change (containment/agent-containment.md, point 5), or write a complete " +
		"file under your scratchpad window directory, named so the command does not spell " + name + "."
}

// shellRead is one Bash command as the tripwire reads it: its "|" segments as words (quotes and
// escapes removed), and the first operator outside quotes that writes a file or starts another
// program, as the phrase a refusal uses ("" when there is none).
type shellRead struct {
	segments [][]string
	operator string
}

// readForTripwire reads command the way bash would: '...' is literal, "..." is literal except for
// an expansion that runs a command, a backslash makes the next character literal (and a
// backslash-newline joins lines), ";" "&" "|" ">" "<" backquote and "$(" are operators outside
// quotes, "N>&N" is a descriptor merge and writes no file, and tee is matched as a word.
func readForTripwire(command string) shellRead {
	var read shellRead
	var words []string
	var word strings.Builder
	inWord := false
	quote := byte(0)
	note := func(phrase string) {
		if read.operator == "" {
			read.operator = phrase
		}
	}
	endWord := func() {
		if inWord {
			words = append(words, word.String())
			word.Reset()
			inWord = false
		}
	}
	endSegment := func() {
		endWord()
		read.segments = append(read.segments, words)
		words = nil
	}
	keep := func(character byte) {
		word.WriteByte(character)
		inWord = true
	}
	for index := 0; index < len(command); index++ {
		character := command[index]
		next := byte(0)
		if index+1 < len(command) {
			next = command[index+1]
		}
		switch {
		case quote == '\'':
			if character == '\'' {
				quote = 0
				continue
			}
			keep(character)
		case quote == '"':
			switch {
			case character == '"':
				quote = 0
			case character == '`':
				note("\"`\" runs another command")
			case character == '$' && next == '(':
				note("\"$(\" runs another command")
				index++
			case character == '\\' && index+1 < len(command):
				index++
				keep(command[index])
			default:
				keep(character)
			}
		case character == '\'' || character == '"':
			quote, inWord = character, true
		case character == '\\':
			if next == '\n' {
				index++
				continue
			}
			if index+1 < len(command) {
				index++
				keep(command[index])
			}
		case character == ' ' || character == '\t' || character == '\r':
			endWord()
		case character == '\n':
			note("a newline, so a second command or a heredoc")
			endWord()
		case character == ';':
			note("\";\" starts another command")
			endWord()
		case character == '`':
			note("\"`\" runs another command")
		case character == '$' && next == '(':
			note("\"$(\" runs another command")
			index++
		case character == '|':
			if next == '|' {
				note("\"||\" starts another command")
				index++
			}
			endSegment()
		case character == '&':
			note("\"&\" starts another command or a background job")
		case character == '>':
			if next == '&' && index+2 < len(command) && isDigit(command[index+2]) {
				index += 2
				continue
			}
			note("\">\" writes a file")
		case character == '<':
			note("\"<\" reads a file into the command, and \"<<\" starts a heredoc")
		default:
			keep(character)
		}
	}
	if quote != 0 {
		note("an unclosed quote, so what bash would run cannot be told")
	}
	endSegment()
	for _, segment := range read.segments {
		for _, candidate := range segment {
			if filepath.Base(candidate) == "tee" {
				note("\"tee\" writes a file")
			}
		}
	}
	return read
}

// isDigit reports whether character is an ASCII digit.
func isDigit(character byte) bool {
	return character >= '0' && character <= '9'
}

// namedProtectedFile returns the protected file whose spelling (from tripwireSpellings) occurs in
// command, ignoring case, or "". Of several, the longest spelling wins, so it names the right one.
// A file's spelling counts wherever it occurs, so a staging copy named CLAUDE.md is caught too. A
// tree's counts only where the text is this repository's tree: at the start of a word, or in a word
// that starts with the repository root. A tree is spelled as a path (containment/go), and a path
// like that is a part of every absolute path into another checkout of the same repository, where an
// agent is meant to work: matching those would refuse ordinary commands, which is the behaviour F5
// of the 2026-10-27 review is about.
func namedProtectedFile(command string, config Config) string {
	lower := strings.ToLower(command)
	named := ""
	longest := 0
	spellings := tripwireSpellings()
	for _, name := range gate.ProtectedFiles {
		spelling := spellings[name]
		if len(spelling) > longest && strings.Contains(lower, strings.ToLower(spelling)) {
			named = name
			longest = len(spelling)
		}
	}
	if named != "" {
		return named
	}
	for _, name := range gate.ProtectedTrees {
		if len(spellings[name]) > longest && namesTree(command, spellings[name], config) {
			named = name
			longest = len(spellings[name])
		}
	}
	return named
}

// namesTree reports whether command spells this repository's tree: a word that is the spelling or
// starts with it, or a word that starts with the repository root and holds it.
func namesTree(command string, spelling string, config Config) bool {
	for _, segment := range commandSegments(command) {
		for _, word := range strings.Fields(segment) {
			bare := strings.Trim(word, `'"`)
			if hasPrefixFold(bare, spelling) || hasPrefixFold(bare, "./"+spelling) {
				return true
			}
			if config.Root != "" && hasPrefixFold(bare, config.Root) &&
				strings.Contains(strings.ToLower(bare[len(config.Root):]), strings.ToLower("/"+spelling)) {
				return true
			}
		}
	}
	return false
}

// tripwireSpellings maps each of gate.ProtectedFiles and gate.ProtectedTrees to the text that
// names it: its basename, unless another protected name shares it or it is a bare word (no "." or
// "-", like config or go), then the shortest trailing path that is neither. So d1-nonet's main.go
// is spelled d1-nonet/main.go and a Bash edit of another crate's main.go is not refused, while
// CLAUDE.md, game.sb and settings.json (which also names the owner's ~/.claude/settings.json)
// match by name alone, and the trees by their path (containment/go, .git/hooks).
func tripwireSpellings() map[string]string {
	spellings := map[string]string{}
	for _, name := range append(slices.Clone(gate.ProtectedFiles), gate.ProtectedTrees...) {
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

// sharedSuffix reports whether a protected file or tree other than name ends with suffix.
func sharedSuffix(name string, suffix string) bool {
	for _, other := range append(slices.Clone(gate.ProtectedFiles), gate.ProtectedTrees...) {
		if other != name && (other == suffix || strings.HasSuffix(other, "/"+suffix)) {
			return true
		}
	}
	return false
}

// readsOnly reports whether words, one "|" segment as bash would pass it, starts a reading program,
// spelled bare (no path, no NAME= assignment before it, so a planted program or PATH= cannot stand
// in), with no option that makes it write a file or run a program (--output, --pre, git's -O pager,
// less's -o log file).
func readsOnly(words []string) bool {
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
