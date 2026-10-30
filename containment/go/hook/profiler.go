package hook

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// The read-only logs and profilers (owner, 2026-10-28: agents need measurement tools; anything
// read-only that cannot damage the machine is admitted). Every model may run them, elevated or not,
// with the sandbox on or off, as ProfilerForm admits: one line of literal words, the program at its
// own path, only the options in profilerSpecs, a process only if it is this project's, an input file
// only inside the repository, and nothing written but the program's output on the terminal.
//
// Two proposals were blocked by review (runs/hookstage/REVIEW-profilers-*-2026-10-28.txt in
// d1preservation). The first reused ExcludedForm: a "#" comment hid a second command, quoted
// options passed a check on raw words, output options wrote anywhere, "3< /dev/tcp/..." connected.
// The second checked output paths under runs/ before the tool ran, which an agent can race with a
// link, since runs/ is the agent's to write. So no form here writes a file: xctrace record,
// metalperftrace collect and every --output are left to the owner.

// profilerPaths are the programs, each only at its own path. xctrace is named directly, not
// through xcrun, which picks the tool by DEVELOPER_DIR and TOOLCHAINS.
var profilerPaths = map[string]string{
	"log":            "/usr/bin/log",
	"sample":         "/usr/bin/sample",
	"vmmap":          "/usr/bin/vmmap",
	"footprint":      "/usr/bin/footprint",
	"malloc_history": "/usr/bin/malloc_history",
	"metalperftrace": "/usr/bin/metalperftrace",
	"xctrace":        "/Applications/Xcode.app/Contents/Developer/usr/bin/xctrace",
}

type wordKind int

const (
	flagWord    wordKind = iota // an option with no value
	valueWord                   // any literal value
	pidWord                     // a PID of this project's processes (projectProcess)
	inputWord                   // a file the tool reads, inside the repository
	numberWord                  // digits, with at most one "." (a duration or interval)
	addressWord                 // a hexadecimal address, 0x...
)

// profilerSpec is one admitted program and subcommand: its options, the kinds of its positional
// words in order (the last repeats up to max), and options it must have.
type profilerSpec struct {
	options     map[string]wordKind
	positionals []wordKind
	max         int
	required    []string
	choices     []string // when set, the one positional word must be one of these
}

func options(kind wordKind, names ...string) map[string]wordKind {
	m := map[string]wordKind{}
	return with(m, kind, names...)
}

func with(m map[string]wordKind, kind wordKind, names ...string) map[string]wordKind {
	for _, n := range names {
		m[n] = kind
	}
	return m
}

// profilerSpecs, by "program" or "program subcommand". Left out on purpose: every option that
// writes a file (--output, -o, sample -file, footprint --json, metalperftrace collect, xctrace
// record); --predicate (an NSPredicate can call methods in the tool); log --pager (starts less);
// sample -e (opens TextEdit) and -wait (waits for a process not yet started); malloc_history
// -showContent (prints heap contents); every -forkCorpse; footprint --all, --targetChildren,
// --unmapped and process names (they reach other processes); metalperftrace setup (changes a
// running process).
var profilerSpecs = map[string]profilerSpec{
	"log show": {options: with(options(flagWord, "--source", "--info", "--no-info", "--debug", "--no-debug", "--signpost", "--no-signpost", "--last24", "--today", "--yesterday", "--no-pager", "--metric"),
		valueWord, "--process", "--style", "--color", "--start", "--end", "--last")},
	"log stream": {options: with(options(flagWord, "--source", "--mach-continuous-time", "--unreliable", "--ignore-dropped"),
		valueWord, "--color", "--level", "--process", "--style", "--timeout", "--type")},
	"xctrace export": {options: with(with(options(flagWord, "--toc", "--quiet"), valueWord, "--xpath"), inputWord, "--input"), required: []string{"--input"}},
	"xctrace list":   {positionals: []wordKind{valueWord}, max: 1, choices: []string{"templates", "instruments"}},
	"sample":         {options: options(flagWord, "-mayDie", "-fullPaths"), positionals: []wordKind{pidWord, numberWord, numberWord}, max: 3},
	"vmmap": {options: options(flagWord, "-s", "-sortBySize", "-w", "-wide", "-v", "-verbose", "-attributes", "-pages", "-interleaved", "-submap", "-allSplitLibs", "-noCoalesce", "-summary"),
		positionals: []wordKind{pidWord, addressWord}, max: 2},
	"footprint": {options: with(with(options(flagWord, "-v", "-w", "--wide", "--swapped", "--wired", "--vmObjectDirty", "--sysFootprint"),
		valueWord, "-f", "--format", "--sort", "--minFootprint"), pidWord, "--pid"),
		positionals: []wordKind{pidWord}, max: 8},
	"malloc_history": {options: options(flagWord, "-allByCount", "-allBySize", "-allEvents", "-callTree", "-chargeSystemLibraries", "-collapseRecursion", "-highWaterMark", "-ignoreThreads", "-invert", "-virtual"),
		positionals: []wordKind{pidWord, addressWord}, max: 8},
	"metalperftrace overview": {options: with(options(flagWord, "--json", "--json-include-timeline", "--include-state-transitions", "--aggregate"), valueWord, "--start", "--end", "--domain", "--state-label"),
		positionals: []wordKind{inputWord}, max: 1},
	"metalperftrace listen": {options: with(with(options(flagWord, "--json"), valueWord, "--interval", "-i"), pidWord, "--pid")},
}

// profilerName is the program a word names, quotes and path aside, if it is one of profilerPaths.
func profilerName(word string) string {
	name := filepath.Base(strings.NewReplacer(`'`, "", `"`, "", `\`, "").Replace(word))
	if _, known := profilerPaths[name]; known {
		return name
	}
	return ""
}

// RoutesToProfiler reports whether any command segment starts with a profiler, or is xcrun with
// xctrace anywhere in it, spelled any way: quotes and backslashes aside, and with bash's
// backslash-newline removed first. ProfilerForm then decides the whole command, for every model,
// and refuses all but its own forms.
func RoutesToProfiler(code string) bool {
	code = strings.ReplaceAll(code, "\\\n", "")
	segments := strings.FieldsFunc(strings.ReplaceAll(code, "$(", ";"), func(character rune) bool {
		return strings.ContainsRune(";&|(){}`\n", character)
	})
	for _, segment := range segments {
		words := strings.Fields(segment)
		for len(words) > 0 && isAssignment(words[0]) {
			words = words[1:]
		}
		if len(words) == 0 {
			continue
		}
		if profilerName(words[0]) != "" {
			return true
		}
		if strings.Trim(filepath.Base(words[0]), `"'\`) == "xcrun" && slices.ContainsFunc(words[1:], func(word string) bool { return profilerName(word) == "xctrace" }) {
			return true
		}
	}
	return false
}

// ProfilerForm returns "" when command is one of profilerSpecs, alone, on one line, or why not.
// root is the repository.
func ProfilerForm(command string, root string) string {
	if strings.ContainsAny(command, "\n\r") {
		return "a profiler runs as one line: no second line, heredoc or line continuation"
	}
	words, why := literalWords(command)
	if why != "" {
		return why
	}
	if len(words) == 0 {
		return "no command"
	}
	name := filepath.Base(words[0])
	if path, known := profilerPaths[name]; !known || words[0] != path {
		return "a profiler runs at its own path: " + strings.Join(pathList(), ", ") + " (a bare name could find a planted program on PATH; xcrun picks xctrace by DEVELOPER_DIR)"
	}
	rest := words[1:]
	if name == "log" || name == "metalperftrace" || name == "xctrace" {
		if len(rest) == 0 {
			return name + " needs a subcommand"
		}
		name, rest = name+" "+rest[0], rest[1:]
	}
	spec, known := profilerSpecs[name]
	if !known {
		return name + " is not one of the admitted profilers: " + strings.Join(specNames(), ", ") + " (nothing that writes a file: xctrace record and metalperftrace collect are the owner's)"
	}
	var positionals []string
	seen := map[string]bool{}
	for index := 0; index < len(rest); index++ {
		word := rest[index]
		if !strings.HasPrefix(word, "-") {
			positionals = append(positionals, word)
			continue
		}
		option, value, hasValue := strings.Cut(word, "=")
		kind, allowed := spec.options[option]
		if !allowed {
			return name + " " + option + " is not admitted; its options here: " + strings.Join(optionNames(spec), " ")
		}
		if seen[option] {
			return option + " appears twice"
		}
		seen[option] = true
		if kind == flagWord {
			if hasValue {
				return option + " takes no value"
			}
			continue
		}
		if !hasValue {
			if index+1 >= len(rest) || strings.HasPrefix(rest[index+1], "-") {
				return option + " needs a value"
			}
			index++
			value = rest[index]
		}
		if why := checkWord(kind, value, root); why != "" {
			return option + ": " + why
		}
	}
	for _, option := range spec.required {
		if !seen[option] {
			return name + " needs " + option
		}
	}
	if len(positionals) > spec.max {
		return name + " takes at most " + strconv.Itoa(spec.max) + " words that are not options"
	}
	if spec.choices != nil {
		if len(positionals) != 1 || !slices.Contains(spec.choices, positionals[0]) {
			return name + " is one of: " + strings.Join(spec.choices, ", ")
		}
		return ""
	}
	for index, word := range positionals {
		kind := spec.positionals[min(index, len(spec.positionals)-1)]
		if why := checkWord(kind, word, root); why != "" {
			return name + " " + word + ": " + why
		}
	}
	return ""
}

// checkWord returns "" when word is what kind asks for.
func checkWord(kind wordKind, word string, root string) string {
	switch kind {
	case pidWord:
		pid, err := strconv.Atoi(word)
		if err != nil || pid <= 0 || strconv.Itoa(pid) != word {
			return "a process is named by its PID here, one of this project's"
		}
		if why := projectProcess(pid, root); why != "" {
			return "profilers look only at this project's processes, not " + why
		}
	case inputWord:
		return inputPath(word, root)
	case numberWord:
		if _, err := strconv.ParseFloat(word, 64); err != nil || strings.Trim(word, "0123456789.") != "" {
			return "a number"
		}
	case addressWord:
		if !strings.HasPrefix(word, "0x") || len(word) < 3 || strings.Trim(word[2:], "0123456789abcdefABCDEF") != "" {
			return "an address, 0x and hexadecimal digits"
		}
	case valueWord:
		if word == "" {
			return "an empty value"
		}
	}
	return ""
}

// inputPath returns "" when path, an absolute path, resolves inside the repository: what the
// profilers read (a trace, an archive) is this project's, not another of the owner's files.
func inputPath(path string, root string) string {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "an input is an absolute path without .. inside " + root
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "cannot resolve " + root
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil || real != realRoot && !strings.HasPrefix(real, realRoot+"/") {
		return path + " is not a file inside " + root
	}
	if _, err := os.Stat(real); err != nil {
		return path + " cannot be read"
	}
	return ""
}

// literalWords splits line into the words bash would pass, refusing anything bash would read as
// more than literal text. Outside quotes only letters, digits and - _ . , : / = + @ % are words, and
// spaces or tabs part them; '...' is literal text of printable ASCII, joined to what touches it.
// So no comment, expansion, glob, redirection, escape, double quote or second command can occur,
// and the checks after this see exactly the program's arguments.
func literalWords(line string) ([]string, string) {
	var words []string
	var word strings.Builder
	inWord := false
	for index := 0; index < len(line); index++ {
		character := line[index]
		switch {
		case character == ' ' || character == '\t':
			if inWord {
				words = append(words, word.String())
				word.Reset()
				inWord = false
			}
		case character == '\'':
			end := strings.IndexByte(line[index+1:], '\'')
			if end < 0 {
				return nil, "an unclosed quote"
			}
			for _, quoted := range []byte(line[index+1 : index+1+end]) {
				if quoted < 0x20 || quoted > 0x7e {
					return nil, "quoted text in a profiler command is printable ASCII"
				}
			}
			word.WriteString(line[index+1 : index+1+end])
			index += end + 1
			inWord = true
		case character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' ||
			strings.IndexByte("-_.,:/=+@%", character) >= 0:
			word.WriteByte(character)
			inWord = true
		default:
			return nil, "a profiler command is plain words: " + strconv.QuoteToASCII(string(character)) + " is shell syntax here (use letters, digits, - _ . , : / = + @ % or '...' text)"
		}
	}
	if inWord {
		words = append(words, word.String())
	}
	return words, ""
}

func pathList() []string {
	var paths []string
	for _, path := range profilerPaths {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	return paths
}

func specNames() []string {
	var names []string
	for name := range profilerSpecs {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func optionNames(spec profilerSpec) []string {
	var names []string
	for name := range spec.options {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}
