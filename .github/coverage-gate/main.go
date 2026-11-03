// Command coverage-gate fails the coverage workflow when the containment suite's statement
// coverage is under a minimum (60%, owner, 2026-11-03), or when any file with statements has none
// covered: a 0% file is a fail outright, whatever the total. It reads Go coverage profiles (the
// suite's go test profile and the subprocesses' covdata, merged), counts each block once however
// many test binaries reported it, covered if any did, and prints every file worst first. It is the
// same count octocov reports.
//
//	go run ./.github/coverage-gate -min 60 coverage.out
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// block is one profile line's block: its statements, and whether any run covered it.
type block struct {
	statements int
	covered    bool
}

// file is one source file's totals.
type file struct {
	name       string
	statements int
	covered    int
}

func main() {
	minimum := flag.Float64("min", 60, "the lowest total statement coverage, in percent, that passes")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: coverage-gate [-min PERCENT] PROFILE...")
		os.Exit(64)
	}
	blocks := map[string]*block{}
	for _, path := range flag.Args() {
		if err := read(path, blocks); err != nil {
			fmt.Fprintln(os.Stderr, "coverage-gate:", err)
			os.Exit(1)
		}
	}
	files, statements, covered := totals(blocks)
	if statements == 0 {
		fmt.Fprintln(os.Stderr, "coverage-gate: the profiles hold no statements")
		os.Exit(1)
	}
	total := percent(covered, statements)
	var report strings.Builder
	fmt.Fprintf(&report, "| coverage | statements | file |\n|---:|---:|---|\n")
	var failures []string
	for _, f := range files {
		mark := ""
		if f.covered == 0 {
			mark = " **0%: fail**"
			failures = append(failures, f.name+" has "+strconv.Itoa(f.statements)+" statements and none covered")
		}
		fmt.Fprintf(&report, "| %.1f%% | %d/%d | %s%s |\n", percent(f.covered, f.statements), f.covered, f.statements, f.name, mark)
	}
	fmt.Fprintf(&report, "| **%.1f%%** | %d/%d | **total** (minimum %.0f%%) |\n", total, covered, statements, *minimum)
	if total < *minimum {
		failures = append(failures, fmt.Sprintf("total %.1f%% is under the minimum %.0f%%", total, *minimum))
	}
	fmt.Print(report.String())
	if summary := os.Getenv("GITHUB_STEP_SUMMARY"); summary != "" {
		if err := appendTo(summary, "### Coverage gate\n\n"+report.String()+"\n"); err != nil {
			fmt.Fprintln(os.Stderr, "coverage-gate:", err)
		}
	}
	if len(failures) > 0 {
		for _, failure := range failures {
			fmt.Fprintln(os.Stderr, "coverage-gate: FAIL:", failure)
		}
		os.Exit(1)
	}
	fmt.Printf("coverage-gate: pass, %.1f%% total, no file at 0%%\n", total)
}

// read adds a profile's blocks to blocks. A block seen before keeps its statements and is
// covered if this line or any earlier one covered it.
func read(path string, blocks map[string]*block) error {
	input, err := os.Open(path)
	if err != nil {
		return err
	}
	defer input.Close()
	scanner := bufio.NewScanner(input)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "mode:") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) != 3 || !strings.Contains(fields[0], ":") {
			return fmt.Errorf("%s:%d: not a coverage profile line: %q", path, line, text)
		}
		statements, err := strconv.Atoi(fields[1])
		if err != nil {
			return fmt.Errorf("%s:%d: statements: %v", path, line, err)
		}
		count, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil {
			return fmt.Errorf("%s:%d: count: %v", path, line, err)
		}
		seen := blocks[fields[0]]
		if seen == nil {
			seen = &block{statements: statements}
			blocks[fields[0]] = seen
		}
		seen.covered = seen.covered || count > 0
	}
	return scanner.Err()
}

// totals sums blocks by file, worst coverage first (then by name), and over all files.
func totals(blocks map[string]*block) ([]file, int, int) {
	byName := map[string]*file{}
	statements, covered := 0, 0
	for key, b := range blocks {
		name := key[:strings.LastIndex(key, ":")]
		f := byName[name]
		if f == nil {
			f = &file{name: name}
			byName[name] = f
		}
		f.statements += b.statements
		statements += b.statements
		if b.covered {
			f.covered += b.statements
			covered += b.statements
		}
	}
	var files []file
	for _, f := range byName {
		if f.statements > 0 {
			files = append(files, *f)
		}
	}
	sort.Slice(files, func(i, j int) bool {
		left, right := percent(files[i].covered, files[i].statements), percent(files[j].covered, files[j].statements)
		if left != right {
			return left < right
		}
		return files[i].name < files[j].name
	})
	return files, statements, covered
}

// percent is part of whole in percent.
func percent(part int, whole int) float64 {
	return 100 * float64(part) / float64(whole)
}

// appendTo appends text to the file at path.
func appendTo(path string, text string) error {
	output, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, err = output.WriteString(text)
	if closeError := output.Close(); err == nil {
		err = closeError
	}
	return err
}
