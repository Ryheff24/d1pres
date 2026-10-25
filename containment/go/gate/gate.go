// Package gate holds what a launcher needs around its Seatbelt profile: the one normalized
// policy text, descriptor hygiene, and the probes. The applied kernel policy contains the
// process; the probes check selected properties of it. Each probe attempts the forbidden thing;
// only EPERM or EACCES, Seatbelt's answers, counts as refused. Each returns failure items,
// "what: why"; none means every probe saw a refusal.
package gate

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unicode"
)

// repoRuns is the one parameterized expression in game.sb.
const repoRuns = `(string-append (param "REPO") "/runs")`

// Normalize turns game.sb into the exact text both consumers apply: each line cut at its first
// ";", trimmed, empty lines dropped, joined with nothing, and repoRuns replaced by "<root>/runs"
// (no escaping: roots with a quote, backslash or control character are refused before this).
// The Rust build.rs does exactly the same for the C gate, whose sandbox_init stacks on this Mac
// only under the same compiled policy (measured: comments and the REPO parameter do not matter,
// one extra allow does); that is the identity check between launcher and gate.
func Normalize(profile string, root string) string {
	return NormalizeWith(profile, map[string]string{"REPO": root})
}

// NormalizeWith is Normalize with named parameters: after repoRuns, every remaining
// (param "NAME") becomes the quoted value. game.sb has no other parameter, so its text is
// unchanged; local.sb uses REPO and HOME. A parameter left unnamed stays, and sandbox-exec then
// refuses the profile. Values are checked with CheckParameter before this.
func NormalizeWith(profile string, parameters map[string]string) string {
	var rules strings.Builder
	for _, line := range strings.Split(profile, "\n") {
		rule, _, _ := strings.Cut(line, ";")
		rules.WriteString(strings.TrimSpace(rule))
	}
	text := strings.ReplaceAll(rules.String(), repoRuns, `"`+parameters["REPO"]+`/runs"`)
	for name, value := range parameters {
		text = strings.ReplaceAll(text, `(param "`+name+`")`, `"`+value+`"`)
	}
	return text
}

// Refusal is the one line a launcher prints before it exits 2, naming every failed item. The
// command is quoted and every control character replaced, so no argument can split the line.
func Refusal(tool string, command string, failures []string) string {
	return OneLine(tool + ": REFUSED - " + strconv.Quote(command) + " would run without network containment ( " +
		strings.Join(failures, ", ") + "); follow the procedure in containment/agent-containment.md and " +
		"spec/03-runtime/03.2-recomp-runtime.md section 7; do not modify, bypass or work around this check; " +
		"if the procedure does not resolve it, stop and report.")
}

// OneLine replaces every control character, newlines included, with a space.
func OneLine(text string) string {
	return strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return ' '
		}
		return character
	}, text)
}

// check appends "what: why" unless err is a sandbox refusal. Success is a failure of the gate.
func check(failures []string, what string, err error) []string {
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return failures
	}
	if err == nil {
		err = errors.New("succeeded")
	}
	return append(failures, what+": "+err.Error())
}

// attempt connects (stream) or sends one byte (datagram) to address and port on a nonblocking
// socket, so a broken profile cannot hang it. zone is the interface index link-local IPv6 needs.
func attempt(socketType int, address netip.Addr, zone int, port int) error {
	family := syscall.AF_INET6
	var destination syscall.Sockaddr = &syscall.SockaddrInet6{Port: port, ZoneId: uint32(zone), Addr: address.As16()}
	if address.Is4() {
		family = syscall.AF_INET
		destination = &syscall.SockaddrInet4{Port: port, Addr: address.As4()}
	}
	descriptor, err := syscall.Socket(family, socketType, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(descriptor)
	err = syscall.SetNonblock(descriptor, true)
	if err == nil && socketType == syscall.SOCK_STREAM {
		return syscall.Connect(descriptor, destination)
	}
	if err == nil {
		return syscall.Sendto(descriptor, []byte("x"), 0, destination)
	}
	return fmt.Errorf("cannot make the probe socket nonblocking (%v)", err)
}

// NoNetwork requires TCP and UDP to 127.0.0.1 and ::1 refused, and TCP to every address of every
// up, non-loopback interface, all at port 9, which no profile lists: Seatbelt's "localhost" admits this Mac's LAN address too (T1, T9).
func NoNetwork() []string {
	var failures []string
	for _, address := range []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()} {
		failures = check(failures, "tcp "+address.String(), attempt(syscall.SOCK_STREAM, address, 0, 9))
		failures = check(failures, "udp "+address.String(), attempt(syscall.SOCK_DGRAM, address, 0, 9))
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return append(failures, "interface list: "+err.Error())
	}
	for _, device := range interfaces {
		if device.Flags&net.FlagUp == 0 || device.Flags&net.FlagLoopback != 0 {
			continue
		}
		assigned, err := device.Addrs()
		if err != nil {
			failures = append(failures, "addresses of "+device.Name+": "+err.Error())
		}
		for _, network := range assigned {
			prefix, err := netip.ParsePrefix(network.String())
			if err != nil {
				failures = append(failures, "address "+network.String()+": cannot parse")
				continue
			}
			zone := 0
			if prefix.Addr().IsLinkLocalUnicast() {
				zone = device.Index
			}
			what := "tcp " + device.Name + " " + prefix.Addr().String()
			failures = check(failures, what, attempt(syscall.SOCK_STREAM, prefix.Addr(), zone, 9))
		}
	}
	return failures
}

// NoSocketOptions sets harmless options on fresh UDP sockets and requires each refused: an IP
// multicast join emits IGMP even under (deny network*); only (deny socket-option-set) stops it.
func NoSocketOptions() []string {
	failures := check(nil, "setsockopt SO_REUSEADDR", setOption(syscall.AF_INET, syscall.SOL_SOCKET, syscall.SO_REUSEADDR))
	failures = check(failures, "setsockopt IP_TTL", setOption(syscall.AF_INET, syscall.IPPROTO_IP, syscall.IP_TTL))
	return check(failures, "setsockopt IPV6_UNICAST_HOPS", setOption(syscall.AF_INET6, syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS))
}

// setOption sets one option to 1 on a fresh UDP socket, then closes it.
func setOption(family int, level int, option int) error {
	descriptor, err := syscall.Socket(family, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(descriptor)
	return syscall.SetsockoptInt(descriptor, level, option, 1)
}

// Writes attempts a write that changes nothing at each denied path, and requires it refused: a
// file is opened to append and closed; a directory gets a new file, removed at once if created.
// A missing path fails, since a refusal there proves nothing. A write to allowed must succeed:
// the positive control, so a probe that reads every write as refused cannot pass.
func Writes(denied []string, allowed string) []string {
	var failures []string
	for _, path := range denied {
		info, err := os.Stat(path)
		if err == nil && info.IsDir() {
			err = createAndRemove(path)
		} else if err == nil {
			err = appendNothing(path)
		} else {
			err = fmt.Errorf("cannot probe (%v)", err)
		}
		failures = check(failures, "write "+path, err)
	}
	err := createAndRemove(allowed)
	if err != nil {
		failures = append(failures, "write control "+allowed+": "+err.Error())
	}
	return failures
}

// appendNothing opens path to append and closes it without writing.
func appendNothing(path string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err == nil {
		file.Close()
	}
	return err
}

// createAndRemove creates a new uniquely named file in directory and removes it. A failed
// removal is reported, not wrapped, so it can never read as a refusal.
func createAndRemove(directory string) error {
	name := directory + "/.d1-probe-" + strconv.Itoa(os.Getpid())
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	file.Close()
	err = os.Remove(name)
	if err != nil {
		return fmt.Errorf("created %s and could not remove it (%v)", name, err)
	}
	return nil
}

// Execs starts each path with no arguments and stdin on /dev/null, and requires the start
// refused. One that starts is killed at once and reaped, so a broken profile runs nothing long.
func Execs(paths []string) []string {
	var failures []string
	for _, path := range paths {
		command := exec.Command(path)
		err := command.Start()
		if err == nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
		failures = check(failures, "exec "+path, err)
	}
	return failures
}

// inspect is "" for a descriptor that is not a socket, else "socket" or why it cannot be inspected.
func inspect(descriptor int) string {
	var status syscall.Stat_t
	err := syscall.Fstat(descriptor, &status)
	if err != nil {
		return "cannot inspect (" + err.Error() + ")"
	}
	if status.Mode&syscall.S_IFMT == syscall.S_IFSOCK {
		return "socket"
	}
	return ""
}

// IsSocket reports whether descriptor is a socket. One that cannot be inspected counts as one.
func IsSocket(descriptor int) bool {
	return inspect(descriptor) != ""
}

// openDescriptors lists every open descriptor from /dev/fd. A loop to a limit misses one above
// a lowered RLIMIT_NOFILE (measured: fd 500 under a limit of 64). The listing's own descriptors
// (Go duplicates one to read it) are closed first, and only those then still open are returned.
func openDescriptors() ([]int, error) {
	directory, err := os.Open("/dev/fd")
	if err != nil {
		return nil, err
	}
	names, err := directory.Readdirnames(-1)
	directory.Close()
	var descriptors []int
	for _, name := range names {
		descriptor, parseError := strconv.Atoi(name)
		var status syscall.Stat_t
		if parseError == nil && syscall.Fstat(descriptor, &status) != syscall.EBADF {
			descriptors = append(descriptors, descriptor)
		}
	}
	return descriptors, err
}

// NoOpenSockets requires that no descriptor open at this point is a socket, stdio included: an
// inherited socket could be connected to anything (T7). One it cannot inspect fails too.
func NoOpenSockets() []string {
	descriptors, err := openDescriptors()
	if err != nil {
		return []string{"descriptors: cannot list /dev/fd (" + err.Error() + ")"}
	}
	var failures []string
	for _, descriptor := range descriptors {
		state := inspect(descriptor)
		if state != "" {
			failures = append(failures, "descriptor "+strconv.Itoa(descriptor)+": "+state)
		}
	}
	return failures
}

// Hygiene prepares what a launcher hands on: /dev/null on stdin (Claude Code's Bash gives a
// socket there), every descriptor above 2 close-on-exec so the next program starts with only
// 0-2 (not closed: some are Go's runtime's own), and stdout not a socket. Any step that fails
// refuses. The caller checks stderr first, since the refusal is written there.
func Hygiene() []string {
	null, err := syscall.Open("/dev/null", syscall.O_RDONLY, 0)
	if err == nil && null != 0 {
		err = syscall.Dup2(null, 0)
		syscall.Close(null)
	}
	if err != nil {
		return []string{"stdin: cannot put /dev/null there (" + err.Error() + ")"}
	}
	descriptors, err := openDescriptors()
	if err != nil {
		return []string{"descriptors: cannot list /dev/fd (" + err.Error() + ")"}
	}
	var failures []string
	for _, descriptor := range descriptors {
		if descriptor <= 2 {
			continue
		}
		err = markCloseOnExec(descriptor)
		if err != nil {
			failures = append(failures, "descriptor "+strconv.Itoa(descriptor)+": cannot mark close-on-exec ("+err.Error()+")")
		}
	}
	if IsSocket(1) {
		failures = append(failures, "stdout: socket")
	}
	return failures
}

// markCloseOnExec sets FD_CLOEXEC with checked fcntl calls; syscall.CloseOnExec discards the
// result, and a descriptor whose flag failed to set would survive the exec unnoticed.
func markCloseOnExec(descriptor int) error {
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(descriptor), syscall.F_GETFD, 0)
	if errno == 0 {
		_, _, errno = syscall.Syscall(syscall.SYS_FCNTL, uintptr(descriptor), syscall.F_SETFD, flags|syscall.FD_CLOEXEC)
	}
	if errno != 0 {
		return errno
	}
	return nil
}
