package gate

import (
	"fmt"
	"net/netip"
	"syscall"
)

// ProtectedFiles are the repository files no agent edits and nothing under d1-localonly writes:
// the policies, the code that applies them, the gate call sites, the agent instructions, and what
// git, cargo and Claude Code read on the owner's behalf. Named files only, never directories (owner,
// 2026-10-16). The hook refuses edits to each; local.sb denies writes to each and renames of every
// directory above one (TestLocalProtectedFiles keeps the two lists equal). A file that does not
// exist yet is protected against being created.
var ProtectedFiles = []string{
	"CLAUDE.md",
	"AGENTS.md",
	".claude/settings.json",
	".claude/settings.local.json",
	".git/config",
	".git/hooks/pre-push",
	".cargo/config.toml",
	"d1-server/.cargo/config.toml",
	"containment/agent-containment.md",
	"containment/install.sh",
	"containment/c/d1netgate.c",
	"containment/go/profile.go",
	"containment/go/profiles/game.sb",
	"containment/go/profiles/local.sb",
	"containment/go/gate/gate.go",
	"containment/go/gate/launch.go",
	"containment/go/gate/local.go",
	"containment/go/hook/hook.go",
	"containment/go/hook/install.go",
	"containment/go/hook/protect.go",
	"containment/go/hook/shell.go",
	"containment/go/cmd/d1-nonet/main.go",
	"containment/go/cmd/d1-localonly/main.go",
	"containment/go/cmd/d1-agent-hook/main.go",
	"d1-server/crates/d1-recomp/netgate_profile.rs",
	"d1-server/crates/d1-recomp/build.rs",
	"d1-server/crates/d1-recomp/src/main.rs",
	"d1-server/crates/d1-oracle/build.rs",
	"d1-server/crates/d1-oracle/src/main.rs",
	"d1-server/crates/d1-replay/build.rs",
	"d1-server/crates/d1-replay/src/main.rs",
	"containment/c/d1testgate.c",
	"containment/go/cmd/d1-testgate-header/main.go",
	"tools/d1/internal/testgate/testgate.go",
	"tools/d1/internal/testgate/testgate_test.go",
	"containment/go/profiles/orkey.sb",
	"containment/go/cmd/d1-orkey/main.go",
	"containment/go/orkey/orkey.go",
	"containment/go/orkey/controls.go",
}

// GameBinaries run game code (or, d1-srv, start it) and run only under d1-nonet. The Rust three
// carry the C gate; d1-srv probes its own containment at start.
var GameBinaries = []string{"d1-recomp", "d1-oracle", "d1-replay", "d1-srv"}

// BeyondThisMac attempts TCP to 192.0.2.1:443, then UDP to 192.0.2.1, multicast 239.255.255.250
// and broadcast 255.255.255.255, all at port 3074; both ports are listed, so only the address can
// refuse them. It stops at the first not refused: a leaking profile then sends at most one packet,
// to TEST-NET-1 (RFC 5737), which is never routed to a host.
func BeyondThisMac() []string {
	testNet := netip.MustParseAddr("192.0.2.1")
	multicast := netip.MustParseAddr("239.255.255.250")
	probes := []struct {
		what    string
		attempt func() error
	}{
		{"tcp 192.0.2.1:443", func() error { return attempt(syscall.SOCK_STREAM, testNet, 0, 443) }},
		{"udp 192.0.2.1:3074", func() error { return attempt(syscall.SOCK_DGRAM, testNet, 0, 3074) }},
		{"udp 239.255.255.250:3074 (multicast)", func() error { return attempt(syscall.SOCK_DGRAM, multicast, 0, 3074) }},
		{"udp 255.255.255.255:3074 (broadcast)", broadcast},
	}
	for _, probe := range probes {
		failures := check(nil, probe.what, probe.attempt())
		if len(failures) > 0 {
			return failures
		}
	}
	return nil
}

// broadcast sends one byte to 255.255.255.255:3074. SO_BROADCAST is set first: without it the
// kernel itself answers EACCES, which would read as a refusal. A failure to set it is reported
// without its errno, so it can never read as one either.
func broadcast() error {
	descriptor, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(descriptor)
	err = syscall.SetsockoptInt(descriptor, syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
	if err != nil {
		return fmt.Errorf("cannot set SO_BROADCAST, so a refusal would prove nothing (%v)", err)
	}
	return syscall.Sendto(descriptor, []byte("x"), 0, &syscall.SockaddrInet4{Port: 3074, Addr: [4]byte{255, 255, 255, 255}})
}

// LoopbackOpen is the positive control for the network rules: TCP and UDP to 127.0.0.1 at port,
// which the profile lists, and a bind to 127.0.0.1 port 0 must each get any answer but a refusal
// (nothing listening is fine), so probes that read everything as refused cannot pass.
func LoopbackOpen(port int) []string {
	loopback := netip.MustParseAddr("127.0.0.1")
	what := fmt.Sprintf("127.0.0.1:%d (a listed port)", port)
	failures := notRefused(nil, "tcp "+what, attempt(syscall.SOCK_STREAM, loopback, 0, port))
	failures = notRefused(failures, "udp "+what, attempt(syscall.SOCK_DGRAM, loopback, 0, port))
	return notRefused(failures, "bind 127.0.0.1:0", bindLoopback())
}

// notRefused appends "what: refused" when err is a sandbox refusal; any other answer passes.
func notRefused(failures []string, what string, err error) []string {
	if len(check(nil, what, err)) == 0 {
		return append(failures, what+": refused ("+err.Error()+")")
	}
	return failures
}

// bindLoopback binds a fresh TCP socket to 127.0.0.1 port 0 and closes it; it listens for nothing.
func bindLoopback() error {
	descriptor, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(descriptor)
	return syscall.Bind(descriptor, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}})
}

// LocalSocketOptions requires the IPv4 and IPv6 multicast options refused (a join sends IGMP
// whatever the address rules say) and SO_REUSEADDR set, which servers need: the positive control.
func LocalSocketOptions() []string {
	failures := check(nil, "setsockopt IP_MULTICAST_TTL", setOption(syscall.AF_INET, syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL))
	failures = check(failures, "setsockopt IPV6_MULTICAST_HOPS", setOption(syscall.AF_INET6, syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_HOPS))
	err := setOption(syscall.AF_INET, syscall.SOL_SOCKET, syscall.SO_REUSEADDR)
	if err != nil {
		failures = append(failures, "setsockopt SO_REUSEADDR (allowed): "+err.Error())
	}
	return failures
}
