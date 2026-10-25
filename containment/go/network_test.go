package netguard

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestGameNetwork pairs every direct and child denial with the same syscall on loopback.
func TestGameNetwork(t *testing.T) {
	for _, address := range probeAddresses(t) {
		for _, operation := range []string{"connect", "sendto"} {
			t.Run(address+"/"+operation, func(t *testing.T) {
				port := loopbackPort(t, loopbackAddress(address), operation)
				requireProbe(t, "", "network", operation, loopbackAddress(address), port, "allowed")
				arguments := []string{"network", operation, address, port, "denied"}
				requireProbe(t, "profiles/game.sb", arguments...)
				requireProbe(t, "profiles/game.sb", append([]string{"child"}, arguments...)...)
			})
		}
	}
}

// probeAddresses includes every active non-loopback unicast address, without sending to it.
func probeAddresses(t *testing.T) []string {
	t.Helper()
	addresses := []string{"127.0.0.1", "192.0.2.1", "::1", "2001:db8::1", "::ffff:127.0.0.1"}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range interfaces {
		if device.Flags&net.FlagUp == 0 || device.Flags&net.FlagLoopback != 0 {
			continue
		}
		assigned, err := device.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, assignedAddress := range assigned {
			prefix, err := netip.ParsePrefix(assignedAddress.String())
			if err != nil {
				t.Fatal(err)
			}
			if prefix.Addr().IsGlobalUnicast() {
				addresses = append(addresses, prefix.Addr().String())
			}
		}
	}
	t.Logf("T1 destinations (LAN addresses when present): %v", addresses)
	return addresses
}

// loopbackAddress preserves the destination's socket family for safe positive controls.
func loopbackAddress(address string) string {
	parsed := netip.MustParseAddr(address)
	if parsed.Is4() {
		return "127.0.0.1"
	}
	if parsed.Is4In6() {
		return "::ffff:127.0.0.1"
	}
	return "::1"
}

// loopbackPort binds only loopback, providing a live positive peer for each operation.
func loopbackPort(t *testing.T, address string, operation string) string {
	t.Helper()
	host := loopbackAddress(address)
	network := "tcp4"
	if strings.Contains(host, ":") && !netip.MustParseAddr(host).Is4In6() {
		network = "tcp6"
	}
	if netip.MustParseAddr(host).Is4In6() {
		host = "127.0.0.1"
	}
	endpoint := net.JoinHostPort(host, "0")
	if operation == "sendto" {
		connection, err := net.ListenPacket(strings.Replace(network, "tcp", "udp", 1), endpoint)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			connection.Close()
		})
		return strconv.Itoa(connection.LocalAddr().(*net.UDPAddr).Port)
	}
	listener, err := net.Listen(network, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		listener.Close()
	})
	return strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
}

// TestBrokerNetwork proves T6 denies off-machine peers while admitting loopback peers.
func TestBrokerNetwork(t *testing.T) {
	for _, operation := range []string{"connect", "sendto"} {
		port := loopbackPort(t, "127.0.0.1", operation)
		requireProbe(t, "", "network", operation, "127.0.0.1", port, "allowed")
		requireProbe(t, "profiles/broker.sb", "network", operation, "127.0.0.1", port, "allowed")
		requireProbe(t, "profiles/broker.sb", "network", operation, "192.0.2.1", port, "denied")
	}
}

// TestDeliberateBreak requires the actual T1 probe to reject a permissive profile on loopback.
func TestDeliberateBreak(t *testing.T) {
	requireSeatbelt(t)
	contents, err := os.ReadFile("profiles/game.sb")
	if err != nil {
		t.Fatal(err)
	}
	broken := strings.Replace(string(contents), "(deny network*)", "(allow network*)", 1)
	if broken == string(contents) {
		t.Fatal("game profile no longer contains the rule to deliberately break")
	}
	brokenPath := filepath.Join(t.TempDir(), "broken.sb")
	err = os.WriteFile(brokenPath, []byte(broken), 0600)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"connect", "sendto"} {
		port := loopbackPort(t, "127.0.0.1", operation)
		requireProbe(t, "", "network", operation, "127.0.0.1", port, "allowed")
		output, err := probe(brokenPath, "network", operation, "127.0.0.1", port, "denied")
		t.Log(output)
		if err == nil || !strings.Contains(output, "refusal required:") {
			t.Fatalf("T1 did not detect the deliberate break: %v\n%s", err, output)
		}
	}
}
