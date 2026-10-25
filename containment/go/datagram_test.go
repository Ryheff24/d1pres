package netguard

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// TestReceivedDatagram answers whether network denial permits I/O on an SCM_RIGHTS endpoint
// received over an inherited control descriptor.
func TestReceivedDatagram(t *testing.T) {
	for _, profilePath := range []string{"", "profiles/game.sb"} {
		t.Run("profile="+profilePath, func(t *testing.T) {
			runDatagramControl(t, profilePath)
		})
	}
}

// runDatagramControl hands the helper a pre-connected Unix stream at descriptor 3, the shape
// netguard uses for the game's broker channel, and passes a datagram endpoint over it.
func runDatagramControl(t *testing.T, profilePath string) {
	t.Helper()
	if profilePath != "" {
		requireSeatbelt(t)
	}
	descriptors, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(descriptors[0])
	defer syscall.Close(descriptors[1])
	syscall.CloseOnExec(descriptors[0])
	syscall.CloseOnExec(descriptors[1])
	control, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	syscall.CloseOnExec(control[0])
	syscall.CloseOnExec(control[1])
	parentFile := os.NewFile(uintptr(control[0]), "control-parent")
	childFile := os.NewFile(uintptr(control[1]), "control-child")
	defer parentFile.Close()
	defer childFile.Close()
	connection, err := net.FileConn(parentFile)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	result := make(chan error, 1)
	go func() {
		result <- sendDatagramRights(connection.(*net.UnixConn), descriptors)
	}()
	output, probeError := probeWithFiles(profilePath, []*os.File{childFile}, "received-datagram", "3")
	serverError := <-result
	t.Log(output)
	if probeError != nil || serverError != nil {
		t.Fatalf("received datagram: helper=%v peer=%v", probeError, serverError)
	}
}

// sendDatagramRights passes an endpoint and checks a complete local datagram round trip.
func sendDatagramRights(connection *net.UnixConn, descriptors [2]int) error {
	err := connection.SetDeadline(time.Now().Add(3 * time.Second))
	if err != nil {
		return err
	}
	_, _, err = connection.WriteMsgUnix([]byte("f"), syscall.UnixRights(descriptors[0]), nil)
	if err != nil {
		return err
	}
	timeout := syscall.Timeval{Sec: 3}
	err = syscall.SetsockoptTimeval(descriptors[1], syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout)
	if err != nil {
		return err
	}
	_, err = syscall.Write(descriptors[1], []byte("whole datagram"))
	if err != nil {
		return err
	}
	buffer := make([]byte, 32)
	length, err := syscall.Read(descriptors[1], buffer)
	if err != nil {
		return err
	}
	if string(buffer[:length]) != "whole datagram" {
		return fmt.Errorf("datagram round trip changed the message: %q", buffer[:length])
	}
	return nil
}

// TestBrokerLoopbackIO exercises local IP binding and inbound replies, paired with T6 denials.
func TestBrokerLoopbackIO(t *testing.T) {
	for _, profilePath := range []string{"", "profiles/broker.sb"} {
		if profilePath != "" {
			requireSeatbelt(t)
		}
		listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		err = listener.SetDeadline(time.Now().Add(3 * time.Second))
		if err != nil {
			listener.Close()
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() {
			result <- echoLoopback(listener)
		}()
		output, probeError := probe(profilePath, "udp-roundtrip", listener.LocalAddr().String())
		serverError := <-result
		listener.Close()
		if probeError != nil || serverError != nil {
			t.Fatalf("loopback I/O: helper=%v peer=%v\n%s", probeError, serverError, output)
		}
	}
}

// echoLoopback replies only to the synthetic UDP peer on the local listener.
func echoLoopback(listener *net.UDPConn) error {
	buffer := make([]byte, 32)
	length, peer, err := listener.ReadFromUDP(buffer)
	if err != nil {
		return err
	}
	_, err = listener.WriteToUDP(buffer[:length], peer)
	return err
}
