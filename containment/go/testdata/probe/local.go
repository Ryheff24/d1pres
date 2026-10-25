package main

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"syscall"
)

// loopbackProbe listens on address:port with raw syscalls (no socket option first), then connects
// to it from the same process. "allowed" needs the connection made and one byte across it;
// "denied" needs the connect refused by policy. A failed bind or listen is reported without its
// errno, so it can never read as the connect's refusal.
func loopbackProbe(addressText string, portText string, expectation string) error {
	port, err := strconv.Atoi(portText)
	if err != nil {
		return err
	}
	family, destination := socketDestination(netip.MustParseAddr(addressText), port)
	listener, err := syscall.Socket(family, syscall.SOCK_STREAM, 0)
	if err != nil {
		return fmt.Errorf("listener socket: %v", err)
	}
	defer syscall.Close(listener)
	err = syscall.Bind(listener, destination)
	if err == nil {
		err = syscall.Listen(listener, 1)
	}
	if err != nil {
		return fmt.Errorf("listen on %s:%d failed before the connect was tried: %v", addressText, port, err)
	}
	client, err := syscall.Socket(family, syscall.SOCK_STREAM, 0)
	if err != nil {
		return fmt.Errorf("client socket: %v", err)
	}
	err = connectProbe(client, destination, expectation == "allowed")
	if err != nil {
		syscall.Close(client)
		return expectPermission(expectation, err)
	}
	return expectPermission(expectation, exchangeOneByte(listener, client))
}

// exchangeOneByte accepts the connection, carries one byte from the client to the server and
// closes both, the client first, and the server only once it has read the client's end of stream:
// the side that closes first holds TIME_WAIT, and on the client that is an ephemeral port, so the
// listed port is free for the next run.
func exchangeOneByte(listener int, client int) error {
	accepted, _, err := syscall.Accept(listener)
	if err != nil {
		syscall.Close(client)
		return fmt.Errorf("accept: %v", err)
	}
	defer syscall.Close(accepted)
	_, err = syscall.Write(client, []byte("x"))
	if err != nil {
		syscall.Close(client)
		return fmt.Errorf("write: %v", err)
	}
	buffer := make([]byte, 1)
	count, err := syscall.Read(accepted, buffer)
	syscall.Close(client)
	if err != nil || count != 1 || buffer[0] != 'x' {
		return fmt.Errorf("the byte did not arrive: %d %v", count, err)
	}
	count, err = syscall.Read(accepted, buffer)
	if err != nil || count != 0 {
		return fmt.Errorf("no end of stream after the client closed: %d %v", count, err)
	}
	fmt.Println("loopback exchange completed")
	return nil
}

// bindProbe binds a fresh TCP socket to address, port 0, and listens for nothing.
func bindProbe(addressText string, expectation string) error {
	family, destination := socketDestination(netip.MustParseAddr(addressText), 0)
	descriptor, err := syscall.Socket(family, syscall.SOCK_STREAM, 0)
	if err != nil {
		return fmt.Errorf("socket: %v", err)
	}
	defer syscall.Close(descriptor)
	fmt.Printf("PROBE bind %s\n", addressText)
	return expectPermission(expectation, syscall.Bind(descriptor, destination))
}

// renameProbe renames source to destination and, if that worked, back again.
func renameProbe(source string, destination string, expectation string) error {
	err := os.Rename(source, destination)
	if err == nil {
		restoreError := os.Rename(destination, source)
		if restoreError != nil {
			return fmt.Errorf("renamed %s and could not rename it back: %v", source, restoreError)
		}
	}
	return expectPermission(expectation, err)
}
