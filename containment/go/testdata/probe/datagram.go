package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
)

// receivedDatagramProbe reads one SCM_RIGHTS endpoint from the inherited control descriptor.
func receivedDatagramProbe(descriptorText string) error {
	descriptor, err := strconv.Atoi(descriptorText)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(descriptor), "control")
	defer file.Close()
	inherited, err := net.FileConn(file)
	if err != nil {
		return err
	}
	defer inherited.Close()
	connection, isUnix := inherited.(*net.UnixConn)
	if !isUnix {
		return fmt.Errorf("descriptor %d is not a Unix socket", descriptor)
	}
	err = connection.SetDeadline(time.Now().Add(time.Second))
	if err != nil {
		return err
	}
	data := make([]byte, 1)
	ancillary := make([]byte, syscall.CmsgSpace(4))
	_, ancillaryLength, _, _, err := connection.ReadMsgUnix(data, ancillary)
	if err != nil {
		return err
	}
	messages, err := syscall.ParseSocketControlMessage(ancillary[:ancillaryLength])
	if err != nil || len(messages) != 1 {
		return fmt.Errorf("expected one rights message: %v", err)
	}
	descriptors, err := syscall.ParseUnixRights(&messages[0])
	if err != nil {
		return err
	}
	for _, received := range descriptors {
		defer syscall.Close(received)
	}
	if len(descriptors) != 1 {
		return fmt.Errorf("expected one received descriptor, got %d", len(descriptors))
	}
	return echoDatagram(descriptors[0])
}

// echoDatagram confirms whole-datagram I/O on the received endpoint. It sets no socket option:
// game.sb denies them all; the parent's deadline and the probe timeout bound the read.
func echoDatagram(descriptor int) error {
	buffer := make([]byte, 32)
	length, err := syscall.Read(descriptor, buffer)
	if err != nil {
		return err
	}
	if string(buffer[:length]) != "whole datagram" {
		return fmt.Errorf("unexpected datagram %q", buffer[:length])
	}
	_, err = syscall.Write(descriptor, buffer[:length])
	return err
}

// udpRoundTripProbe exercises the broker's local bind and inbound rules using only loopback.
func udpRoundTripProbe(endpoint string) error {
	peer, err := net.ResolveUDPAddr("udp4", endpoint)
	if err != nil {
		return err
	}
	local := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	connection, err := net.DialUDP("udp4", local, peer)
	if err != nil {
		return err
	}
	defer connection.Close()
	err = connection.SetDeadline(time.Now().Add(time.Second))
	if err != nil {
		return err
	}
	_, err = connection.Write([]byte("loopback"))
	if err != nil {
		return err
	}
	buffer := make([]byte, 32)
	length, err := connection.Read(buffer)
	if err != nil {
		return err
	}
	if string(buffer[:length]) != "loopback" {
		return fmt.Errorf("loopback reply changed: %q", buffer[:length])
	}
	return nil
}
