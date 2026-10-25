package main

import (
	"fmt"
	"net/netip"
	"strconv"
	"syscall"
)

// networkProbe exercises the exact connect or sendto syscall with an explicit family.
func networkProbe(arguments []string) error {
	operation := arguments[0]
	address := netip.MustParseAddr(arguments[1])
	port, err := strconv.Atoi(arguments[2])
	if err != nil {
		return err
	}
	family, destination := socketDestination(address, port)
	socketType := syscall.SOCK_STREAM
	if operation == "sendto" {
		socketType = syscall.SOCK_DGRAM
	}
	descriptor, err := syscall.Socket(family, socketType, 0)
	if err != nil {
		return fmt.Errorf("socket creation failed before %s: %w", operation, err)
	}
	defer syscall.Close(descriptor)
	fmt.Printf("PROBE %s %s family=%d\n", operation, address, family)
	if operation == "sendto" {
		err = syscall.Sendto(descriptor, []byte("control"), 0, destination)
	} else {
		err = connectProbe(descriptor, destination, arguments[3] == "allowed")
	}
	return expectPermission(arguments[3], err)
}

// socketDestination preserves IPv4-mapped IPv6 instead of Go Dial's IPv4 conversion.
func socketDestination(address netip.Addr, port int) (int, syscall.Sockaddr) {
	if address.Is4() {
		return syscall.AF_INET, &syscall.SockaddrInet4{Port: port, Addr: address.As4()}
	}
	return syscall.AF_INET6, &syscall.SockaddrInet6{Port: port, Addr: address.As16()}
}

// connectProbe bounds even a broken policy, and confirms positive TCP handshakes.
func connectProbe(descriptor int, destination syscall.Sockaddr, wait bool) error {
	err := syscall.SetNonblock(descriptor, true)
	if err != nil {
		return fmt.Errorf("set nonblocking: %w", err)
	}
	err = syscall.Connect(descriptor, destination)
	if err != syscall.EINPROGRESS || !wait {
		return err
	}
	if descriptor >= 1024 {
		return fmt.Errorf("descriptor exceeds select capacity: %d", descriptor)
	}
	var writable syscall.FdSet
	writable.Bits[descriptor/32] |= 1 << uint(descriptor%32)
	timeout := syscall.Timeval{Sec: 1}
	err = syscall.Select(descriptor+1, nil, &writable, nil, &timeout)
	if err != nil {
		return err
	}
	if writable.Bits[descriptor/32]&(1<<uint(descriptor%32)) == 0 {
		return fmt.Errorf("loopback connection timed out")
	}
	result, err := syscall.GetsockoptInt(descriptor, syscall.SOL_SOCKET, syscall.SO_ERROR)
	if err != nil {
		return err
	}
	if result != 0 {
		return syscall.Errno(result)
	}
	return nil
}
