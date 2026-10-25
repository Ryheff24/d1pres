package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// main dispatches only explicit test operations and reports failures to the parent.
func main() {
	arguments := os.Args[1:]
	var err error
	switch arguments[0] {
	case "hello":
		fmt.Println("helper started")
	case "network":
		err = networkProbe(arguments[1:])
	case "unix":
		err = unixProbe(arguments[1], arguments[2])
	case "unix-listen":
		err = unixListenProbe(arguments[1], arguments[2])
	case "received-datagram":
		err = receivedDatagramProbe(arguments[1])
	case "udp-roundtrip":
		err = udpRoundTripProbe(arguments[1])
	case "resolve":
		err = resolverProbe(arguments[1], arguments[2])
	case "execute":
		err = executeProbe(arguments[1:])
	case "start":
		err = startProbe(arguments[1:])
	case "child":
		err = childProbe(arguments[1:])
	case "mutate":
		err = mutateProbe(arguments[1], arguments[2], arguments[3], arguments[4])
	case "descriptors":
		err = descriptorsProbe()
	case "loopback":
		err = loopbackProbe(arguments[1], arguments[2], arguments[3])
	case "bind":
		err = bindProbe(arguments[1], arguments[2])
	case "rename":
		err = renameProbe(arguments[1], arguments[2], arguments[3])
	default:
		err = fmt.Errorf("unknown test operation %q", arguments[0])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// expectPermission requires a real policy errno, never an incidental network failure.
func expectPermission(expectation string, err error) error {
	if expectation == "allowed" && err == nil {
		return nil
	}
	if expectation == "denied" {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			fmt.Printf("refused by policy: %v\n", err)
			return nil
		}
		return fmt.Errorf("refusal required: got %v", err)
	}
	return fmt.Errorf("success required: got %v", err)
}

// unixProbe connects without sending application data, including to mDNSResponder.
func unixProbe(path string, expectation string) error {
	connection, err := net.DialTimeout("unix", path, time.Second)
	if connection != nil {
		connection.Close()
	}
	return expectPermission(expectation, err)
}

// unixListenProbe binds and listens on a Unix socket with raw syscalls and no socket option
// first, so a denial comes from the network rule. A file created and removed at the same path
// first shows the directory is writable, so the filesystem cannot be the cause either.
func unixListenProbe(path string, expectation string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("the socket's directory is not writable, a denial would prove nothing: %w", err)
	}
	file.Close()
	err = os.Remove(path)
	if err != nil {
		return err
	}
	descriptor, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return fmt.Errorf("socket creation failed before bind: %w", err)
	}
	defer syscall.Close(descriptor)
	err = syscall.Bind(descriptor, &syscall.SockaddrUnix{Name: path})
	if err == nil {
		defer os.Remove(path)
		err = syscall.Listen(descriptor, 1)
	}
	return expectPermission(expectation, err)
}

// resolverProbe uses Go's forced libSystem resolver, with diagnostics captured by tests.
func resolverProbe(name string, expectation string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupHost(ctx, name)
	fmt.Printf("%s addresses=%v error=%v\n", name, addresses, err)
	if expectation == "denied" && err != nil && ctx.Err() == nil {
		return nil
	}
	if expectation == "allowed" && err == nil && len(addresses) > 0 {
		return nil
	}
	return fmt.Errorf("resolver expected %s, got addresses=%v error=%v", expectation, addresses, err)
}

// executeProbe replaces this process, so success cannot be mistaken for an exec denial.
func executeProbe(arguments []string) error {
	expectation := arguments[0]
	path := arguments[1]
	fmt.Printf("PROBE exec %s\n", path)
	err := syscall.Exec(path, arguments[1:], os.Environ())
	return expectPermission(expectation, err)
}

// startProbe distinguishes successful exec from open's nonzero usage exit without opening anything.
func startProbe(arguments []string) error {
	command := exec.Command(arguments[1], arguments[2:]...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	err := command.Start()
	if err != nil {
		return expectPermission(arguments[0], err)
	}
	fmt.Printf("exec completed: %v\n", command.Wait())
	return expectPermission(arguments[0], nil)
}

// childProbe uses Go's safe fork/exec path to test inherited policy in a child.
func childProbe(arguments []string) error {
	path, err := os.Executable()
	if err != nil {
		return err
	}
	command := exec.Command(path, arguments...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return command.Run()
}

// mutateProbe attempts create, write, rename and unlink at a protected place: create newPath,
// append to existingPath, rename existingPath to renamedPath, unlink what remains. Each must be
// refused ("denied") or each must succeed ("allowed"); every attempt is reported.
func mutateProbe(expectation string, newPath string, existingPath string, renamedPath string) error {
	file, createError := os.OpenFile(newPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if createError == nil {
		file.Close()
		os.Remove(newPath)
	}
	file, writeError := os.OpenFile(existingPath, os.O_WRONLY|os.O_APPEND, 0)
	if writeError == nil {
		_, writeError = file.Write([]byte("x"))
		file.Close()
	}
	renameError := os.Rename(existingPath, renamedPath)
	remaining := existingPath
	if renameError == nil {
		remaining = renamedPath
	}
	unlinkError := os.Remove(remaining)
	var failures []string
	for name, err := range map[string]error{"create": createError, "write": writeError, "rename": renameError, "unlink": unlinkError} {
		result := expectPermission(expectation, err)
		if result != nil {
			failures = append(failures, name+": "+result.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("%v", failures)
	}
	return nil
}

// descriptorsProbe prints every descriptor above 2 still open in this process, sockets and
// regular files alike, and fails if there is any. Its own listing's descriptors are closed first.
func descriptorsProbe() error {
	directory, err := os.Open("/dev/fd")
	if err != nil {
		return err
	}
	names, err := directory.Readdirnames(-1)
	directory.Close()
	if err != nil {
		return err
	}
	var open []string
	for _, name := range names {
		var descriptor int
		var status syscall.Stat_t
		_, scanError := fmt.Sscan(name, &descriptor)
		if scanError == nil && descriptor > 2 && syscall.Fstat(descriptor, &status) == nil {
			open = append(open, fmt.Sprintf("%d(mode %o)", descriptor, status.Mode&syscall.S_IFMT))
		}
	}
	fmt.Printf("descriptors above 2: %v\n", open)
	if len(open) > 0 {
		return fmt.Errorf("inherited descriptors survived: %v", open)
	}
	return nil
}
