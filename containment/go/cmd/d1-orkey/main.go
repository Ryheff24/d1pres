// Command d1-orkey holds the owner's OpenRouter key for agent sessions and forwards one route to
// one host with it: POST /v1/messages on 127.0.0.1:8790 to https://openrouter.ai/api/v1/messages
// (package orkey). A LaunchAgent starts it at login. The launcher takes the key from
// OPENROUTER_API_KEY when that is set (op run), else from the login Keychain item service
// "d1-orkey", account "openrouter". "d1-orkey store-key", run by the owner in a terminal after each
// install, creates that item from this binary's own process, so the item trusts this binary alone
// (by its code hash; install.sh signs it with the hardened runtime, so nothing can be loaded into
// it). The launcher never shows a Keychain dialog: a build the item does not trust refuses and
// names store-key, so the owner never learns to click a dialog that names d1-orkey. It runs its
// prove step as a child under the embedded profile (profiles/orkey.sb) with no key, writes the key
// into a pipe on descriptor 3, and replaces itself with sandbox-exec applying the same profile to
// "d1-orkey --serve", which reads the pipe and serves. No environment, argument or file holds the
// key; agents start sessions holding none (09.22 §3).
//
// Exit status: 2 refusal (one REFUSED line on stderr, about containment or about the key), 64 usage. "d1-orkey --prove" is the prove
// child: it prints its failed items on one line and exits 2, or exits 0. "d1-orkey controls" runs
// the forwarder's controls in memory, with no key and no socket, and exits 2 on any failure.
package main

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>
// SecKeychainSetUserInteractionAllowed, SecTrustedApplicationCreateFromPath and SecAccessCreate are
// deprecated with the file-based keychain, which is the login keychain this item lives in.
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

// keychain_key copies the login Keychain's generic password (service, account) into out, at most
// size bytes, sets *length to its full length, and returns the OSStatus. The Keychain checks the
// calling program, this binary, against the item's access and partition lists; with interaction
// off it refuses instead of asking the owner.
static OSStatus keychain_key(const char *service, const char *account, char *out, long size, long *length) {
	SecKeychainSetUserInteractionAllowed(false);
	CFStringRef s = CFStringCreateWithCString(NULL, service, kCFStringEncodingUTF8);
	CFStringRef a = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
	const void *keys[] = {kSecClass, kSecAttrService, kSecAttrAccount, kSecReturnData, kSecMatchLimit};
	const void *values[] = {kSecClassGenericPassword, s, a, kCFBooleanTrue, kSecMatchLimitOne};
	CFDictionaryRef query = CFDictionaryCreate(NULL, keys, values, 5, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFTypeRef data = NULL;
	OSStatus status = SecItemCopyMatching(query, &data);
	CFRelease(query);
	CFRelease(a);
	CFRelease(s);
	if (status != errSecSuccess) return status;
	*length = CFDataGetLength(data);
	if (*length <= size) memcpy(out, CFDataGetBytePtr(data), *length);
	CFRelease(data);
	return status;
}

// keychain_store deletes every generic password (service, account) and adds one holding key, whose
// access list trusts this binary alone. The item's creator is this process, not a security tool,
// so no other program is trusted by default (09.22: an item made by security trusts security).
static OSStatus keychain_store(const char *service, const char *account, const char *key, long length) {
	SecTrustedApplicationRef self = NULL;
	OSStatus status = SecTrustedApplicationCreateFromPath(NULL, &self);
	if (status != errSecSuccess) return status;
	CFArrayRef trusted = CFArrayCreate(NULL, (const void **)&self, 1, &kCFTypeArrayCallBacks);
	SecAccessRef access = NULL;
	status = SecAccessCreate(CFSTR("d1-orkey"), trusted, &access);
	CFRelease(trusted);
	CFRelease(self);
	if (status != errSecSuccess) return status;
	CFStringRef s = CFStringCreateWithCString(NULL, service, kCFStringEncodingUTF8);
	CFStringRef a = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
	CFDataRef secret = CFDataCreate(NULL, (const UInt8 *)key, length);
	const void *match_keys[] = {kSecClass, kSecAttrService, kSecAttrAccount};
	const void *match_values[] = {kSecClassGenericPassword, s, a};
	CFDictionaryRef match = CFDictionaryCreate(NULL, match_keys, match_values, 3, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	status = SecItemDelete(match);
	if (status == errSecSuccess || status == errSecItemNotFound) {
		const void *keys[] = {kSecClass, kSecAttrService, kSecAttrAccount, kSecValueData, kSecAttrAccess};
		const void *values[] = {kSecClassGenericPassword, s, a, secret, access};
		CFDictionaryRef item = CFDictionaryCreate(NULL, keys, values, 5, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
		status = SecItemAdd(item, NULL);
		CFRelease(item);
	}
	CFRelease(match);
	CFRelease(secret);
	CFRelease(a);
	CFRelease(s);
	CFRelease(access);
	return status;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"d1preservation/netguard"
	"d1preservation/netguard/gate"
	"d1preservation/netguard/orkey"
)

const proveFlag = "--prove"
const serveFlag = "--serve"

// The login Keychain item that holds the key, and how the owner stores it (README).
const (
	keychainService = "d1-orkey"
	keychainAccount = "openrouter"
	installedPath   = "/usr/local/libexec/d1-agent/d1-orkey"
	storeCommand    = installedPath + " store-key (in your terminal)"
)

// main picks the launcher, the prove step, the server or the controls. SIGPIPE is ignored so a
// closed stderr cannot stop a refusal short of exit 2; a socket on stderr exits 2 silently.
func main() {
	signal.Ignore(syscall.SIGPIPE)
	if gate.IsSocket(2) {
		os.Exit(2)
	}
	arguments := os.Args[1:]
	switch {
	case len(arguments) == 0:
		launch()
	case len(arguments) == 1 && arguments[0] == proveFlag:
		prove()
	case len(arguments) == 1 && arguments[0] == serveFlag:
		serve()
	case len(arguments) == 1 && arguments[0] == "controls":
		controls()
	case len(arguments) == 1 && arguments[0] == "store-key":
		storeKey()
	}
	fmt.Fprintln(os.Stderr, "usage: /usr/local/libexec/d1-agent/d1-orkey (the LaunchAgent com.d1preservation.orkey starts it)\n"+
		"  serves POST /v1/messages on "+orkey.Listen+" to https://openrouter.ai with the key from the login Keychain,\n"+
		"  or from OPENROUTER_API_KEY when set (op run --env-file=/usr/local/libexec/d1-agent/d1-orkey.env -- ...)\n"+
		"       d1-orkey store-key\n  reads the key from your terminal (not echoed) and stores it for this binary alone; after each install\n"+
		"       d1-orkey controls\n  runs the forwarder's controls (no key, no socket); exit 2 on any failure")
	os.Exit(64)
}

// refuse prints the REFUSED line and exits 2.
func refuse(failures []string) {
	fmt.Fprintln(os.Stderr, gate.Refusal("d1-orkey", "d1-orkey", failures))
	os.Exit(2)
}

// refuseKey prints the key refusal and exits 2: the key did not reach the server, so it never
// started and nothing was sent. That is a fault in d1-orkey or in how it was started, not a
// containment failure, so it does not send the reader to the containment procedure.
func refuseKey(why string) {
	fmt.Fprintln(os.Stderr, gate.OneLine("d1-orkey "+time.Now().Format("15:04:05")+" KEY NOT HANDED OVER - "+why+"; the server did not start and nothing "+
		"was sent. The key comes from the login Keychain (service "+keychainService+", account "+keychainAccount+
		"), or from OPENROUTER_API_KEY under op run; if it is stored there, report this line."))
	os.Exit(2)
}

// takeKey is the key and environment minus it: from OPENROUTER_API_KEY when that is set at all
// (op run), else from the login Keychain.
func takeKey(environment []string) (string, []string, error) {
	if _, set := os.LookupEnv(orkey.KeyVariable); set {
		return orkey.TakeKey(environment)
	}
	key, err := keychainKey(keychainService, keychainAccount)
	if err != nil {
		return "", nil, err
	}
	return key, orkey.WithoutKey(environment, key), nil
}

// keychainKey reads the Keychain item through the Security framework, in this process, so the
// program the Keychain checks is d1-orkey itself and not a security tool it started.
func keychainKey(service string, account string) (string, error) {
	cService, cAccount := C.CString(service), C.CString(account)
	defer C.free(unsafe.Pointer(cService))
	defer C.free(unsafe.Pointer(cAccount))
	buffer := make([]byte, 512)
	defer clear(buffer)
	var length C.long
	status := C.keychain_key(cService, cAccount, (*C.char)(unsafe.Pointer(&buffer[0])), C.long(len(buffer)), &length)
	item := "Keychain item service " + service + ", account " + account
	switch status {
	case 0:
	case -25300: // errSecItemNotFound
		return "", errors.New("no " + item + "; store the key: " + storeCommand)
	case -25293, -25308: // errSecAuthFailed, errSecInteractionNotAllowed
		return "", fmt.Errorf("the %s does not admit this d1-orkey build without a dialog (OSStatus %d; it was stored "+
			"by another build, or the keychain is locked), and d1-orkey shows none; store the key again: %s", item, int(status), storeCommand)
	default:
		return "", fmt.Errorf("the Keychain gave OSStatus %d for the %s", int(status), item)
	}
	if int(length) > len(buffer) {
		return "", fmt.Errorf("the %s holds %d bytes, more than an OpenRouter key", item, int(length))
	}
	key := string(buffer[:length])
	err := orkey.CheckKey(key)
	if err != nil {
		return "", fmt.Errorf("the %s: %w", item, err)
	}
	return key, nil
}

// storeKey is "d1-orkey store-key": the owner, in a terminal, after each install. It reads the key
// from the terminal with echo off, checks it, and replaces the Keychain item from this process, so
// the item trusts this binary at installedPath alone. It prints one line naming the item, or one
// refusal and exits 2.
func storeKey() {
	self, err := gate.Executable()
	if err != nil || self != installedPath {
		refuseStore("run it as " + installedPath + " store-key, the binary the item will trust (this is " + self + ")")
	}
	key, err := readSecret()
	defer clear(key)
	if err != nil {
		refuseStore(err.Error())
	}
	err = orkey.CheckKey(string(key))
	if err != nil {
		refuseStore(err.Error())
	}
	service, account := C.CString(keychainService), C.CString(keychainAccount)
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(account))
	status := C.keychain_store(service, account, (*C.char)(unsafe.Pointer(&key[0])), C.long(len(key)))
	if status != 0 {
		refuseStore(fmt.Sprintf("the Keychain gave OSStatus %d", int(status)))
	}
	fmt.Println("d1-orkey: stored the login Keychain item service " + keychainService + ", account " + keychainAccount + ", trusted to " + installedPath + " alone")
	os.Exit(0)
}

// refuseStore prints the store-key refusal and exits 2; the Keychain is as it was unless the
// refusal names an OSStatus from the store itself.
func refuseStore(why string) {
	fmt.Fprintln(os.Stderr, gate.OneLine("d1-orkey store-key: KEY NOT STORED - "+why))
	os.Exit(2)
}

// readSecret reads one line from the terminal on stdin with echo off. Anything but a terminal there
// (a pipe, a file) is refused, so no pipe, file or argument ever carries the key in. Echo comes back
// on return and on an interrupt.
func readSecret() ([]byte, error) {
	var saved syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, 0, syscall.TIOCGETA, uintptr(unsafe.Pointer(&saved)))
	if errno != 0 {
		return nil, errors.New("stdin is not a terminal; run it in your own terminal and type or paste the key")
	}
	quiet := saved
	quiet.Lflag &^= syscall.ECHO
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, 0, syscall.TIOCSETA, uintptr(unsafe.Pointer(&quiet)))
	if errno != 0 {
		return nil, fmt.Errorf("cannot turn echo off (%v)", errno)
	}
	restore := func() { syscall.Syscall(syscall.SYS_IOCTL, 0, syscall.TIOCSETA, uintptr(unsafe.Pointer(&saved))) }
	defer restore()
	interrupted := make(chan os.Signal, 1)
	signal.Notify(interrupted, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(interrupted)
	go func() {
		<-interrupted
		restore()
		os.Exit(2)
	}()
	fmt.Fprint(os.Stderr, "OpenRouter key (not shown): ")
	line := make([]byte, 0, 512)
	one := make([]byte, 1)
	for len(line) < cap(line) {
		n, err := syscall.Read(0, one)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return line, fmt.Errorf("read the terminal: %w", err)
		}
		if n == 0 || one[0] == '\n' || one[0] == '\r' {
			break
		}
		line = append(line, one[0])
	}
	one[0] = 0
	fmt.Fprintln(os.Stderr)
	return line, nil
}

// serverCommand is what the launcher execs: the profile and this binary's server mode, no key.
func serverCommand(policy string, self string) []string {
	return []string{gate.SandboxExec, "-p", policy, "--", self, serveFlag}
}

// launch runs outside the profile: hygiene, the key out of the environment or the Keychain, the
// policy, the prove child under it, the key into the pipe, then sandbox-exec with the same policy
// and the server.
func launch() {
	failures := gate.Hygiene()
	if len(failures) > 0 {
		refuse(failures)
	}
	key, environment, err := takeKey(gate.CleanEnvironment())
	if err != nil {
		refuseKey(err.Error())
	}
	self, err := gate.Executable()
	if err != nil {
		refuse([]string{"its own path: " + err.Error()})
	}
	policy, err := orkeyPolicy(self)
	if err != nil {
		refuse([]string{err.Error()})
	}
	why := gate.ProveUnder(policy, self, proveFlag, environment)
	if why != "" {
		refuse([]string{why})
	}
	err = handKey(key)
	if err != nil {
		refuseKey("key pipe: " + err.Error())
	}
	err = syscall.Exec(gate.SandboxExec, serverCommand(policy, self), environment)
	refuse([]string{"sandbox-exec: " + err.Error()})
}

// handKey writes key into a pipe and leaves the pipe's read end at orkey.KeyDescriptor, open
// across exec. The pipe is a raw one (no os.File, whose finalizer could close it), and
// close-on-exec is cleared on descriptor 3 explicitly and then checked: dup2 clears the flag only
// when it copies, and when the read end already is descriptor 3 it copies nothing. That was the
// first start's failure (owner, 21:15: "read key: bad file descriptor"; os.Pipe sets the flag).
func handKey(key string) error {
	var ends [2]int
	err := syscall.Pipe(ends[:])
	if err != nil {
		return err
	}
	reader, writer := ends[0], ends[1]
	written, err := syscall.Write(writer, []byte(key))
	syscall.Close(writer)
	if err == nil && written != len(key) {
		err = fmt.Errorf("wrote %d of %d bytes", written, len(key))
	}
	if err == nil && reader != orkey.KeyDescriptor {
		err = syscall.Dup2(reader, orkey.KeyDescriptor)
		syscall.Close(reader)
	}
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, orkey.KeyDescriptor, syscall.F_SETFD, 0)
	if errno != 0 {
		return fmt.Errorf("clear close-on-exec: %v", errno)
	}
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, orkey.KeyDescriptor, syscall.F_GETFD, 0)
	if errno != 0 || flags&syscall.FD_CLOEXEC != 0 {
		return fmt.Errorf("descriptor %d would close on exec (flags %d, %v)", orkey.KeyDescriptor, flags, errno)
	}
	return nil
}

// orkeyPolicy is orkey.sb with this binary's resolved path for SELF, the one program it may exec.
func orkeyPolicy(self string) (string, error) {
	err := gate.CheckParameter(self)
	if err != nil {
		return "", fmt.Errorf("its own path: %w", err)
	}
	return gate.NormalizeWith(netguard.OrkeyProfile, map[string]string{"SELF": self}), nil
}

// prove runs inside the profile as the launcher's child: nothing but TCP 443 leaves (TEST-NET-1
// at port 80, UDP 443, loopback and LAN port 9 are refused), no file is written, nothing else
// runs; and the positive controls pass: the listen address binds and /dev/null opens for writing.
func prove() {
	home, err := gate.Home()
	if err != nil {
		fmt.Fprintln(os.Stderr, gate.OneLine("home directory: "+err.Error()))
		os.Exit(2)
	}
	failures := gate.NoOpenSockets()
	failures = append(failures, gate.NoNetwork()...)
	testNet := netip.MustParseAddr("192.0.2.1")
	failures = refused(failures, "tcp 192.0.2.1:80", attempt(syscall.SOCK_STREAM, testNet, 80))
	failures = refused(failures, "udp 192.0.2.1:443", attempt(syscall.SOCK_DGRAM, testNet, 443))
	for _, directory := range []string{home, "/private/tmp", "/private/var/folders"} {
		failures = refused(failures, "write in "+directory, createIn(directory))
	}
	failures = append(failures, gate.Execs([]string{"/bin/sh", "/usr/bin/open", "/usr/bin/osascript"})...)
	listener, err := net.Listen("tcp", orkey.Listen)
	if err != nil {
		failures = append(failures, "listen control "+orkey.Listen+": "+err.Error()+" (is a d1-orkey already serving?)")
	} else {
		listener.Close()
	}
	null, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
	if err != nil {
		failures = append(failures, "write control /dev/null: "+err.Error())
	} else {
		null.Close()
	}
	if len(failures) > 0 {
		fmt.Fprintln(os.Stderr, gate.OneLine(strings.Join(failures, ", ")))
		os.Exit(2)
	}
	os.Exit(0)
}

// refused appends "what: why" unless err is a sandbox refusal (gate's check, which is unexported).
func refused(failures []string, what string, err error) []string {
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return failures
	}
	if err == nil {
		err = errors.New("succeeded")
	}
	return append(failures, what+": "+err.Error())
}

// attempt connects (stream) or sends one byte (datagram) on a nonblocking IPv4 socket, as gate's
// unexported attempt does, so a broken profile cannot hang it.
func attempt(socketType int, address netip.Addr, port int) error {
	descriptor, err := syscall.Socket(syscall.AF_INET, socketType, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(descriptor)
	destination := &syscall.SockaddrInet4{Port: port, Addr: address.As4()}
	err = syscall.SetNonblock(descriptor, true)
	if err == nil && socketType == syscall.SOCK_STREAM {
		return syscall.Connect(descriptor, destination)
	}
	if err == nil {
		return syscall.Sendto(descriptor, []byte("x"), 0, destination)
	}
	return fmt.Errorf("cannot make the probe socket nonblocking (%v)", err)
}

// createIn creates a new file in directory, and removes it if that succeeded.
func createIn(directory string) error {
	name := filepath.Join(directory, fmt.Sprintf(".d1-orkey-probe-%d", os.Getpid()))
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	file.Close()
	os.Remove(name)
	return nil
}

// serve runs inside the profile: the key from the pipe, no core file (it would hold the key), then
// the forwarder on orkey.Listen. Each request is logged as method, path and status, never headers.
func serve() {
	key, err := orkey.ReadKey(os.NewFile(orkey.KeyDescriptor, "key"))
	syscall.Close(orkey.KeyDescriptor)
	if err != nil {
		refuseKey(err.Error())
	}
	err = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{})
	if err != nil {
		refuseKey("core limit (a core file would hold the key): " + err.Error())
	}
	handler := orkey.Handler(key, orkey.Transport())
	server := &http.Server{
		Addr:              orkey.Listen,
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			started := time.Now()
			status := &statusWriter{ResponseWriter: writer, status: http.StatusOK}
			handler.ServeHTTP(status, request)
			fmt.Fprintln(os.Stderr, gate.OneLine(fmt.Sprintf("d1-orkey %s %s %s %d %dms", started.Format("15:04:05"), request.Method, request.URL.Path, status.status, time.Since(started).Milliseconds())))
		}),
	}
	fmt.Fprintln(os.Stderr, "d1-orkey "+time.Now().Format("15:04:05")+" serving http://"+orkey.Listen+orkey.Route+" to https://"+orkey.UpstreamHost)
	refuse([]string{"serve: " + server.ListenAndServe().Error()})
}

// statusWriter records the status for the log line and passes Flush on, which streaming needs.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// controls runs the forwarder's controls against this binary's own server command line.
func controls() {
	failures := orkey.Controls(func() []string { return serverCommand("(version 1)", "/usr/local/libexec/d1-agent/d1-orkey") })
	for _, failure := range failures {
		fmt.Println("FAIL", failure)
	}
	if len(failures) > 0 {
		os.Exit(2)
	}
	fmt.Println("OK   d1-orkey controls: one route, one host, the key in no child environment or argument")
	os.Exit(0)
}
