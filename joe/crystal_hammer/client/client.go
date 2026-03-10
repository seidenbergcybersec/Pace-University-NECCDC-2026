package main

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
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

func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	rawKey, err := ssh.ParseRawPrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("parse raw private key: %w", err)
	}
	rsaPriv, ok := rawKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA (it is %T)", rawKey)
	}
	return rsaPriv, nil
}

func startInteractiveShell(bc *bufioConn) {
    sshConfig := &ssh.ClientConfig{
        User:            "shell",
        Auth:            []ssh.AuthMethod{},
        HostKeyCallback: ssh.InsecureIgnoreHostKey(),
    }

    safeConn := &nopCloserConn{Conn: bc}
    sshConn, chans, reqs, err := ssh.NewClientConn(safeConn, bc.RemoteAddr().String(), sshConfig)
    if err != nil {
        fmt.Fprintf(os.Stderr, "\n[ERROR] SSH handshake failed: %v\n", err)
        return
    }
    client := ssh.NewClient(sshConn, chans, reqs)

    session, err := client.NewSession()
    if err != nil {
        fmt.Fprintf(os.Stderr, "[ERROR] Session failed: %v\n", err)
        return
    }

    fd := int(os.Stdin.Fd())
    oldState, _ := term.MakeRaw(fd)
    defer term.Restore(fd, oldState)

    w, h, _ := term.GetSize(fd)
    session.RequestPty("xterm-256color", h, w, ssh.TerminalModes{})

    session.Stdin = os.Stdin
    session.Stdout = os.Stdout
    session.Stderr = os.Stderr

    session.Shell()
    session.Wait()

    session.Close()
    client.Close()
}

// asyncReader continuously reads from the server and prints to stdout.
// It exits when stopReader is closed or the connection dies.
func asyncReader(bc *bufioConn, stopReader <-chan struct{}, readerDone chan struct{}) {
	defer close(readerDone)
	buf := make([]byte, 4096)
	for {
		n, err := bc.Read(buf)
		if n > 0 {
			fmt.Print(string(buf[:n]))
		}
		if err != nil {
			// Check if we were stopped intentionally
			select {
			case <-stopReader:
				return
			default:
				return
			}
		}
		
		// Check if stop signal was sent while we weren't blocked
		select {
		case <-stopReader:
			return
		default:
		}
	}
}

func main() {
	var addr string
	var port string
	var keyPath string

	// 1. Bind both long and short flags to the same variables
	flag.StringVar(&addr, "addr", "", "Server address")
	flag.StringVar(&addr, "a", "", "Server address (shorthand)")
	
	flag.StringVar(&port, "port", "6769", "Server port")
	flag.StringVar(&port, "p", "6769", "Server port (shorthand)")
	
	flag.StringVar(&keyPath, "key", "id_rsa", "Path to private key")
	
	flag.Parse()

	// 2. Handle positional arguments (e.g., ./client 1.2.3.4 8080)
	// flag.Args() contains everything that didn't start with a hyphen
	posArgs := flag.Args()
	if len(posArgs) > 0 && addr == "" {
		// If -a or -addr wasn't used, take the first positional arg as the address
		addr = posArgs[0]
	}
	if len(posArgs) > 1 {
		// If a second positional arg exists, treat it as the port
		port = posArgs[1]
	}

	// 3. Validation
	if addr == "" {
		fmt.Println("Usage: client [addr] [port] or use -a <addr> -p <port>")
		os.Exit(1)
	}

	// Now use 'addr' and 'port' variables directly
	conn, err := tls.Dial("tcp", net.JoinHostPort(addr, port), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		fmt.Printf("Connect error: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	bc := &bufioConn{Conn: conn, r: bufio.NewReader(conn)}

	// --- Auth ---
	challengeHex, _ := bc.r.ReadString('\n')
	challenge, _ := hex.DecodeString(strings.TrimSpace(challengeHex))
	privKey, err := loadRSAPrivateKey(keyPath)
	if err != nil {
		fmt.Printf("Key error: %v\n", err)
		os.Exit(1)
	}
	hash := sha256.Sum256(challenge)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
	bc.Conn.Write([]byte(hex.EncodeToString(sig) + "\n"))

	// --- Start async reader ---
	
	// --- Start async reader ---
	stopReader := make(chan struct{})
	readerDone := make(chan struct{})
	go asyncReader(bc, stopReader, readerDone)

	// --- Command loop ---
	scanner := bufio.NewScanner(os.Stdin)
	for {
		//fmt.Print("> ") // Print a prompt so you know when it's ready
		if !scanner.Scan() {
			break
		}
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}

		if text == "shell" {
			// 1. Tell the reader to stop
			close(stopReader)

			// 2. Force the blocking bc.Read() in asyncReader to unblock by setting an immediate deadline
			// This ensures the goroutine actually finishes.
			conn.SetReadDeadline(time.Now()) // Ensure you import "time" as importTime or similar

			// 3. Wait for reader to confirm it has stopped
			<-readerDone

			// 4. Clear the deadline so the connection can be used for SSH
			conn.SetReadDeadline(time.Time{})

			// 5. NOW send the command to the server
			bc.Conn.Write([]byte("shell\n"))

			// 6. Immediately start the SSH client
			startInteractiveShell(bc)
			fmt.Println("\n[*] Shell exited. Closing connection.")
			return
		}

		bc.Conn.Write([]byte(text + "\n"))
		// Give the reader a tiny bit of time to print the response before showing the prompt again
		time.Sleep(100 * time.Millisecond) 
	}
}