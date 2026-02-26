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

	"golang.org/x/crypto/ssh"
)

func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}

	// ParseRawPrivateKey returns the underlying crypto.PrivateKey (e.g., *rsa.PrivateKey, *ecdsa.PrivateKey)
	rawKey, err := ssh.ParseRawPrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("parse raw private key: %w", err)
	}

	// Type assert the raw key to *rsa.PrivateKey
	rsaPriv, ok := rawKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA (it is %T)", rawKey)
	}

	return rsaPriv, nil
}

func main() {
	addrPtr := flag.String("addr", "", "Server address (Required)")
	portPtr := flag.String("port", "9090", "Server port")
	keyPath := flag.String("key", "id_rsa", "Path to private key")
	flag.Parse()

	if *addrPtr == "" {
		fmt.Println("Error: -addr is required")
		flag.Usage()
		os.Exit(1)
	}

	serverEndpoint := net.JoinHostPort(*addrPtr, *portPtr)

	// TLS config
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", serverEndpoint, conf)
	if err != nil {
		fmt.Printf("Failed to connect to %s: %v\n", serverEndpoint, err)
		os.Exit(1)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// === Receive challenge ===
	challengeHex, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Failed to read challenge: %v\n", err)
		os.Exit(1)
	}

	challenge, err := hex.DecodeString(strings.TrimSpace(challengeHex))
	if err != nil {
		fmt.Printf("Invalid challenge hex: %v\n", err)
		os.Exit(1)
	}

	// === Load private key ===
	privKey, err := loadRSAPrivateKey(*keyPath)
	if err != nil {
		fmt.Printf("Failed to load private key: %v\n", err)
		os.Exit(1)
	}

	// === Sign challenge ===
	hash := sha256.Sum256(challenge)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
	if err != nil {
		fmt.Printf("Signing failed: %v\n", err)
		os.Exit(1)
	}

	// === Send signature ===
	_, err = conn.Write([]byte(hex.EncodeToString(signature) + "\n"))
	if err != nil {
		fmt.Printf("Failed to send signature: %v\n", err)
		os.Exit(1)
	}

	// === Reader goroutine ===
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			fmt.Print(string(buf[:n]))
		}
	}()

	// === Interactive stdin ===
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		_, _ = conn.Write([]byte(scanner.Text() + "\n"))
	}
}