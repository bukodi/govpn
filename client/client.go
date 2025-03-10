package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/joshperry/govpn"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/songgao/water"
)

const (
	MTU = 1300
)

// Info that the client sends in its first packet after connection
// encoded as json
type ClientInfo struct {
	Time    string `json:"time"`
	Version string `json:"version"`
}

// Settings to send json encoded as the first packet to the client after reading
// its first packet which contains ClientInfo
type ClientSettings struct {
	Time    string `json:"time"`
	Version string `json:"version"`
	IP      string `json:"ip"`
}

func main() {
	govpn.LoadConfig()

	err := StartClient()
	if err != nil {
		panic(err)
	}
}

func StartClient() error {

	// Load the server's PKI keypair
	// TODO: Load from config
	cer, err := tls.LoadX509KeyPair(
		govpn.ConfigString("tls/cert"),
		govpn.ConfigString("tls/key"),
	)
	if err != nil {
		return fmt.Errorf("failed to load server PKI material: %w", err)
	}

	// Load server CA cert chain
	certpool := x509.NewCertPool()
	pem, err := os.ReadFile(govpn.ConfigString("tls/ca"))
	if err != nil {
		return fmt.Errorf("failed to read server certificate authority: %w", err)
	}
	if !certpool.AppendCertsFromPEM(pem) {
		return fmt.Errorf("failed to parse server certificate authority")
	}

	// Create tls config with PKI material
	// TODO: Load from config
	tlsconfig := &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{cer},
		MinVersion:         tls.VersionTLS12,
		CurvePreferences:   []tls.CurveID{tls.X25519}, // Last two for browser compat?
		CipherSuites:       []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		RootCAs:            certpool,
	}
	tlsconfig.BuildNameToCertificate()

	// Create tun interface
	tunconfig := water.Config{DeviceType: water.TUN, PlatformSpecificParams: water.PlatformSpecificParams{MultiQueue: true}}
	tunconfig.Name = govpn.ConfigString("tun/name")
	iface, err := water.New(tunconfig)
	if nil != err {
		return fmt.Errorf("unable to allocate TUN interface: %w", err)
	}

	// Waitgroup for waiting on main services to stop
	mainwait := &sync.WaitGroup{}

	// Create pool of messages
	bufpool := sync.Pool{
		New: func() interface{} {
			return &message{}
		},
	}

	// Connect to server
	tlscon, err := tls.Dial("tcp", govpn.ConfigString("server"), tlsconfig)
	if nil != err {
		return fmt.Errorf("connect failed: %w", err)
	}

	// Filter stack for sending packets to the tun iface
	tuntxstack := filterstack{tuntx(iface)}

	done := make(chan bool)
	go service(tlscon, tuntxstack, &bufpool, done, mainwait)

	// Wait until the handshake goes well
	_, ok := <-done

	// If done was closed then there was an error negotiating the client
	if !ok {
		return fmt.Errorf("client handshake failed")
	}
	// Put the conntx filter at the end of the tunrx stack
	tunrxstack := filterstack{conntx(tlscon)}

	go tunrx(iface, tunrxstack, mainwait, &bufpool)

	// Handle SIGINT and SIGTERM
	sigs := make(chan os.Signal)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigs:
		pkgLogger.Info(fmt.Sprintf("got %s signal", sig))
		close(done)
	case <-done:
	}

	pkgLogger.Info("waiting for shutdown")
	mainwait.Wait()
	return nil
}
