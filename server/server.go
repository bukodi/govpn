package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/joshperry/govpn"
	"log"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"

	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

const (
	MTU = 1400
)

/**
* See service.go for main vpn service loop guts
* See clienthandler.go for vpn service client handler cogs/gears
* See client.go for client data structs/defines
* See various files for the goroutine functions the sprout up
 */

func main() {
	err := start()
	if err != nil {
		panic(err)
	}
}

func start() error {

	// Find path to config file before loading config
	// Get config path from the env

	govpn.LoadConfig()
	// Load the server's PKI keypair

	cer, err := tls.LoadX509KeyPair(
		govpn.ConfigString("tls/cert"),
		govpn.ConfigString("tls/key"),
	)
	if err != nil {
		return fmt.Errorf("server: failed to load server PKI material: %w", err)
	}

	// Load client CA cert chain
	certpool := x509.NewCertPool()
	pem, err := os.ReadFile(govpn.ConfigString("tls/ca"))
	if err != nil {
		return fmt.Errorf("server: failed to read client certificate authority: %w", err)
	}
	if !certpool.AppendCertsFromPEM(pem) {
		return fmt.Errorf("server: failed to parse client certificate authority")
	}

	// Create tls config with PKI material
	// TODO: Can this handle a client CRL?
	// TODO: Load from config
	tlsconfig := &tls.Config{
		Certificates:             []tls.Certificate{cer},
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP384, tls.CurveP256}, // Last two for browser compat?
		PreferServerCipherSuites: true,
		CipherSuites:             []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		ClientAuth:               tls.VerifyClientCertIfGiven,
		ClientCAs:                certpool,
	}
	tlsconfig.BuildNameToCertificate()

	// Parse the server address block
	servernet, _ := netlink.ParseAddr(govpn.ConfigString("secnet/netblock"))
	servernet.IP = int2ip(ip2int(servernet.IP.Mask(servernet.Mask)) + 1) // Set IP to first in the network

	// Create tun interface
	tunconfig := water.Config{DeviceType: water.TUN, PlatformSpecificParams: water.PlatformSpecificParams{MultiQueue: true}}
	tunconfig.Name = govpn.ConfigString("tun/name")
	iface, err := water.New(tunconfig)
	if nil != err {
		log.Fatalln("server: unable to allocate TUN interface:", err)
	}

	// Set tun adapter settings and turn it up
	log.Printf("server: setting TUN adapter address to %s", servernet.IP)
	nlhand, _ := netlink.NewHandle()
	tunlink, _ := netlink.LinkByName(tunconfig.Name)
	netlink.AddrAdd(tunlink, servernet)
	nlhand.LinkSetMTU(tunlink, MTU)
	nlhand.LinkSetUp(tunlink)

	// Disable ipv6 on tun interface
	err = os.WriteFile("/proc/sys/net/ipv6/conf/tun_govpn/disable_ipv6", []byte("1"), 0644)

	// Listen for clients
	port, _ := strconv.Atoi(govpn.ConfigString("listen/port"))
	listener, err := tls.Listen(
		"tcp",
		fmt.Sprintf(
			"%s:%d",
			govpn.ConfigString("listen/address"),
			port,
		),
		tlsconfig,
	)
	if err != nil {
		log.Fatalf("server: listen failed: %s", err)
	}
	log.Printf("server: listening on %s", listener.Addr().String())

	// Create pool of messages
	bufpool := sync.Pool{
		New: func() interface{} {
			return &message{}
		},
	}

	// Create an instance of the VPN server service
	// Run it 5 times with the active listener to accept connections, tun channels for tun comms, and server network info
	service := NewService()
	go service.Serve(listener, iface, &bufpool, servernet.IPNet)

	// Handle SIGINT and SIGTERM
	sigs := make(chan os.Signal)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Block waiting for a signal
	select {
	case <-sigs:
		// Stop the service and disconnect clients gracefully
		log.Print("server(term): got shutdown signal")
		service.Stop()
	case <-service.done:
		log.Print("server: saw done, waiting for shutdown")
		service.shutdownGroup.Wait()
	}

	// Close the tun interface
	log.Print("server: closing tun interface")
	iface.Close()

	log.Print("server(perm): goodbye")
	return nil
}
