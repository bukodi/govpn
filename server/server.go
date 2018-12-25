package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/songgao/water"
	"golang.org/x/net/ipv4"
)

const (
	MTU = 1300
)

// The VPN server service
type Service struct {
	done          chan bool
	shutdownGroup *sync.WaitGroup
}

// Make a new Service.
func NewService() *Service {
	s := &Service{
		done:          make(chan bool),
		shutdownGroup: &sync.WaitGroup{},
	}
	s.shutdownGroup.Add(1)
	return s
}

// Defines the state for an authenticated client connection
type Client struct {
	ip       net.IP // client tunnel ip
	publicip net.IP // client public ip
	name     string // name of the authenticated client
	tunrx    chan []byte
}

// Creates a new client given a tls connection
// Validates and parses the client certificate values
// Tracks ~static state of a vpn client connection for data routing and address reaping
func NewClient(tlscon *tls.Conn) (*Client, error) {
	ipstring := tlscon.RemoteAddr().String()

	// Grab connection state from the completed connection
	state := tlscon.ConnectionState()
	log.Print(state)

	// If client cert not provided, send back HTTP 403 response
	// TODO: Also send same error if curve preference is not met?
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("no peer cert provided")
	}

	log.Println("Server: client public key is:")
	for _, v := range state.PeerCertificates {
		log.Print(x509.MarshalPKIXPublicKey(v.PublicKey))
	}

	// TODO: Verify certificate parameters as vpn client and extract client name
	name := "10702AG"

	return &Client{
		name:     name,
		publicip: net.ParseIP(ipstring[0:strings.Index(ipstring, ":")]),
		tunrx:    make(chan []byte),
	}, nil
}

// An "enum" of the transition state
type Transition int

// Of type Transition
const (
	_ Transition = iota
	Connect
	Disconnect
)

// Couples a transition state with the target client for
// client state channel delivery
type ClientState struct {
	transition Transition
	client     *Client
}

//====
// The outbound packet router

// Happy path packets inbound from the tun adapter on the rxchan channel, are parsed for their destination IP,
// then written to the client matching that address found in the routing table
// Internal routing table is kept in sync by reading events from the statechan channel
func routePackets(rxchan <-chan []byte, statechan <-chan ClientState) {
	// routing table state used only in this goroutine
	// routes are a mapping from client ip to a distinct client's tunrx channel
	routes := make(map[uint32]chan<- []byte)
	for {
		// serializing the state updates and state consumption in the same
		// goroutine gives lock-free operation.
		select {
		// State messages update the routes map state
		// We must not write to a client's channel after getting a disconnect for it
		// because its tunrx channel is closed after disconnect
		case state := <-statechan:
			ipint := ip2int(state.client.ip)
			if state.transition == Connect {
				log.Printf("serverrx: got client connect %s", state.client.name)
				// Add an item to the routing table
				routes[ipint] = state.client.tunrx
			} else {
				log.Printf("serverrx: got client disconnect %s", state.client.name)
				// Close the rx channel and remove the item from the routing table
				close(routes[ipint])
				delete(routes, ipint)
			}
			continue // Jump to top of loop for more possible state change messages
		default: // This default causes this case to immediately be skipped if statechan is empty
		}

		// Data routing consumes the routes map state when there are no client state messages waiting
		// This repetition allows us to sleep the goroutine while there are no messages to process
		// while being instantly responsive to new messages of either type
		// TODO: Refactor DRY
		select {
		case state := <-statechan:
			ipint := ip2int(state.client.ip)
			if state.transition == Connect {
				log.Printf("serverrx: got client connect %s", state.client.name)
				// Add an item to the routing table
				routes[ipint] = state.client.tunrx
			} else {
				log.Printf("serverrx: got client disconnect %s", state.client.name)
				// Close the rx channel and remove the item from the routing table
				close(routes[ipint])
				delete(routes, ipint)
			}
			continue // Jump to top of loop for more possible state change messages

		// Route packet to appropriate client tunrx channel
		// Channel is closed when tun adapter read loop exits (in main)
		case buf, ok := <-rxchan:
			if !ok {
				// If the receive channel is closed, exit the loop
				return
			}

			// Get destination IP from packet
			header, err := ipv4.ParseHeader(buf)
			if err != nil {
				// If we couldn't parse IP headers, drop the packet
				log.Printf("serverrx(dropped): could not parse packet header: %s", err)
				continue
			}

			clientip := header.Dst

			log.Printf("serverrx: got %d byte tun packet for %s", len(buf), clientip)

			// Lookup client in routing state
			if clientrx, ok := routes[ip2int(clientip)]; ok {
				// Send packet to client tunrx channel
				clientrx <- buf
			} else {
				//TODO: Send ICMP unreachable if no client found
			}
		}
	}
}

// Accept connections and spawn a goroutine to serve() each one.
// Stop listening if anything is received on the done channel.
// tuntx: channel to write packets from the client to the tun adapter
// tunrx: channel to read packets for the clients from the tun adapter
func (s *Service) Serve(listener net.Listener, tuntx chan<- []byte, tunrx <-chan []byte, servernet *net.IPNet) {
	// Close the listener when the server stops
	defer listener.Close()

	// Channel to send new tls connections to
	connchan := make(chan net.Conn)

	// Channel to send client connection state changes to
	clientstate := make(chan ClientState)

	// Goroutine to pump the accept loop into a handler channel
	// Exits when Accept fails on deferred listener.Close()
	go func(listener net.Listener, connhandler chan<- net.Conn) {
		// Exit the wait group when the accept pump exits
		defer s.shutdownGroup.Done()
		defer close(connhandler)

		for {
			// Block waiting for a client connection
			// ends on deferred listener.Close()
			conn, err := listener.Accept()
			if nil != err {
				// log the error and leave the accept loop
				log.Printf("serverac: accept failed: %s", err)
				return
			}

			// Send the connection for handling
			connhandler <- conn
		}
	}(listener, connchan)

	// Route packets bound for clients as they come in the tunrx channel
	// Uses clientstate channel to keep internal routing table up to date
	// Exits when tunrx channel is closed
	go routePackets(tunrx, clientstate)

	// Implements a channel that delivers unused IP addresses when read
	// And returns IPs to the pool when a client disconnects
	// Set the buffer size to the host count - 3 (network address, server address, and broadcast address)
	netmasklen, networksize := servernet.Mask.Size()
	hostmask := uint32(2 ^ (networksize - netmasklen)) // Calculate host count
	netblock := make(chan net.IP, hostmask-3)
	// No exit state needed
	go func(blockchan chan<- net.IP, statechan <-chan ClientState, hostcount uint32, netip uint32) {
		log.Printf("server: netblock: adding %d host addresses", hostmask-3)

		// Pump the netblock channel full of available addresses
		for i := uint32(2); i < hostmask; i++ {
			blockchan <- int2ip(netip + i)
		}

		for {
			// When a client disconnects, add its IP back to the block
			state := <-statechan
			if state.transition == Disconnect {
				log.Printf("server: netblock: recovered ip %s, %d unallocated ips remain", state.client.ip, len(blockchan))
				blockchan <- state.client.ip
			}
		}
	}(netblock, clientstate, hostmask, ip2int(servernet.IP))

	// Forever select on the done channel, and the client connection handler channel
	for {
		select {
		case <-s.done:
			log.Println("server: got done signal", listener.Addr())
			return

		case conn := <-connchan:
			log.Println("serverac:", conn.RemoteAddr(), "connected")
			// Add a client to the waitgroup, and handle it in a goroutine
			s.shutdownGroup.Add(1)
			go s.serve(conn, tuntx, clientstate, netblock)
		}
	}
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

// Stop the service by closing the done channel
// Block until the service and all clients have stopped
func (s *Service) Stop() {
	close(s.done)
	s.shutdownGroup.Wait()
}

// Client handler function for :443
func (s *Service) serve(conn net.Conn, tuntx chan<- []byte, clientstate chan<- ClientState, netblock <-chan net.IP) {
	// Close connection when handler exits
	defer conn.Close()

	tlscon, ok := conn.(*tls.Conn)
	if !ok {
		log.Print("server: conn(term): not a TLS connection")
		return
	}

	// Progress to the tls handshake
	err := tlscon.Handshake()
	if err != nil {
		log.Printf("server: conn(term): TLS handshake failed: %s", err)
		return
	} else {
		log.Print("server: conn: TLS handshake completed")
	}

	// Validate this connection as a valid new client
	client, err := NewClient(tlscon)
	if err != nil {
		log.Printf("server: conn(term): error validating client: %s", err)
		//TODO: Send HTTP 403 response
		//tlscon.Write()
		return
	}

	// A channel to signal a read or write error to/from the client
	rwerr := make(chan bool, 2)
	// A channel for flowing packets read from the client
	clientrx := make(chan []byte)

	// Producer that pumps the read-side of the client connection into the clientrx channel
	// Exits on failing read after deferred conn.Close()
	go func(conn net.Conn, rxchan chan<- []byte, wait *sync.WaitGroup) {
		// Leave the wait group when the read pump exits
		defer wait.Done()

		// Forever read
		buf := make([]byte, MTU)
		for {
			log.Print("server: connrx: waiting")
			// This ends when the connection is closed locally or remotely
			n, err := conn.Read(buf)
			if nil != err {
				// Read failed, pumpexit the handler
				log.Printf("server: connrx(term): error while reading: %s", err)
				rwerr <- true
				return
			}

			// Send the packet to the rx channel
			rxchan <- buf[:n]
		}
	}(tlscon, clientrx, s.shutdownGroup)

	// Pipe that pumps packets from the client tunrx channel into the client connection
	// Exits on failing write after deferred conn.Close() or after deferred close(client.tunrx)
	go func(txchan <-chan []byte, conn net.Conn) {
		// Pump the transmit channel until it is closed
		for buf := range txchan {
			log.Print("server: conntx: sending packet to client")

			//TODO: Any processing on packet from tun adapter

			n, err := conn.Write(buf)
			log.Printf("server: conntx: wrote %d bytes", n)
			if err != nil {
				log.Printf("server: conntx(term): error while writing: %s", err)
				// If the write errors, signal the rwerr channel
				rwerr <- true
				return
			}
		}
	}(client.tunrx, tlscon)

	// Application-Layer Handshake
	// Read first packet from client with a timeout
	select {
	case infobuf := <-clientrx:
		log.Print(infobuf)
		// TODO: Decode client info struct from json in the first packet, delimited with newline

		// Now that we have client info, send client settings json

		// Allocate client IP address
		client.ip = <-netblock

		// TODO: Create client settings to send

		settingsbuf := make([]byte, MTU)
		// TODO: Encode client settings struct to newline delimited json and send as first packet
		n := 3
		client.tunrx <- settingsbuf[n:]

	case <-time.After(2 * time.Minute): // TODO: Define in config
		log.Print("server: conn(term): timed out waiting for client info")
		return
	}

	// Defer client cleanup to when leaving the handler
	defer func() {
		// Disconnect client state change
		clientstate <- ClientState{
			transition: Disconnect,
			client:     client,
		}
	}()

	// Send client connect state change
	// This causes the client.tunrx channel to be mounted by the tun router and it will now receieve traffic
	clientstate <- ClientState{
		transition: Connect,
		client:     client,
	}

	// Forever select on the done channel, the rwerr channel, and the clientrx read producer channel
	// until a read or write operation fails or the done signal is received
	for {
		select {
		// Disconnect if we're told to shut down shop
		case <-s.done:
			log.Println("server: conn(term): got done signal", tlscon.RemoteAddr())
			return

		// Disconnect if we receive a message on the rwerr channel
		case <-rwerr:
			return

		// Consumes packets from the clientrx channel then sends them into the tuntx channel
		case buf := <-clientrx:
			log.Print("server: conn: received packet from client")
			if len(buf) == 0 {
				log.Print("server: conn(term): remote client closed connection")
				return
			}

			// Grab the packet ip header
			header, _ := ipv4.ParseHeader(buf)

			// Drop any packets with a source address different than the one allocated to the client
			if !header.Src.Equal(client.ip) {
				continue
			}

			// TODO: Process packet to work on tun adapter?

			// Push the received packet to the tun tx channel
			tuntx <- buf
		}
	}
}

func main() {
	log.SetFlags(log.Lshortfile)

	// Load the server's PKI keypair
	cer, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatalf("server: failed to load server PKI material: %s", err)
	}

	// Load client CA cert chain
	certpool := x509.NewCertPool()
	pem, err := ioutil.ReadFile("certs/ca.pem")
	if err != nil {
		log.Fatalf("server: failed to read client certificate authority: %v", err)
	}
	if !certpool.AppendCertsFromPEM(pem) {
		log.Fatalf("server: failed to parse client certificate authority")
	}

	// Create tls config with PKI material
	// TODO: Can this handle a client CRL?
	config := &tls.Config{
		Certificates:             []tls.Certificate{cer},
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP384, tls.CurveP256}, // Last two for browser compat?
		PreferServerCipherSuites: true,
		CipherSuites:             []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ClientAuth:               tls.VerifyClientCertIfGiven,
		ClientCAs:                certpool,
	}
	config.BuildNameToCertificate()

	// TODO: Get from config
	serverip, servernet, _ := net.ParseCIDR("192.168.0.1/21")

	// Create tun interface
	iface, err := water.NewTUN("tun_govpn")
	if nil != err {
		log.Fatalln("server: unable to allocate TUN interface:", err)
	}

	// TODO: Set tun adapter address
	log.Printf("server: setting TUN adapter address to %s", serverip)

	// Channels to recieve and send packet buffers to/from the tun interface
	tunrx := make(chan []byte)
	tuntx := make(chan []byte)

	// Close the tun tx channel when we exit main
	defer func() {
		log.Print("server: tuntx: deferred closing tuntx channel")
		close(tuntx)
	}()

	// Producer that reads packets off of the tun interface and pushes them on the tunrx channel
	// TODO: Read ends when tun interface is closed/stopped?
	go func(tun *water.Interface, rxchan chan<- []byte) {
		// Close channel when read loop ends to signal end of traffic
		// Used by client data router to know when to stop reading
		defer close(rxchan)

		tunbuf := make([]byte, MTU)
		for {
			n, err := tun.Read(tunbuf)
			log.Printf("server: tunrx: read %d bytes", n)
			if err != nil {
				// Stop pumping if read returns error
				log.Printf("server: tunrx(term): error reading %s", err)
				return
			}
			rxchan <- tunbuf[n:]
		}
	}(iface, tunrx)

	// Consumer that reads packets off of the tuntx channel and writes them to the tun interface
	// TODO: Write ends when tun interface is closed/stopped?
	go func(txchan <-chan []byte, tun *water.Interface) {
		// Read the channel until it is closed
		for tunbuf := range txchan {
			// Write the buffer to the tun interface
			n, err := tun.Write(tunbuf)
			log.Printf("server: tuntx: wrote %d bytes", n)
			if err != nil {
				log.Printf("server: tuntx(term): error writing %s", err)
				return
			}
		}
		log.Print("server: tuntx(term): txchan closed")
	}(tuntx, iface)

	// Listen on tcp:443
	listener, err := tls.Listen("tcp", ":443", config)
	if err != nil {
		log.Fatalf("server: listen failed: %s", err)
	}

	// Create an instance of the VPN server service
	// Hand it the active listener to accept connections in a goroutine
	service := NewService()
	go service.Serve(listener, tuntx, tunrx, servernet)

	// Handle SIGINT and SIGTERM
	sigs := make(chan os.Signal)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Block waiting for a signal
	log.Println(<-sigs)

	// Stop the service and disconnect clients gracefully
	service.Stop()
}
