package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/textproto"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
)

func service(tlscon *tls.Conn, tuntxstack filterstack, bufpool *sync.Pool, done chan bool, wait *sync.WaitGroup) {
	defer tlscon.Close()

	if err := tlscon.Handshake(); nil != err {
		log.Printf("client(term): tls handshake failed: %s", err)
		close(done)
		return
	} else {
		log.Print("client: tls handshake succeeded")
	}

	// Settings we get back from the server
	var settings ClientSettings

	// Application layer handshake
	{
		// Create buffered reader for connection
		bufrx := bufio.NewReader(tlscon)

		// Encode client settings struct to newline delimited json and send as first packet
		infobuf, err := json.Marshal(ClientInfo{
			Time:    time.Now().UTC().Format(time.RFC3339),
			Version: "0.1.0",
		})
		if err != nil {
			log.Print("(term): error encoding client info packet")
			close(done)
			return
		}

		// Write http response and headers
		tlscon.Write([]byte("POST / HTTP/1.0\n"))
		tlscon.Write([]byte("Content-Type: application/json\n"))
		tlscon.Write([]byte(fmt.Sprintf("Content-Length: %d\n", len(infobuf))))
		tlscon.Write([]byte("\n"))
		tlscon.Write(infobuf)

		// Process the response
		tp := textproto.NewReader(bufrx)
		request, err := tp.ReadLine()
		if err != nil {
			log.Printf("(term): error reading request line: %s", err)
			close(done)
			return
		}
		log.Print(string(request))

		// Get headers
		headers, err := tp.ReadMIMEHeader()
		if err != nil {
			log.Printf("(term): error reading request headers: %s", err)
			close(done)
			return
		}
		log.Print("got headers")
		log.Print(headers)

		// Get body
		bodylen, err := strconv.ParseInt(headers["Content-Length"][0], 10, 64)
		if err != nil {
			log.Print("(term): error parsing content-length header")
			close(done)
			return
		}

		// TODO: Protect for content too large

		body := make([]byte, bodylen)
		n, err := bufrx.Read(body)
		if err != nil {
			log.Print("(term): error reading request body")
			close(done)
			return
		}
		log.Print("got body")
		log.Print(string(body))

		// Decode client settings struct from json in the respnse
		if err := json.Unmarshal(body[:n], &settings); err != nil {
			log.Print("(term): error decoding client settings")
			close(done)
			return
		}

		// TODO: Set tun adapter IP address and state

		// Set tun adapter settings and turn it up
		// TODO: Make more bulletproof/config
		nlhand, _ := netlink.NewHandle()
		tunlink, _ := netlink.LinkByName("tun_govpnc")
		ipnet, _ := netlink.ParseAddr(settings.IP + "/21")
		netlink.AddrAdd(tunlink, ipnet)
		nlhand.LinkSetMTU(tunlink, MTU)
		nlhand.LinkSetUp(tunlink)

		// Disable ipv6 on tun interface
		err = os.WriteFile("/proc/sys/net/ipv6/conf/tun_govpn/disable_ipv6", []byte("1"), 0644)

		// Ensure the buffered reader doesn't hold further data
		if bufrx.Buffered() != 0 {
			panic("Didn't read all buffered bytes")
		}
	}

	// A channel to signal a write error to the server
	readerr := make(chan bool)

	// Channel for packets coming from the server
	// Exits when the read fails
	wait.Add(1)
	go connrx(tlscon, tuntxstack, readerr, wait, bufpool)

	// Signal ready for tun traffic
	done <- true

	// Block waiting for a signal, or an error
	for {
		select {
		case <-done:
			log.Println("client(term): done closed")
			return

		case <-readerr:
			log.Println("client(term): error reading from server")
			close(done)
			return

		}
	}
}
