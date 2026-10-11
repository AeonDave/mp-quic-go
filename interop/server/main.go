package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"

	quic "github.com/AeonDave/mp-quic-go"
	"github.com/AeonDave/mp-quic-go/http3"
	"github.com/AeonDave/mp-quic-go/internal/qtls"
	"github.com/AeonDave/mp-quic-go/interop/http09"
	"github.com/AeonDave/mp-quic-go/interop/utils"
)

func main() {
	logFile, err := os.Create("/logs/log.txt")
	if err != nil {
		fmt.Printf("Could not create log file: %s\n", err.Error())
		os.Exit(1)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	keyLog, err := utils.GetSSLKeyLog()
	if err != nil {
		fmt.Printf("Could not create key log: %s\n", err.Error())
		os.Exit(1)
	}
	if keyLog != nil {
		defer keyLog.Close()
	}

	testcase := os.Getenv("TESTCASE")

	quicConf := &quic.Config{
		Allow0RTT: testcase == "zerortt",
		Tracer:    utils.NewQLOGConnectionTracer,
	}
	cert, err := tls.LoadX509KeyPair("/certs/cert.pem", "/certs/priv.key")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		KeyLogWriter: keyLog,
		NextProtos:   []string{http09.NextProto},
	}

	switch testcase {
	case "versionnegotiation", "handshake", "retry", "transfer", "resumption", "multiconnect", "zerortt", "ecn":
		// ECN is used by default, if the platform supports it.
		err = runHTTP09Server(tlsConf, quicConf, testcase == "retry")
	case "connectionmigration":
		err = runPreferredAddressServer(tlsConf, quicConf)
	case "v2":
		// prefer QUIC version 2, using compatible version negotiation (RFC 9368)
		quicConf.Versions = []quic.Version{quic.Version2, quic.Version1}
		err = runHTTP09Server(tlsConf, quicConf, false)
	case "chacha20":
		reset := qtls.SetCipherSuite(tls.TLS_CHACHA20_POLY1305_SHA256)
		defer reset()
		err = runHTTP09Server(tlsConf, quicConf, false)
	case "http3":
		tlsConf.NextProtos = []string{http3.NextProtoH3}
		err = runHTTP3Server(tlsConf, quicConf)
	default:
		fmt.Printf("unsupported test case: %s\n", testcase)
		os.Exit(127)
	}

	if err != nil {
		fmt.Printf("Error running server: %s\n", err.Error())
		os.Exit(1)
	}
}

func runHTTP09Server(tlsConf *tls.Config, quicConf *quic.Config, forceRetry bool) error {
	http.DefaultServeMux.Handle("/", http.FileServer(http.Dir("/www")))
	server := http09.Server{}

	udpAddr, err := net.ResolveUDPAddr("udp", ":443")
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	tr := &quic.Transport{
		Conn:                conn,
		VerifySourceAddress: func(net.Addr) bool { return forceRetry },
	}
	ln, err := tr.ListenEarly(tlsConf, quicConf)
	if err != nil {
		return err
	}
	return server.ServeListener(ln)
}

// The server's addresses in the network of the interop runner.
var (
	serverIPv4 = netip.MustParseAddrPort("193.167.100.100:443")
	serverIPv6 = netip.MustParseAddrPort("[fd00:cafe:cafe:100::100]:443")
)

// runPreferredAddressServer sends the server's preferred address (section 9.6 of RFC 9000).
// The server recognizes the packets sent to the preferred address by their local IP address, so the preferred
// address needs a different IP address than the one the client connected to: the server sends its address of the
// other address family as its preferred address.
func runPreferredAddressServer(tlsConf *tls.Config, quicConf *quic.Config) error {
	http.DefaultServeMux.Handle("/", http.FileServer(http.Dir("/www")))
	server := http09.Server{}

	// a dual-stack socket, receiving the packets sent to both addresses
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 443})
	if err != nil {
		return err
	}
	tr := &quic.Transport{
		Conn:             conn,
		PreferredAddress: &quic.PreferredAddress{IPv4: serverIPv4, IPv6: serverIPv6},
	}
	ln, err := tr.ListenEarly(tlsConf, quicConf)
	if err != nil {
		return err
	}
	return server.ServeListener(ln)
}

func runHTTP3Server(tlsConf *tls.Config, quicConf *quic.Config) error {
	server := http3.Server{
		Addr:       ":443",
		TLSConfig:  tlsConf,
		QUICConfig: quicConf,
	}
	http.DefaultServeMux.Handle("/", http.FileServer(http.Dir("/www")))
	return server.ListenAndServe()
}
