// This example uses IETF Multipath QUIC (draft-ietf-quic-multipath-21).
//
// It runs a server and a client in the same process. The server configures a multipath controller for every
// connection it accepts. The client connects from one UDP socket, opens a second path from a second UDP socket,
// and uploads data on a stream. The data is sent on both paths.
//
// Run it with:
//
//	go run ./example/multipath
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"slices"
	"time"

	quic "github.com/AeonDave/mp-quic-go"
)

const alpn = "quic-multipath-example"

func main() {
	size := flag.Int("size", 8<<20, "number of bytes the client uploads")
	flag.Parse()

	if err := run(*size); err != nil {
		log.Fatal(err)
	}
}

func run(size int) error {
	ln, err := quic.ListenAddr("127.0.0.1:0", generateTLSConfig(), &quic.Config{
		// Configuring a multipath controller enables IETF Multipath QUIC.
		// A controller keeps the state of a single connection, so the server creates one for every connection.
		MultipathControllerFactory: func() quic.MultipathController {
			return quic.NewDefaultMultipathController(quic.NewRoundRobinScheduler())
		},
	})
	if err != nil {
		return err
	}
	defer ln.Close()
	go serve(ln)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return runClient(ctx, ln.Addr(), size)
}

// serve accepts connections until the listener is closed.
func serve(ln *quic.Listener) {
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		go serveConn(conn)
	}
}

// serveConn reads the data sent by the client on every stream, and responds with the number of bytes received.
func serveConn(conn *quic.Conn) {
	for {
		str, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go func() {
			defer str.Close()
			n, err := io.Copy(io.Discard, str)
			if err != nil {
				return
			}
			_, _ = str.Write(binary.BigEndian.AppendUint64(nil, uint64(n)))
		}()
	}
}

func runClient(ctx context.Context, serverAddr net.Addr, size int) error {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	tr := &quic.Transport{Conn: udpConn}
	defer tr.Close()

	controller := quic.NewDefaultMultipathController(quic.NewRoundRobinScheduler())
	conn, err := tr.Dial(ctx, serverAddr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{alpn}}, &quic.Config{
		// Up to 2 paths can be used at the same time.
		MaxPaths:            2,
		MultipathController: controller,
	})
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "")
	// Multipath is only used if both endpoints support it.
	// Otherwise, the connection is a standard single-path QUIC connection.
	if !conn.ConnectionState().SupportsMultipath {
		return errors.New("the server doesn't support multipath")
	}

	// Open a second path, sending from a second UDP socket.
	// The path can be used once it was validated.
	udpConn2, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	tr2 := &quic.Transport{Conn: udpConn2}
	// The Transport needs to stay open until the connection is closed:
	// closing it destroys the connection, without sending a CONNECTION_CLOSE frame to the server.
	defer func() {
		conn.CloseWithError(0, "")
		tr2.Close()
	}()
	path, err := conn.AddPath(tr2)
	if err != nil {
		return err
	}
	if err := path.Probe(ctx); err != nil {
		return fmt.Errorf("opening the second path failed: %w", err)
	}
	pathID, _ := path.ID()
	log.Printf("client: opened path %d from %s", pathID, udpConn2.LocalAddr())

	// Data is sent on all paths that can be used.
	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	start := time.Now()
	if _, err := str.Write(make([]byte, size)); err != nil {
		return err
	}
	if err := str.Close(); err != nil {
		return err
	}
	resp, err := io.ReadAll(str)
	if err != nil {
		return err
	}
	if len(resp) != 8 || binary.BigEndian.Uint64(resp) != uint64(size) {
		return fmt.Errorf("unexpected response: %x", resp)
	}
	log.Printf("client: uploaded %d bytes in %s", size, time.Since(start).Round(time.Millisecond))

	for _, p := range conn.Paths() {
		log.Printf("client: path %d: %s -> %s, %s", p.ID, p.LocalAddr, p.RemoteAddr, p.State)
	}
	// The controller collects statistics for the paths that it selects packets for.
	stats := controller.GetStatistics()
	ids := make([]quic.PathID, 0, len(stats))
	for id := range stats {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		s := stats[id]
		log.Printf("client: path %d: %d packets (%d bytes) sent, %d lost, RTT %s", id, s.PacketsSent, s.BytesSent, s.PacketsLost, s.SmoothedRTT)
	}
	return nil
}

// generateTLSConfig returns a bare-bones TLS config for the server.
func generateTLSConfig() *tls.Config {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  priv,
		}},
		NextProtos: []string{alpn},
	}
}
