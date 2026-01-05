package quic

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

// TestMultipath_E2E_BasicConnection tests basic multipath connection establishment
func TestMultipath_E2E_BasicConnection(t *testing.T) {
	// Setup server
	serverAddr := "127.0.0.1:0"
	listener, err := net.ListenPacket("udp", serverAddr)
	require.NoError(t, err)
	defer listener.Close()

	serverTransport := &Transport{Conn: listener}

	tlsConf := generateTLSConfig()
	serverConfig := &Config{
		MultipathController: createTestMultipathController(protocol.PerspectiveServer),
	}

	earlyListener, err := serverTransport.ListenEarly(tlsConf, serverConfig)
	require.NoError(t, err)
	defer earlyListener.Close()

	// Start server handler
	var wg sync.WaitGroup
	serverErr := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := earlyListener.Accept(ctx)
		if err != nil {
			serverErr <- err
			return
		}

		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			serverErr <- err
			return
		}
		defer stream.Close()

		// Echo back
		buf := make([]byte, 1024)
		n, err := stream.Read(buf)
		if err != nil && err != io.EOF {
			serverErr <- err
			return
		}
		if _, err := stream.Write(buf[:n]); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	// Setup client
	clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer clientConn.Close()

	clientTransport := &Transport{Conn: clientConn}
	clientTLS := generateTLSConfigWithServerName("localhost")
	clientConfig := &Config{
		MultipathController: createTestMultipathController(protocol.PerspectiveClient),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := clientTransport.Dial(ctx, listener.LocalAddr(), clientTLS, clientConfig)
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	// Open stream and send data
	stream, err := conn.OpenStreamSync(ctx)
	require.NoError(t, err)

	testData := []byte("Hello Multipath QUIC!")
	_, err = stream.Write(testData)
	require.NoError(t, err)

	// Read echo
	buf := make([]byte, 1024)
	n, err := stream.Read(buf)
	if err != nil && err != io.EOF {
		require.NoError(t, err)
	}
	require.Equal(t, testData, buf[:n])

	stream.Close()
	wg.Wait()
	require.NoError(t, <-serverErr)
}

// TestMultipath_E2E_PathSwitching tests path switching during connection
func TestMultipath_E2E_PathSwitching(t *testing.T) {
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer serverConn.Close()

	serverController := &pathSwitchController{}
	serverTransport := &Transport{Conn: serverConn}
	serverTLS := generateTLSConfig()
	serverConfig := &Config{
		MultipathController: serverController,
	}

	listener, err := serverTransport.Listen(serverTLS, serverConfig)
	require.NoError(t, err)
	defer listener.Close()

	clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer clientConn.Close()

	altConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer altConn.Close()

	require.NotEqual(t, clientConn.LocalAddr().String(), altConn.LocalAddr().String())

	clientController := &pathSwitchController{}
	clientTransport := &Transport{Conn: clientConn}
	clientTLS := generateTLSConfigWithServerName("localhost")
	clientConfig := &Config{
		MultipathController: clientController,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			serverErr <- err
			return
		}
		serverController.setConn(conn)
		defer conn.CloseWithError(0, "")

		for i := 0; i < 2; i++ {
			stream, err := conn.AcceptStream(ctx)
			if err != nil {
				serverErr <- err
				return
			}
			buf := make([]byte, 1024)
			n, err := stream.Read(buf)
			if err != nil && err != io.EOF {
				serverErr <- err
				return
			}
			if _, err := stream.Write(buf[:n]); err != nil {
				serverErr <- err
				return
			}
			_ = stream.Close()
		}
		serverErr <- nil
	}()

	conn, err := clientTransport.Dial(ctx, serverConn.LocalAddr(), clientTLS, clientConfig)
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	clientController.setConn(conn)

	sendAndReceive := func(payload []byte) {
		stream, err := conn.OpenStreamSync(ctx)
		require.NoError(t, err)

		_, err = stream.Write(payload)
		require.NoError(t, err)

		buf := make([]byte, len(payload))
		n, err := stream.Read(buf)
		if err != nil && err != io.EOF {
			require.NoError(t, err)
		}
		require.Equal(t, payload, buf[:n])
		_ = stream.Close()
	}

	sendAndReceive([]byte("before switch"))

	altTransport := &Transport{Conn: altConn}
	path, err := conn.AddPath(altTransport)
	require.NoError(t, err)

	probeCtx, probeCancel := context.WithTimeout(ctx, 5*time.Second)
	defer probeCancel()
	require.NoError(t, path.Probe(probeCtx))

	require.NoError(t, path.Switch())
	require.Eventually(t, func() bool {
		return conn.LocalAddr().String() == altConn.LocalAddr().String()
	}, 2*time.Second, 10*time.Millisecond)

	sendAndReceive([]byte("after switch"))

	require.NoError(t, <-serverErr)
}

// TestMultipath_E2E_SchedulerComparison tests different scheduling policies
func TestMultipath_E2E_SchedulerComparison(t *testing.T) {
	policies := []SchedulingPolicy{
		SchedulingPolicyRoundRobin,
		SchedulingPolicyLowLatency,
		SchedulingPolicyMinRTT,
	}

	for _, policy := range policies {
		t.Run(fmt.Sprintf("Policy_%d", policy), func(t *testing.T) {
			testSchedulerPolicy(t, policy)
		})
	}
}

func testSchedulerPolicy(t *testing.T, policy SchedulingPolicy) {
	// Setup server
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	serverTransport := &Transport{Conn: listener}
	tlsConf := generateTLSConfig()

	pathManager := NewMultipathPathManager(protocol.PerspectiveServer)
	pathManager.EnableMultipath()
	scheduler := NewMultipathScheduler(pathManager, policy)

	serverConfig := &Config{
		MultipathController: scheduler,
	}

	earlyListener, err := serverTransport.ListenEarly(tlsConf, serverConfig)
	require.NoError(t, err)
	defer earlyListener.Close()

	// Server handler
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := earlyListener.Accept(ctx)
		if err != nil {
			return
		}
		defer conn.CloseWithError(0, "")

		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}

		// Receive and count
		buf := make([]byte, 1024)
		total := 0
		for {
			n, err := stream.Read(buf)
			total += n
			if err != nil {
				break
			}
		}
	}()

	// Client
	clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer clientConn.Close()

	clientTransport := &Transport{Conn: clientConn}
	clientTLS := generateTLSConfigWithServerName("localhost")

	clientPathManager := NewMultipathPathManager(protocol.PerspectiveClient)
	clientPathManager.EnableMultipath()
	clientScheduler := NewMultipathScheduler(clientPathManager, policy)

	clientConfig := &Config{
		MultipathController: clientScheduler,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := clientTransport.Dial(ctx, listener.LocalAddr(), clientTLS, clientConfig)
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	// Send data
	stream, err := conn.OpenStreamSync(ctx)
	require.NoError(t, err)

	data := make([]byte, 10000)
	for i := range data {
		data[i] = byte(i % 256)
	}

	_, err = stream.Write(data)
	require.NoError(t, err)
	stream.Close()

	wg.Wait()
}

// TestMultipath_E2E_ConcurrentStreams tests multiple streams over multipath
func TestMultipath_E2E_ConcurrentStreams(t *testing.T) {
	// Setup server
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	serverTransport := &Transport{Conn: listener}
	tlsConf := generateTLSConfig()
	serverConfig := &Config{
		MultipathController: createTestMultipathController(protocol.PerspectiveServer),
	}

	earlyListener, err := serverTransport.ListenEarly(tlsConf, serverConfig)
	require.NoError(t, err)
	defer earlyListener.Close()

	// Server handler for multiple streams
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := earlyListener.Accept(ctx)
		if err != nil {
			return
		}
		defer conn.CloseWithError(0, "")

		var streamWg sync.WaitGroup
		for i := 0; i < 5; i++ {
			stream, err := conn.AcceptStream(ctx)
			if err != nil {
				return
			}

			streamWg.Add(1)
			go func(s *Stream) {
				defer streamWg.Done()
				defer s.Close()
				io.Copy(s, s) // Echo
			}(stream)
		}
		streamWg.Wait()
	}()

	// Client
	clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer clientConn.Close()

	clientTransport := &Transport{Conn: clientConn}
	clientTLS := generateTLSConfigWithServerName("localhost")
	clientConfig := &Config{
		MultipathController: createTestMultipathController(protocol.PerspectiveClient),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := clientTransport.Dial(ctx, listener.LocalAddr(), clientTLS, clientConfig)
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	// Open 5 concurrent streams
	var streamWg sync.WaitGroup
	for i := 0; i < 5; i++ {
		streamWg.Add(1)
		go func(id int) {
			defer streamWg.Done()

			stream, err := conn.OpenStreamSync(ctx)
			if err != nil {
				t.Errorf("Stream %d: failed to open: %v", id, err)
				return
			}
			defer stream.Close()

			testData := []byte(fmt.Sprintf("Stream %d data", id))
			_, err = stream.Write(testData)
			if err != nil {
				t.Errorf("Stream %d: failed to write: %v", id, err)
				return
			}

			buf := make([]byte, 1024)
			n, err := stream.Read(buf)
			if err != nil && err != io.EOF {
				t.Errorf("Stream %d: failed to read: %v", id, err)
				return
			}

			if string(buf[:n]) != string(testData) {
				t.Errorf("Stream %d: data mismatch", id)
			}
		}(i)
	}

	streamWg.Wait()
	wg.Wait()
}

// TestMultipath_E2E_DuplicationPolicy tests packet duplication
func TestMultipath_E2E_DuplicationPolicy(t *testing.T) {
	duplicationPolicy := NewMultipathDuplicationPolicy()
	duplicationPolicy.Enable()
	duplicationPolicy.SetDuplicatePathCount(2)

	// Setup with duplication
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	serverTransport := &Transport{Conn: listener}
	tlsConf := generateTLSConfig()

	controller := createTestMultipathController(protocol.PerspectiveServer)
	serverConfig := &Config{
		MultipathController: controller,
	}

	earlyListener, err := serverTransport.ListenEarly(tlsConf, serverConfig)
	require.NoError(t, err)
	defer earlyListener.Close()

	// Simple connection test with duplication enabled
	go func() {
		conn, err := earlyListener.Accept(context.Background())
		if err != nil {
			return
		}
		defer conn.CloseWithError(0, "")

		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		io.Copy(stream, stream)
	}()

	// Client
	clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer clientConn.Close()

	clientTransport := &Transport{Conn: clientConn}
	clientConfig := &Config{
		MultipathController:        createTestMultipathController(protocol.PerspectiveClient),
		MultipathDuplicationPolicy: duplicationPolicy,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientTLS := generateTLSConfigWithServerName("localhost")
	conn, err := clientTransport.Dial(ctx, listener.LocalAddr(), clientTLS, clientConfig)
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	stream, err := conn.OpenStreamSync(ctx)
	require.NoError(t, err)

	testData := []byte("Duplicated data test")
	_, err = stream.Write(testData)
	require.NoError(t, err)

	buf := make([]byte, 1024)
	n, err := stream.Read(buf)
	if err != nil && err != io.EOF {
		require.NoError(t, err)
	}
	require.Equal(t, testData, buf[:n])
}

// Helper functions

func createTestMultipathController(perspective protocol.Perspective) MultipathController {
	pathManager := NewMultipathPathManager(perspective)
	pathManager.EnableMultipath()
	scheduler := NewMultipathScheduler(pathManager, SchedulingPolicyRoundRobin)
	scheduler.EnableMultipath()
	return scheduler
}

func generateTLSConfig() *tls.Config {
	cert := generateTestCertificate()
	return &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"multipath-quic-test"},
		Certificates:       []tls.Certificate{cert},
	}
}

func generateTLSConfigWithServerName(serverName string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
		NextProtos:         []string{"multipath-quic-test"},
	}
}

func generateTestCertificate() tls.Certificate {
	// Generate CA
	caTempl := &x509.Certificate{
		SerialNumber:          big.NewInt(2024),
		Subject:               pkix.Name{CommonName: "MP-QUIC Test CA"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caBytes, _ := x509.CreateCertificate(rand.Reader, caTempl, caTempl, caPub, caPriv)
	ca, _ := x509.ParseCertificate(caBytes)

	// Generate leaf certificate
	leafTempl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafPub, leafPriv, _ := ed25519.GenerateKey(rand.Reader)
	leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTempl, ca, leafPub, caPriv)

	return tls.Certificate{
		Certificate: [][]byte{leafBytes},
		PrivateKey:  leafPriv,
	}
}

type pathSwitchController struct {
	mu   sync.RWMutex
	conn *Conn
}

func (c *pathSwitchController) setConn(conn *Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conn = conn
}

func (c *pathSwitchController) SelectPath(PathSelectionContext) (PathInfo, bool) {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()
	if conn == nil {
		return PathInfo{}, false
	}
	return PathInfo{
		ID:         0,
		LocalAddr:  conn.LocalAddr(),
		RemoteAddr: conn.RemoteAddr(),
	}, true
}

func (c *pathSwitchController) PathIDForPacket(net.Addr, net.Addr) (PathID, bool) {
	return 0, true
}
