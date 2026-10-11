package fips

import (
	"bufio"
	"bytes"
	"context"
	"crypto/fips140"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	quic "github.com/AeonDave/mp-quic-go"
	"github.com/AeonDave/mp-quic-go/integrationtests/tools"
	"github.com/AeonDave/mp-quic-go/internal/handshake"
	"github.com/AeonDave/mp-quic-go/qlog"
	"github.com/AeonDave/mp-quic-go/qlogwriter"
	"github.com/AeonDave/mp-quic-go/testutils/events"

	"github.com/stretchr/testify/require"
)

const (
	helperRoleEnv  = "QUIC_GO_FIPS_TRANSFER_ROLE"
	helperAddrEnv  = "QUIC_GO_FIPS_TRANSFER_ADDR"
	helperDirEnv   = "QUIC_GO_FIPS_TRANSFER_DIR"
	helperRetryEnv = "QUIC_GO_FIPS_TRANSFER_RETRY"
	// If set, the endpoints use IETF Multipath QUIC, and the client opens a second path.
	helperMultipathEnv = "QUIC_GO_FIPS_TRANSFER_MULTIPATH"

	keyUpdatePackets = 32
	minKeyUpdates    = 3
	// With IETF Multipath QUIC, key updates are spaced by 3 times the largest PTO of all paths
	// (section 2.5 of draft-ietf-quic-multipath-21), so the transfer only takes long enough for one key update.
	// The installation of the 1-RTT keys is counted as well.
	minMultipathKeyUpdates = 2
	transferSize           = 512 * 1024
)

type clientResult struct {
	FIPSEnabled bool   `json:"fips_enabled"` // used as a sanity check
	Checksum    string `json:"checksum"`
	KeyUpdates  int    `json:"key_updates"`
	// with IETF Multipath QUIC: the number of 1-RTT packets with STREAM frames received on every path
	PathDataPackets map[string]int `json:"path_data_packets,omitempty"`
	// with IETF Multipath QUIC: the number of these packets that used the key phase bit 1
	PathKeyPhaseOnePackets map[string]int `json:"path_key_phase_one_packets,omitempty"`
}

func TestFIPS140Transfers(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "fips.test")
	out, err := exec.Command("go", "test", "-c", "-o", exe, ".").CombinedOutput()
	require.NoErrorf(t, err, "building test binary failed:\n%s", out)

	dir := t.TempDir()
	writeCerts(t, dir)
	transferData := make([]byte, transferSize)
	_, err = rand.Read(transferData)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "data.bin"), transferData, 0o600))

	for _, tc := range []struct {
		serverFIPS bool
		clientFIPS bool
		retry      bool
		multipath  bool
	}{
		{},
		{retry: true},
		{serverFIPS: true},
		{serverFIPS: true, retry: true},
		{clientFIPS: true},
		{clientFIPS: true, retry: true},
		{serverFIPS: true, clientFIPS: true},
		{serverFIPS: true, clientFIPS: true, retry: true},
		{multipath: true},
		{serverFIPS: true, multipath: true},
		{clientFIPS: true, multipath: true},
		{serverFIPS: true, clientFIPS: true, multipath: true},
	} {
		name := fmt.Sprintf("server: %t, client: %t, retry: %t", tc.serverFIPS, tc.clientFIPS, tc.retry)
		if tc.multipath {
			name += ", multipath"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			server := exec.CommandContext(ctx, exe)
			server.Env = append(os.Environ(),
				helperRoleEnv+"=server",
				helperDirEnv+"="+dir,
				helperRetryEnv+"="+fmt.Sprint(tc.retry),
				helperMultipathEnv+"="+fmt.Sprint(tc.multipath),
				"GODEBUG="+fipsGODEBUG(tc.serverFIPS),
			)
			serverStdout, err := server.StdoutPipe()
			require.NoError(t, err)
			var serverStderr bytes.Buffer
			server.Stderr = &serverStderr
			require.NoError(t, server.Start())
			defer server.Process.Kill()

			addrChan := make(chan string, 1)
			go func() {
				line, _ := bufio.NewReader(serverStdout).ReadString('\n')
				addrChan <- strings.TrimSpace(line)
			}()
			var addr string
			select {
			case addr = <-addrChan:
				require.NotEmptyf(t, addr, "server didn't print its address:\n%s", serverStderr.Bytes())
			case <-time.After(5 * time.Second):
				require.FailNowf(t, "server didn't start listening", "%s", serverStderr.Bytes())
			}

			client := exec.CommandContext(ctx, exe)
			client.Env = append(os.Environ(),
				helperRoleEnv+"=client",
				helperAddrEnv+"="+addr,
				helperDirEnv+"="+dir,
				helperMultipathEnv+"="+fmt.Sprint(tc.multipath),
				"GODEBUG="+fipsGODEBUG(tc.clientFIPS),
			)
			var clientStdout, clientStderr bytes.Buffer
			client.Stdout = &clientStdout
			client.Stderr = &clientStderr
			clientErr := client.Run()
			if clientErr != nil {
				_ = server.Process.Kill()
			}
			serverErr := server.Wait()

			require.NoErrorf(t, clientErr, "client stderr:\n%s", clientStderr.Bytes())
			require.NoErrorf(t, serverErr, "server stderr:\n%s", serverStderr.Bytes())

			var result clientResult
			require.NoErrorf(t, json.Unmarshal(clientStdout.Bytes(), &result), "client stdout:\n%s", clientStdout.Bytes())
			t.Logf("key_updates: %d", result.KeyUpdates)
			require.Equalf(t, tc.clientFIPS, result.FIPSEnabled, "client fips140.Enabled() = %v, want %v", result.FIPSEnabled, tc.clientFIPS)
			gotChecksum, err := hex.DecodeString(result.Checksum)
			require.NoErrorf(t, err, "checksum hex decode: %q", result.Checksum)
			expectedChecksum := sha256.Sum256(transferData)
			require.Equal(t, expectedChecksum[:], gotChecksum, "checksum mismatch")
			minUpdates := minKeyUpdates
			if tc.multipath {
				minUpdates = minMultipathKeyUpdates
			}
			require.GreaterOrEqualf(t, result.KeyUpdates, minUpdates, "client observed %d key updates, want at least %d", result.KeyUpdates, minUpdates)
			if tc.multipath {
				// the data was sent on both paths, every path carrying at least 10% of the packets
				t.Logf("data packets per path: %v", result.PathDataPackets)
				require.Len(t, result.PathDataPackets, 2)
				var total int
				for _, n := range result.PathDataPackets {
					total += n
				}
				for _, path := range []string{"0", "1"} {
					require.GreaterOrEqualf(t, result.PathDataPackets[path]*10, total, "path %s: %d of %d data packets", path, result.PathDataPackets[path], total)
					// both key phases were used on every path
					require.NotZerof(t, result.PathKeyPhaseOnePackets[path], "path %s: no packets with key phase 1", path)
					require.Lessf(t, result.PathKeyPhaseOnePackets[path], result.PathDataPackets[path], "path %s: no packets with key phase 0", path)
				}
			} else {
				require.Empty(t, result.PathDataPackets)
			}
		})
	}
}

func fipsGODEBUG(enabled bool) string {
	if enabled {
		return "fips140=only"
	}
	return "fips140=off"
}

func writeCerts(t *testing.T, dir string) {
	t.Helper()

	ca, caKey, err := tools.GenerateCA()
	require.NoError(t, err)
	leaf, leafKey, err := tools.GenerateLeafCert(ca, caKey)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "cert.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}),
		0o600,
	))
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "key.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		0o600,
	))
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "ca.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}),
		0o600,
	))
}

func TestMain(m *testing.M) {
	role := os.Getenv(helperRoleEnv)
	if role == "" {
		os.Exit(m.Run())
	}

	handshake.FirstKeyUpdateInterval = keyUpdatePackets
	handshake.SetKeyUpdateInterval(keyUpdatePackets)

	dir := os.Getenv(helperDirEnv)

	var runErr error
	switch role {
	case "server":
		runErr = runServer(dir)
	case "client":
		runErr = runClient(dir, os.Getenv(helperAddrEnv))
	default:
		runErr = fmt.Errorf("unknown role: %q", role)
	}
	if runErr != nil {
		panic(runErr)
	}
	os.Exit(0)
}

func multipathEnabled() bool { return os.Getenv(helperMultipathEnv) == "true" }

// quicConfig returns the config of an endpoint.
// With IETF Multipath QUIC, the packets are sent on the paths in turn.
func quicConfig(perspective string) *quic.Config {
	if !multipathEnabled() {
		return nil
	}
	newController := func() quic.MultipathController {
		return quic.NewDefaultMultipathController(quic.NewRoundRobinScheduler())
	}
	if perspective == "client" {
		return &quic.Config{MultipathController: newController()}
	}
	return &quic.Config{MultipathControllerFactory: newController}
}

func runServer(dir string) error {
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(dir, "data.bin"))
	if err != nil {
		return err
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return err
	}
	tr := &quic.Transport{
		Conn:                udpConn,
		VerifySourceAddress: func(net.Addr) bool { return os.Getenv(helperRetryEnv) == "true" },
	}
	defer tr.Close()
	ln, err := tr.Listen(&tls.Config{
		Certificates:     []tls.Certificate{cert},
		NextProtos:       []string{tools.ALPN},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.CurveP256},
	}, quicConfig("server"))
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(os.Stdout, ln.Addr().String()); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := ln.Accept(ctx)
	if err != nil {
		return err
	}
	if multipathEnabled() {
		if !conn.ConnectionState().SupportsMultipath {
			return errors.New("multipath not negotiated")
		}
		// the client opens a stream once it opened the second path
		str, err := conn.AcceptUniStream(ctx)
		if err != nil {
			return err
		}
		if _, err := io.ReadAll(str); err != nil {
			return err
		}
	}

	str, err := conn.OpenUniStream()
	if err != nil {
		return err
	}
	if _, err := str.Write(data); err != nil {
		return err
	}
	if err := str.Close(); err != nil {
		return err
	}

	select {
	case <-conn.Context().Done():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func runClient(dir, addr string) error {
	caPEM, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		return err
	}
	root := x509.NewCertPool()
	if !root.AppendCertsFromPEM(caPEM) {
		return errors.New("failed to parse test CA")
	}

	recorder := &events.Recorder{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conf := quicConfig("client")
	if conf == nil {
		conf = &quic.Config{}
	}
	conf.Tracer = func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
		return &events.Trace{Recorder: recorder}
	}
	conn, err := quic.DialAddr(ctx, addr, &tls.Config{
		ServerName:       "localhost",
		RootCAs:          root,
		NextProtos:       []string{tools.ALPN},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.CurveP256},
	}, conf)
	if err != nil {
		return err
	}
	if multipathEnabled() {
		if err := openSecondPath(ctx, conn); err != nil {
			return err
		}
	}

	str, err := conn.AcceptUniStream(ctx)
	if err != nil {
		return err
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, str); err != nil {
		return err
	}
	if err := conn.CloseWithError(0, ""); err != nil {
		return err
	}

	var keyUpdates int
	var pathDataPackets, pathKeyPhaseOnePackets map[string]int
	for _, ev := range recorder.Events() {
		switch ev := ev.(type) {
		case qlog.KeyUpdated:
			if ev.KeyType == qlog.KeyTypeClient1RTT {
				keyUpdates++
			}
		case qlog.PacketReceived:
			if !ev.Header.HasPathID {
				continue
			}
			for _, f := range ev.Frames {
				if _, ok := f.Frame.(*qlog.StreamFrame); ok {
					if pathDataPackets == nil {
						pathDataPackets = make(map[string]int)
						pathKeyPhaseOnePackets = make(map[string]int)
					}
					pathDataPackets[fmt.Sprint(ev.Header.PathID)]++
					if ev.Header.KeyPhaseBit == qlog.KeyPhaseOne {
						pathKeyPhaseOnePackets[fmt.Sprint(ev.Header.PathID)]++
					}
					break
				}
			}
		}
	}
	return json.NewEncoder(os.Stdout).Encode(clientResult{
		FIPSEnabled:            fips140.Enabled(),
		Checksum:               hex.EncodeToString(hasher.Sum(nil)),
		KeyUpdates:             keyUpdates,
		PathDataPackets:        pathDataPackets,
		PathKeyPhaseOnePackets: pathKeyPhaseOnePackets,
	})
}

// openSecondPath opens a path of IETF Multipath QUIC from a second UDP socket,
// and then asks the server to send the data by opening a stream.
func openSecondPath(ctx context.Context, conn *quic.Conn) error {
	if !conn.ConnectionState().SupportsMultipath {
		return errors.New("multipath not negotiated")
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return err
	}
	tr := &quic.Transport{Conn: udpConn}
	// The Transport is closed after the connection: closing it destroys the connection.
	context.AfterFunc(conn.Context(), func() { tr.Close() })
	path, err := conn.AddPath(tr)
	if err != nil {
		return err
	}
	if err := path.Probe(ctx); err != nil {
		return fmt.Errorf("probing the second path failed: %w", err)
	}
	str, err := conn.OpenUniStream()
	if err != nil {
		return err
	}
	return str.Close()
}
