package self_test

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/AeonDave/mp-quic-go"
	"github.com/AeonDave/mp-quic-go/http3"
	quicproxy "github.com/AeonDave/mp-quic-go/integrationtests/tools/proxy"
	"github.com/AeonDave/mp-quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestHTTP0RTT(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/0rtt", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strconv.FormatBool(!r.TLS.HandshakeComplete))
	})
	port := startHTTPServer(t, mux)

	var num0RTTPackets atomic.Uint32
	proxy := quicproxy.Proxy{
		Conn:       newUDPConnLocalhost(t),
		ServerAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port},
		DelayPacket: func(_ quicproxy.Direction, _, _ net.Addr, data []byte) time.Duration {
			if containsPacketType(data, protocol.PacketType0RTT) {
				num0RTTPackets.Add(1)
			}
			return scaleDuration(25 * time.Millisecond)
		},
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	tlsConf := getTLSClientConfigWithoutServerName()
	puts := make(chan string, 10)
	tlsConf.ClientSessionCache = newClientSessionCache(tls.NewLRUClientSessionCache(10), nil, puts)
	tr := &http3.Transport{
		TLSClientConfig:    tlsConf,
		QUICConfig:         getQuicConfig(&quic.Config{MaxIdleTimeout: 10 * time.Second}),
		DisableCompression: true,
	}
	defer tr.Close()
	addDialCallback(t, tr)

	proxyPort := proxy.LocalAddr().(*net.UDPAddr).Port
	req, err := http.NewRequest(http3.MethodGet0RTT, fmt.Sprintf("https://localhost:%d/0rtt", proxyPort), nil)
	require.NoError(t, err)
	rsp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, 200, rsp.StatusCode)
	data, err := io.ReadAll(rsp.Body)
	require.NoError(t, err)
	require.Equal(t, "false", string(data))
	require.Zero(t, num0RTTPackets.Load())

	select {
	case <-puts:
	case <-time.After(time.Second):
		t.Fatal("did not receive session ticket")
	}

	tr2 := &http3.Transport{
		TLSClientConfig:    tr.TLSClientConfig,
		QUICConfig:         tr.QUICConfig,
		DisableCompression: true,
	}
	defer tr2.Close()
	addDialCallback(t, tr2)
	rsp, err = tr2.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, 200, rsp.StatusCode)
	data, err = io.ReadAll(rsp.Body)
	require.NoError(t, err)
	require.Equal(t, "true", string(data))
	require.NotZero(t, num0RTTPackets.Load())
}

// A request sent in 0-RTT that the server rejects with a 425 (Too Early) response is retried after the handshake
// (section 4.2 of RFC 8470).
func TestHTTP0RTTTooEarly(t *testing.T) {
	var early, late atomic.Uint32
	mux := http.NewServeMux()
	mux.HandleFunc("/0rtt", func(w http.ResponseWriter, r *http.Request) {
		if !r.TLS.HandshakeComplete {
			early.Add(1)
			w.WriteHeader(http.StatusTooEarly)
			return
		}
		late.Add(1)
		io.WriteString(w, "foobar")
	})
	port := startHTTPServer(t, mux)

	tlsConf := getTLSClientConfigWithoutServerName()
	puts := make(chan string, 10)
	tlsConf.ClientSessionCache = newClientSessionCache(tls.NewLRUClientSessionCache(10), nil, puts)
	newTransport := func() *http3.Transport {
		tr := &http3.Transport{
			TLSClientConfig:    tlsConf,
			QUICConfig:         getQuicConfig(&quic.Config{MaxIdleTimeout: 10 * time.Second}),
			DisableCompression: true,
		}
		addDialCallback(t, tr)
		return tr
	}

	req, err := http.NewRequest(http3.MethodGet0RTT, fmt.Sprintf("https://localhost:%d/0rtt", port), nil)
	require.NoError(t, err)
	tr := newTransport()
	defer tr.Close()
	rsp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rsp.StatusCode)
	rsp.Body.Close()
	require.Zero(t, early.Load())
	select {
	case <-puts:
	case <-time.After(time.Second):
		t.Fatal("did not receive session ticket")
	}

	// the second request is sent in 0-RTT, rejected, and retried after the handshake
	tr2 := newTransport()
	defer tr2.Close()
	rsp, err = tr2.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rsp.StatusCode)
	data, err := io.ReadAll(rsp.Body)
	require.NoError(t, err)
	require.Equal(t, "foobar", string(data))
	require.Equal(t, uint32(1), early.Load())
	require.Equal(t, uint32(2), late.Load())
}

// The server is restarted with different settings.
// It uses the same session ticket keys, and a ZeroRTTReplayCache shared with the previous server.
func TestHTTP0RTTWithChangedServerSettings(t *testing.T) {
	const originalMaxHeaderBytes = 1024

	for _, tc := range []struct {
		name              string
		newMaxHeaderBytes int
		expect0RTT        bool
	}{
		{name: "increased", newMaxHeaderBytes: 1025, expect0RTT: true},
		{name: "decreased", newMaxHeaderBytes: 1023, expect0RTT: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/0rtt", func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, strconv.FormatBool(!r.TLS.HandshakeComplete))
			})
			serverTLSConf := getTLSConfig()
			replayCache := quic.NewZeroRTTReplayCache(time.Hour, 100)
			port := startHTTPServer(t, mux, func(s *http3.Server) {
				s.TLSConfig = serverTLSConf
				s.QUICConfig.ZeroRTTReplayCache = replayCache
				s.MaxHeaderBytes = originalMaxHeaderBytes
			})

			puts := make(chan string, 1)
			clientTLSConf := getTLSClientConfigWithoutServerName()
			clientTLSConf.ClientSessionCache = newClientSessionCache(tls.NewLRUClientSessionCache(1), nil, puts)
			doRequest := func(port int) (string, error) {
				cl := newHTTP3Client(t, func(tr *http3.Transport) { tr.TLSClientConfig = clientTLSConf })
				req, err := http.NewRequest(http3.MethodGet0RTT, fmt.Sprintf("https://localhost:%d/0rtt", port), nil)
				require.NoError(t, err)
				rsp, err := cl.Do(req)
				if err != nil {
					return "", err
				}
				defer rsp.Body.Close()
				body, err := io.ReadAll(rsp.Body)
				return string(body), err
			}

			body, err := doRequest(port)
			require.NoError(t, err)
			require.Equal(t, "false", body)
			select {
			case <-puts:
			case <-time.After(time.Second):
				t.Fatal("did not receive session ticket")
			}

			port = startHTTPServer(t, mux, func(s *http3.Server) {
				s.TLSConfig = serverTLSConf
				s.QUICConfig.ZeroRTTReplayCache = replayCache
				s.MaxHeaderBytes = tc.newMaxHeaderBytes
			})
			proxy := quicproxy.Proxy{
				Conn:       newUDPConnLocalhost(t),
				ServerAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port},
				DelayPacket: func(quicproxy.Direction, net.Addr, net.Addr, []byte) time.Duration {
					return scaleDuration(25 * time.Millisecond)
				},
			}
			require.NoError(t, proxy.Start())
			defer proxy.Close()

			proxyPort := proxy.LocalAddr().(*net.UDPAddr).Port
			body, err = doRequest(proxyPort)
			if tc.expect0RTT {
				require.NoError(t, err)
				require.Equal(t, "true", body)
			} else {
				require.ErrorIs(t, err, quic.Err0RTTRejected)
			}
		})
	}
}
