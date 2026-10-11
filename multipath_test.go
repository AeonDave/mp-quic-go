package quic

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/handshake"
	"github.com/AeonDave/mp-quic-go/internal/mocks"
	mockackhandler "github.com/AeonDave/mp-quic-go/internal/mocks/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/internal/wire"
	"github.com/AeonDave/mp-quic-go/qlog"
	"github.com/AeonDave/mp-quic-go/qlogwriter"
	"github.com/AeonDave/mp-quic-go/quicvarint"
	"github.com/AeonDave/mp-quic-go/testutils/events"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func multipathTestTracer(r *events.Recorder) func(context.Context, bool, ConnectionID) qlogwriter.Trace {
	return func(context.Context, bool, ConnectionID) qlogwriter.Trace {
		return &events.Trace{Recorder: r}
	}
}

func multipathTestConfig(withController bool, perspective protocol.Perspective, r *events.Recorder) *Config {
	conf := &Config{Tracer: multipathTestTracer(r)}
	if withController {
		conf.MultipathControllerFactory = func() MultipathController { return createTestMultipathController() }
	}
	return conf
}

// A multipathTestConnPair is a client and a server connection, running on a simulated network.
// It must be used inside a synctest bubble.
type multipathTestConnPair struct {
	client, server             *Conn
	clientEvents, serverEvents *events.Recorder
	clientTr, serverTr         *Transport
	ln                         *EarlyListener
}

func newMultipathTestConnPair(t *testing.T, clientWithController, serverWithController bool) *multipathTestConnPair {
	t.Helper()
	var clientEvents, serverEvents events.Recorder
	return dialMultipathTestConnPair(
		t,
		&Transport{},
		multipathTestConfig(clientWithController, protocol.PerspectiveClient, &clientEvents),
		multipathTestConfig(serverWithController, protocol.PerspectiveServer, &serverEvents),
		&clientEvents,
		&serverEvents,
	)
}

func dialMultipathTestConnPair(
	t *testing.T,
	clientTr *Transport,
	clientConf, serverConf *Config,
	clientEvents, serverEvents *events.Recorder,
) *multipathTestConnPair {
	t.Helper()
	clientPacketConn, serverPacketConn, closeNetwork := newSimnetLink(t, 10*time.Millisecond)
	clientTr.Conn = clientPacketConn
	serverTr := &Transport{Conn: serverPacketConn}
	ln, err := serverTr.ListenEarly(generateTLSConfig(), serverConf)
	require.NoError(t, err)

	p := &multipathTestConnPair{
		clientEvents: clientEvents,
		serverEvents: serverEvents,
		clientTr:     clientTr,
		serverTr:     serverTr,
		ln:           ln,
	}
	t.Cleanup(func() {
		if p.client != nil {
			p.client.CloseWithError(0, "")
		}
		ln.Close()
		clientTr.Close()
		serverTr.Close()
		closeNetwork()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := clientTr.Dial(ctx, serverPacketConn.LocalAddr(), generateTLSConfigWithServerName("localhost"), clientConf)
	require.NoError(t, err)
	p.client = client
	server, err := ln.Accept(ctx)
	require.NoError(t, err)
	p.server = server
	select {
	case <-server.HandshakeComplete():
	case <-ctx.Done():
		t.Fatal("timeout waiting for the handshake to complete")
	}
	return p
}

// transfer sends data from the client to the server and back.
func (p *multipathTestConnPair) transfer(t *testing.T, data []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverErr := make(chan error, 1)
	go func() {
		str, err := p.server.AcceptStream(ctx)
		if err != nil {
			serverErr <- err
			return
		}
		received, err := io.ReadAll(str)
		if err != nil {
			serverErr <- err
			return
		}
		if _, err := str.Write(received); err != nil {
			serverErr <- err
			return
		}
		serverErr <- str.Close()
	}()

	str, err := p.client.OpenStreamSync(ctx)
	require.NoError(t, err)
	_, err = str.Write(data)
	require.NoError(t, err)
	require.NoError(t, str.Close())
	echoed, err := io.ReadAll(str)
	require.NoError(t, err)
	require.True(t, bytes.Equal(data, echoed), "echoed data doesn't match")
	require.NoError(t, <-serverErr)
}

// close closes the client connection, and waits for the server connection to be closed.
// The transports and the network are closed when the test ends.
func (p *multipathTestConnPair) close(t *testing.T) {
	t.Helper()
	require.NoError(t, p.client.CloseWithError(0, ""))
	<-p.server.Context().Done()
}

// localTransportParameters returns the parameters_set event for the transport parameters sent by an endpoint.
func localTransportParameters(t *testing.T, r *events.Recorder) qlog.ParametersSet {
	t.Helper()
	for _, ev := range r.Events(qlog.ParametersSet{}) {
		if ps := ev.(qlog.ParametersSet); ps.Initiator == qlog.InitiatorLocal {
			return ps
		}
	}
	t.Fatal("no transport parameters sent")
	return qlog.ParametersSet{}
}

// sent1RTTFrames returns the frames sent in 1-RTT packets, and the number of these packets that carried a path ID.
func sent1RTTFrames(r *events.Recorder) (frames []any, numWithPathID int) {
	for _, ev := range r.Events(qlog.PacketSent{}) {
		ps := ev.(qlog.PacketSent)
		if ps.Header.PacketType != qlog.PacketType1RTT {
			continue
		}
		if ps.Header.HasPathID {
			numWithPathID++
		}
		for _, f := range ps.Frames {
			frames = append(frames, f.Frame)
		}
	}
	return frames, numWithPathID
}

type sentFrameCounts struct {
	ack, pathAck, newConnID, pathNewConnID, otherMultipath int
	pathNewConnIDPaths                                     map[protocol.PathID]struct{}
}

func countSentFrames(frames []any) sentFrameCounts {
	counts := sentFrameCounts{pathNewConnIDPaths: make(map[protocol.PathID]struct{})}
	for _, f := range frames {
		switch f := f.(type) {
		case *qlog.AckFrame:
			if f.HasPathID {
				counts.pathAck++
			} else {
				counts.ack++
			}
		case *qlog.NewConnectionIDFrame:
			counts.newConnID++
		case *qlog.PathNewConnectionIDFrame:
			counts.pathNewConnID++
			counts.pathNewConnIDPaths[f.PathID] = struct{}{}
		case *qlog.PathAbandonFrame, *qlog.PathStatusFrame, *qlog.PathRetireConnectionIDFrame,
			*qlog.MaxPathIDFrame, *qlog.PathsBlockedFrame, *qlog.PathCIDsBlockedFrame:
			counts.otherMultipath++
		}
	}
	return counts
}

func TestMultipathNegotiation(t *testing.T) {
	for _, tc := range []struct {
		name            string
		clientMultipath bool
		serverMultipath bool
		expectIETF      bool
	}{
		{name: "both", clientMultipath: true, serverMultipath: true, expectIETF: true},
		{name: "client only", clientMultipath: true},
		{name: "server only", serverMultipath: true},
		{name: "neither"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p := newMultipathTestConnPair(t, tc.clientMultipath, tc.serverMultipath)
				p.transfer(t, bytes.Repeat([]byte("foobar"), 5000))
				p.close(t)

				// The connections are closed, so their state can be accessed now.
				for _, side := range []struct {
					name        string
					conn        *Conn
					events      *events.Recorder
					multipath   bool
					peerHasCtrl bool
				}{
					{name: "client", conn: p.client, events: p.clientEvents, multipath: tc.clientMultipath},
					{name: "server", conn: p.server, events: p.serverEvents, multipath: tc.serverMultipath},
				} {
					require.Equal(t, side.multipath, side.conn.advertisedMultipath, side.name)
					params := localTransportParameters(t, side.events)
					if side.multipath {
						require.NotNil(t, params.InitialMaxPathID, side.name)
						require.Equal(t, protocol.PathID(2), *params.InitialMaxPathID, side.name)
					} else {
						require.Nil(t, params.InitialMaxPathID, side.name)
					}
					require.Equal(t, tc.expectIETF, side.conn.mp != nil, side.name)
					require.Equal(t, tc.expectIETF, side.conn.ConnectionState().SupportsMultipath, side.name)

					frames, numWithPathID := sent1RTTFrames(side.events)
					counts := countSentFrames(frames)
					if tc.expectIETF {
						require.True(t, side.conn.mp.active, side.name)
						// 1-RTT packets are acknowledged using PATH_ACK frames.
						require.Zero(t, counts.ack, side.name)
						require.NotZero(t, counts.pathAck, side.name)
						require.NotZero(t, counts.pathNewConnID, side.name)
						require.NotZero(t, numWithPathID, side.name)
					} else {
						require.NotZero(t, counts.ack, side.name)
						require.Zero(t, counts.pathAck, side.name)
						require.NotZero(t, counts.newConnID, side.name)
						require.Zero(t, counts.pathNewConnID, side.name)
						require.Zero(t, counts.otherMultipath, side.name)
						require.Zero(t, numWithPathID, side.name)
					}
				}
			})
		})
	}
}

// Versions of this module before IETF Multipath QUIC was implemented (v0.1.x and v0.2.0) negotiated their own
// multipath protocol, using a transport parameter from the private use range.
// A peer that only advertises this transport parameter doesn't support IETF Multipath QUIC,
// so the connection uses a single path (section 2 of draft-ietf-quic-multipath-21).
func TestMultipathPeerWithRemovedMultipathParameter(t *testing.T) {
	for _, pers := range []protocol.Perspective{protocol.PerspectiveClient, protocol.PerspectiveServer} {
		t.Run(pers.String(), func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			cs := mocks.NewMockCryptoSetup(mockCtrl)
			config := &Config{
				MultipathControllerFactory: func() MultipathController { return testMultipathController{} },
				DisablePathMTUDiscovery:    true,
			}
			var tc *testConnection
			if pers == protocol.PerspectiveClient {
				tc = newClientTestConnection(t, mockCtrl, config, false, connectionOptCryptoSetup(cs))
			} else {
				tc = newServerTestConnection(t, mockCtrl, config, false, connectionOptCryptoSetup(cs))
				tc.connRunner.EXPECT().Add(gomock.Any(), gomock.Any()).AnyTimes()
				// The test connection doesn't know the client's source connection ID,
				// so it didn't advertise the extension.
				tc.conn.handshakeDestConnID = protocol.ParseConnectionID([]byte{1, 2, 3, 4})
				tc.conn.maybeAdvertiseMultipath(&wire.TransportParameters{}, tc.srcConnID, tc.conn.handshakeDestConnID)
			}
			c := tc.conn
			require.True(t, c.advertisedMultipath)

			peerParams := &wire.TransportParameters{
				InitialSourceConnectionID: c.handshakeDestConnID,
				ActiveConnectionIDLimit:   4,
				MaxDatagramFrameSize:      protocol.InvalidByteCount,
			}
			if pers == protocol.PerspectiveClient {
				peerParams.OriginalDestinationConnectionID = tc.destConnID
				peerParams.StatelessResetToken = &protocol.StatelessResetToken{1}
			}
			b := peerParams.Marshal(pers.Opposite())
			b = quicvarint.Append(b, 133405871403) // the transport parameter of v0.2.0
			b = quicvarint.Append(b, 0)
			var params wire.TransportParameters
			require.NoError(t, params.Unmarshal(b, pers.Opposite()))
			require.False(t, params.HasInitialMaxPathID)

			// The crypto setup's EnableMultipath must not be called.
			require.NoError(t, c.handleTransportParameters(&params))
			require.Nil(t, c.mp)
			require.False(t, c.supportsMultipath())

			// We advertised the extension, so the frame parser knows its frames.
			// The peer didn't, so it must not send them (section 2 of draft-ietf-quic-multipath-21).
			for _, frame := range ietfMultipathTestFrames() {
				data, err := frame.Append(nil, protocol.Version1)
				require.NoError(t, err)
				frameType, _, err := quicvarint.Parse(data)
				require.NoError(t, err)
				_, _, _, err = c.handleFrames(data, protocol.ConnectionID{}, protocol.Encryption1RTT, nil, monotime.Now())
				require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation, FrameType: frameType})
			}
		})
	}
}

// IETF Multipath QUIC requires non-zero-length connection IDs.
// If the client uses zero-length connection IDs, neither endpoint advertises the extension.
func TestMultipathNegotiationZeroLengthConnectionID(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var clientEvents, serverEvents events.Recorder
		p := dialMultipathTestConnPair(
			t,
			&Transport{ConnectionIDGenerator: &protocol.DefaultConnectionIDGenerator{ConnLen: 0}},
			multipathTestConfig(true, protocol.PerspectiveClient, &clientEvents),
			multipathTestConfig(true, protocol.PerspectiveServer, &serverEvents),
			&clientEvents,
			&serverEvents,
		)
		p.transfer(t, []byte("foobar"))
		p.close(t)

		clientParams := localTransportParameters(t, &clientEvents)
		require.Zero(t, clientParams.InitialSourceConnectionID.Len())
		require.Nil(t, clientParams.InitialMaxPathID)
		require.Nil(t, localTransportParameters(t, &serverEvents).InitialMaxPathID)
		require.False(t, p.client.advertisedMultipath)
		require.False(t, p.server.advertisedMultipath)
		require.Nil(t, p.client.mp)
		require.Nil(t, p.server.mp)
	})
}

// The initial_max_path_id never exceeds the limit for Config.MaxPaths,
// even for configs that are not populated.
func TestMultipathLocalInitialMaxPathID(t *testing.T) {
	for _, tc := range []struct {
		maxPaths int
		expected protocol.PathID
	}{
		{-1, 0},
		{0, 0},
		{1, 0},
		{3, 2},
		{protocol.MaxMultipathPaths, protocol.MaxMultipathPaths - 1},
		{protocol.MaxMultipathPaths + 1, protocol.MaxMultipathPaths - 1},
		{math.MaxInt, protocol.MaxMultipathPaths - 1},
	} {
		require.Equal(t, tc.expected, localInitialMaxPathID(&Config{MaxPaths: tc.maxPaths}), "MaxPaths: %d", tc.maxPaths)
	}
}

// Configs returned by GetConfigForClient are not validated.
// The initial_max_path_id is limited nevertheless.
func TestMultipathMaxPathsGetConfigForClient(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var clientEvents, serverEvents events.Recorder
		p := dialMultipathTestConnPair(
			t,
			&Transport{},
			multipathTestConfig(true, protocol.PerspectiveClient, &clientEvents),
			&Config{
				GetConfigForClient: func(*ClientInfo) (*Config, error) {
					conf := multipathTestConfig(true, protocol.PerspectiveServer, &serverEvents)
					conf.MaxPaths = protocol.MaxMultipathPaths + 1
					return conf, nil
				},
			},
			&clientEvents,
			&serverEvents,
		)
		p.transfer(t, []byte("foobar"))
		p.close(t)

		params := localTransportParameters(t, &serverEvents)
		require.NotNil(t, params.InitialMaxPathID)
		require.Equal(t, protocol.PathID(protocol.MaxMultipathPaths-1), *params.InitialMaxPathID)
		require.Equal(t, protocol.MaxMultipathPaths, p.server.config.MaxPaths)
		require.NotNil(t, p.server.mp)
		require.Equal(t, protocol.PathID(protocol.MaxMultipathPaths-1), p.server.mp.localMaxPathID)
	})
}

// An endpoint that has IETF Multipath QUIC enabled, but didn't advertise it because the client uses a zero-length
// connection ID, closes the connection if the peer advertises it (section 2.1 of draft-ietf-quic-multipath-21).
func TestMultipathZeroLengthConnectionIDPeerAdvertises(t *testing.T) {
	for _, tc := range []struct {
		name string
		// makes one endpoint advertise the extension, although the client uses a zero-length connection ID
		shouldAdvertise func(ctrl MultipathController, srcConnID, destConnID protocol.ConnectionID) bool
		remoteErr       bool
	}{
		{
			name: "client advertises",
			// the client ignores that its own connection ID has a zero length
			shouldAdvertise: func(ctrl MultipathController, _, destConnID protocol.ConnectionID) bool {
				return ctrl != nil && destConnID.Len() > 0
			},
			remoteErr: true,
		},
		{
			name: "server advertises",
			// the server ignores that the client's connection ID has a zero length
			shouldAdvertise: func(ctrl MultipathController, srcConnID, _ protocol.ConnectionID) bool {
				return ctrl != nil && srcConnID.Len() > 0
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			origShouldAdvertise := shouldAdvertiseMultipath
			shouldAdvertiseMultipath = tc.shouldAdvertise
			t.Cleanup(func() { shouldAdvertiseMultipath = origShouldAdvertise })

			synctest.Test(t, func(t *testing.T) {
				clientPacketConn, serverPacketConn, closeNetwork := newSimnetLink(t, 10*time.Millisecond)
				defer closeNetwork()
				var clientEvents, serverEvents events.Recorder
				serverTr := &Transport{Conn: serverPacketConn}
				defer serverTr.Close()
				ln, err := serverTr.Listen(generateTLSConfig(), multipathTestConfig(true, protocol.PerspectiveServer, &serverEvents))
				require.NoError(t, err)
				defer ln.Close()
				clientTr := &Transport{
					Conn:                  clientPacketConn,
					ConnectionIDGenerator: &protocol.DefaultConnectionIDGenerator{ConnLen: 0},
				}
				defer clientTr.Close()

				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_, err = clientTr.Dial(
					ctx,
					serverPacketConn.LocalAddr(),
					generateTLSConfigWithServerName("localhost"),
					multipathTestConfig(true, protocol.PerspectiveClient, &clientEvents),
				)
				var transportErr *TransportError
				require.ErrorAs(t, err, &transportErr)
				require.Equal(t, ProtocolViolation, transportErr.ErrorCode)
				require.Equal(t, tc.remoteErr, transportErr.Remote)

				// Exactly one endpoint advertised the extension.
				clientParams := localTransportParameters(t, &clientEvents)
				require.Zero(t, clientParams.InitialSourceConnectionID.Len())
				require.Equal(t, tc.remoteErr, clientParams.InitialMaxPathID != nil)
				if !tc.remoteErr {
					require.NotNil(t, localTransportParameters(t, &serverEvents).InitialMaxPathID)
				}
			})
		})
	}
}

// A server that uses zero-length connection IDs sends a Retry with a zero-length Source Connection ID.
// A client that advertised IETF Multipath QUIC would have to send the initial_max_path_id transport parameter
// in Initial packets with a zero-length Destination Connection ID (section 2.1 of draft-ietf-quic-multipath-21),
// so it closes the connection. Clients that don't use the extension are not affected.
// If the client sends the transport parameter nevertheless, the server closes the connection.
func TestMultipathRetryZeroLengthConnectionID(t *testing.T) {
	for _, tc := range []struct {
		name            string
		clientMultipath bool
		// makes the client keep advertising the extension after the Retry
		ignoreRetryConnID bool
		expectedErr       *TransportError
	}{
		{name: "client without multipath"},
		{name: "client with multipath", clientMultipath: true, expectedErr: &TransportError{ErrorCode: ProtocolViolation}},
		{
			name:              "client ignores the Retry connection ID",
			clientMultipath:   true,
			ignoreRetryConnID: true,
			expectedErr:       &TransportError{ErrorCode: ProtocolViolation, Remote: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.ignoreRetryConnID {
				origShouldAdvertise := shouldAdvertiseMultipath
				// The server doesn't advertise the extension, since it uses zero-length connection IDs.
				shouldAdvertiseMultipath = func(ctrl MultipathController, srcConnID, _ protocol.ConnectionID) bool {
					return ctrl != nil && srcConnID.Len() > 0
				}
				t.Cleanup(func() { shouldAdvertiseMultipath = origShouldAdvertise })
			}

			synctest.Test(t, func(t *testing.T) {
				clientPacketConn, serverPacketConn, closeNetwork := newSimnetLink(t, 10*time.Millisecond)
				defer closeNetwork()
				var clientEvents, serverEvents events.Recorder
				serverTr := &Transport{
					Conn:                  serverPacketConn,
					ConnectionIDGenerator: &protocol.DefaultConnectionIDGenerator{ConnLen: 0},
					VerifySourceAddress:   func(net.Addr) bool { return true },
				}
				defer serverTr.Close()
				ln, err := serverTr.Listen(generateTLSConfig(), multipathTestConfig(true, protocol.PerspectiveServer, &serverEvents))
				require.NoError(t, err)
				defer ln.Close()
				clientTr := &Transport{Conn: clientPacketConn}
				defer clientTr.Close()

				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				conn, err := clientTr.Dial(
					ctx,
					serverPacketConn.LocalAddr(),
					generateTLSConfigWithServerName("localhost"),
					multipathTestConfig(tc.clientMultipath, protocol.PerspectiveClient, &clientEvents),
				)
				require.Equal(t, tc.clientMultipath, localTransportParameters(t, &clientEvents).InitialMaxPathID != nil)
				if tc.expectedErr == nil {
					require.NoError(t, err)
					received := clientEvents.Events(qlog.PacketReceived{})
					require.NotEmpty(t, received)
					require.Equal(t, qlog.PacketTypeRetry, received[0].(qlog.PacketReceived).Header.PacketType)
					require.Zero(t, received[0].(qlog.PacketReceived).Header.SrcConnectionID.Len())
					require.False(t, conn.supportsMultipath())
					sconn, err := ln.Accept(ctx)
					require.NoError(t, err)
					require.False(t, sconn.supportsMultipath())
					conn.CloseWithError(0, "")
					return
				}
				var transportErr *TransportError
				require.ErrorAs(t, err, &transportErr)
				require.Equal(t, tc.expectedErr.ErrorCode, transportErr.ErrorCode)
				require.Equal(t, tc.expectedErr.Remote, transportErr.Remote)
				if tc.ignoreRetryConnID {
					require.Contains(t, transportErr.ErrorMessage, "zero-length connection ID")
					return
				}
				// The client didn't send any packets after the Retry, so the server never created a connection.
				for _, ev := range clientEvents.Events(qlog.PacketSent{}) {
					require.NotZero(t, ev.(qlog.PacketSent).Header.DestConnectionID.Len())
				}
				require.Empty(t, serverEvents.Events(qlog.ParametersSet{}))
			})
		})
	}
}

// sessionTicketSignallingCache signals when a session ticket is stored.
type sessionTicketSignallingCache struct {
	tls.ClientSessionCache
	puts chan struct{}
}

func (c *sessionTicketSignallingCache) Put(key string, cs *tls.ClientSessionState) {
	c.ClientSessionCache.Put(key, cs)
	select {
	case c.puts <- struct{}{}:
	default:
	}
}

// The initial_max_path_id transport parameter is not remembered for 0-RTT (section 2.1 of draft-ietf-quic-multipath-21).
// IETF Multipath QUIC is negotiated afresh on every connection.
// The server always advertises the extension, the client only if a multipath controller is configured.
func TestMultipathNotRememberedFor0RTT(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		advertiseFirst         bool
		advertiseResumption    bool
		expectMultipathResumed bool
	}{
		{name: "advertised on both connections", advertiseFirst: true, advertiseResumption: true, expectMultipathResumed: true},
		{name: "advertised on the first connection", advertiseFirst: true},
		{name: "advertised on the resumed connection", advertiseResumption: true, expectMultipathResumed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				clientPacketConn, serverPacketConn, closeNetwork := newSimnetLink(t, 10*time.Millisecond)
				defer closeNetwork()

				serverTr := &Transport{Conn: serverPacketConn}
				defer serverTr.Close()
				var serverEvents events.Recorder
				serverConf := multipathTestConfig(true, protocol.PerspectiveServer, &serverEvents)
				serverConf.Allow0RTT = true
				ln, err := serverTr.ListenEarly(generateTLSConfig(), serverConf)
				require.NoError(t, err)
				defer ln.Close()

				clientTr := &Transport{Conn: clientPacketConn}
				defer clientTr.Close()
				cache := &sessionTicketSignallingCache{
					ClientSessionCache: tls.NewLRUClientSessionCache(10),
					puts:               make(chan struct{}, 1),
				}
				clientTLSConf := generateTLSConfigWithServerName("localhost")
				clientTLSConf.ClientSessionCache = cache

				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				// first connection: receive a session ticket
				var clientEvents1 events.Recorder
				conn, err := clientTr.Dial(ctx, serverPacketConn.LocalAddr(), clientTLSConf, multipathTestConfig(tc.advertiseFirst, protocol.PerspectiveClient, &clientEvents1))
				require.NoError(t, err)
				serverConn, err := ln.Accept(ctx)
				require.NoError(t, err)
				select {
				case <-cache.puts:
				case <-ctx.Done():
					t.Fatal("timeout waiting for the session ticket")
				}
				require.NoError(t, conn.CloseWithError(0, ""))
				<-serverConn.Context().Done()
				require.Equal(t, tc.advertiseFirst, conn.mp != nil)

				// second connection: 0-RTT
				var clientEvents2 events.Recorder
				conn, err = clientTr.DialEarly(ctx, serverPacketConn.LocalAddr(), clientTLSConf, multipathTestConfig(tc.advertiseResumption, protocol.PerspectiveClient, &clientEvents2))
				require.NoError(t, err)
				str, err := conn.OpenUniStream()
				require.NoError(t, err)
				_, err = str.Write([]byte("0-RTT data"))
				require.NoError(t, err)
				require.NoError(t, str.Close())

				serverConn, err = ln.Accept(ctx)
				require.NoError(t, err)
				serverStr, err := serverConn.AcceptUniStream(ctx)
				require.NoError(t, err)
				data, err := io.ReadAll(serverStr)
				require.NoError(t, err)
				require.Equal(t, []byte("0-RTT data"), data)
				select {
				case <-conn.HandshakeComplete():
				case <-ctx.Done():
					t.Fatal("timeout waiting for the handshake to complete")
				}
				require.True(t, conn.ConnectionState().Used0RTT)
				require.True(t, serverConn.ConnectionState().Used0RTT)

				require.NoError(t, conn.CloseWithError(0, ""))
				<-serverConn.Context().Done()

				// the transport parameters restored from the session ticket don't contain initial_max_path_id
				restored := clientEvents2.Events(qlog.ParametersSet{})
				var foundRestored bool
				for _, ev := range restored {
					if ps := ev.(qlog.ParametersSet); ps.Restore {
						foundRestored = true
						require.Nil(t, ps.InitialMaxPathID)
					}
				}
				require.True(t, foundRestored)
				require.Equal(t, tc.expectMultipathResumed, conn.mp != nil)
				require.Equal(t, tc.expectMultipathResumed, serverConn.mp != nil)
			})
		})
	}
}

// quic.DialAddr uses zero-length connection IDs, unless multipath is configured.
func TestMultipathDialAddrConnectionIDLength(t *testing.T) {
	for _, withController := range []bool{false, true} {
		t.Run(fmt.Sprintf("with controller: %t", withController), func(t *testing.T) {
			ln, err := ListenAddr("127.0.0.1:0", generateTLSConfig(), nil)
			require.NoError(t, err)
			defer ln.Close()

			var clientEvents events.Recorder
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := DialAddr(
				ctx,
				ln.Addr().String(),
				generateTLSConfigWithServerName("localhost"),
				multipathTestConfig(withController, protocol.PerspectiveClient, &clientEvents),
			)
			require.NoError(t, err)

			srcConnID := localTransportParameters(t, &clientEvents).InitialSourceConnectionID
			if withController {
				require.Equal(t, protocol.DefaultConnectionIDLength, srcConnID.Len())
			} else {
				require.Zero(t, srcConnID.Len())
			}

			require.NoError(t, conn.CloseWithError(0, ""))
			require.NoError(t, ln.Close())
			// The Transport created by DialAddr is closed once the closing period of the connection ended.
			require.Eventually(t, func() bool { return !areTransportsRunning() }, 5*time.Second, 10*time.Millisecond)
		})
	}
}

// checkClosingPeriod checks that the connection ID is handled by a closed connection
// until 3 times the largest PTO among all paths elapsed, and removed afterwards.
func checkClosingPeriod(t *testing.T, tr *Transport, connID protocol.ConnectionID, deadline time.Time) {
	t.Helper()
	time.Sleep(time.Until(deadline) - time.Microsecond)
	synctest.Wait()
	_, ok := (*packetHandlerMap)(tr).Get(connID)
	require.True(t, ok, "connection ID removed before the end of the closing period")
	time.Sleep(2 * time.Microsecond)
	synctest.Wait()
	_, ok = (*packetHandlerMap)(tr).Get(connID)
	require.False(t, ok, "connection ID not removed after the closing period")
}

func countKeyUpdates(r *events.Recorder) int {
	var n int
	for _, ev := range r.Events(qlog.KeyUpdated{}) {
		ku := ev.(qlog.KeyUpdated)
		if (ku.KeyType == qlog.KeyTypeClient1RTT || ku.KeyType == qlog.KeyTypeServer1RTT) && ku.KeyPhase > 0 {
			n++
		}
	}
	return n
}

// Once IETF Multipath QUIC is negotiated, path 0 uses the frames of the extension.
func TestMultipathPath0Transfer(t *testing.T) {
	t.Cleanup(handshake.SetKeyUpdateInterval(1))

	synctest.Test(t, func(t *testing.T) {
		p := newMultipathTestConnPair(t, true, true)
		data := make([]byte, 1<<20)
		rand.Read(data)
		p.transfer(t, data)

		require.NoError(t, p.client.CloseWithError(0, ""))
		clientClosed := time.Now()
		<-p.server.Context().Done()
		serverClosed := time.Now()

		// The connections are closed, so their state can be accessed now.
		for _, side := range []struct {
			name   string
			conn   *Conn
			events *events.Recorder
		}{
			{name: "client", conn: p.client, events: p.clientEvents},
			{name: "server", conn: p.server, events: p.serverEvents},
		} {
			require.NotNil(t, side.conn.mp, side.name)
			require.True(t, side.conn.mp.active, side.name)
			frames, _ := sent1RTTFrames(side.events)
			counts := countSentFrames(frames)
			require.Zero(t, counts.ack, side.name)
			require.NotZero(t, counts.pathAck, side.name)
			require.NotZero(t, counts.pathNewConnID, side.name)
			// a connection ID was issued for every unused path ID
			require.Equal(t, map[protocol.PathID]struct{}{0: {}, 1: {}, 2: {}}, counts.pathNewConnIDPaths, side.name)
			for _, id := range []protocol.PathID{1, 2} {
				h, ok := side.conn.peerConnIDs.paths[id]
				require.True(t, ok, "%s: no connection ID for path %d", side.name, id)
				require.NotEmpty(t, h.queue, "%s: no connection ID for path %d", side.name, id)
			}
			require.NotZero(t, countKeyUpdates(side.events), side.name)
		}

		// The closing and draining periods last 3 times the largest PTO among all paths.
		clientDeadline := clientClosed.Add(3 * p.client.sentPacketHandler.MaxPTO(false))
		serverDeadline := serverClosed.Add(3 * p.server.sentPacketHandler.MaxPTO(false))
		var clientConnID, serverConnID protocol.ConnectionID
		for _, connID := range p.client.connIDGenerator.paths[1].active {
			clientConnID = connID
		}
		for _, connID := range p.server.connIDGenerator.path0.active {
			serverConnID = connID
		}
		if clientDeadline.Before(serverDeadline) {
			checkClosingPeriod(t, p.clientTr, clientConnID, clientDeadline)
			checkClosingPeriod(t, p.serverTr, serverConnID, serverDeadline)
		} else {
			checkClosingPeriod(t, p.serverTr, serverConnID, serverDeadline)
			checkClosingPeriod(t, p.clientTr, clientConnID, clientDeadline)
		}
	})
}

// newIETFMultipathTestConnection returns a connection for which both endpoints advertised IETF Multipath QUIC,
// with the given local and peer maximum path IDs.
// The connection issues connection IDs of the same length as its initial connection ID,
// and the peer's active_connection_id_limit is 4.
func newIETFMultipathTestConnection(
	t *testing.T,
	pers protocol.Perspective,
	localMaxPathID, peerMaxPathID protocol.PathID,
	activate bool,
	opts ...testConnectionOpt,
) *testConnection {
	t.Helper()
	mockCtrl := gomock.NewController(t)
	config := &Config{DisablePathMTUDiscovery: true, MaxPaths: int(localMaxPathID) + 1}
	var tc *testConnection
	if pers == protocol.PerspectiveClient {
		tc = newClientTestConnection(t, mockCtrl, config, false, opts...)
	} else {
		tc = newServerTestConnection(t, mockCtrl, config, false, opts...)
	}
	tc.connRunner.EXPECT().Add(gomock.Any(), gomock.Any()).AnyTimes()
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	tc.connRunner.EXPECT().AddResetToken(gomock.Any(), gomock.Any()).AnyTimes()
	tc.connRunner.EXPECT().RemoveResetToken(gomock.Any()).AnyTimes()
	c := tc.conn
	c.connIDGenerator.generator = &protocol.DefaultConnectionIDGenerator{ConnLen: c.srcConnIDLen}
	c.advertisedMultipath = true
	c.frameParser.EnableMultipath()
	c.peerParams = &wire.TransportParameters{HasInitialMaxPathID: true, InitialMaxPathID: peerMaxPathID, ActiveConnectionIDLimit: 4}
	c.mp = newMultipathState(localMaxPathID, peerMaxPathID)
	require.NoError(t, c.connIDGenerator.SetMaxActiveConnIDs(4))
	if activate {
		activateMultipathTestConnection(t, tc)
	}
	return tc
}

func activateMultipathTestConnection(t *testing.T, tc *testConnection) {
	t.Helper()
	tc.packer.EXPECT().EnableMultipath(gomock.Any(), gomock.Any())
	require.NoError(t, tc.conn.activateMultipath())
}

// queuedFrames returns the control frames queued in the framer.
func queuedFrames(c *Conn) []ackhandler.Frame {
	frames, _, _ := c.framer.Append(nil, nil, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
	return frames
}

func handleTestFrame(t *testing.T, c *Conn, f wire.Frame, encLevel protocol.EncryptionLevel) error {
	t.Helper()
	data, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	_, _, _, err = c.handleFrames(data, protocol.ConnectionID{}, encLevel, nil, monotime.Now())
	return err
}

// The initial_max_path_id transport parameter is checked if IETF Multipath QUIC is enabled locally,
// even if we didn't advertise it because of zero-length connection IDs (section 2.1 of draft-ietf-quic-multipath-21).
func TestMultipathTransportParameterValidation(t *testing.T) {
	for _, pers := range []protocol.Perspective{protocol.PerspectiveClient, protocol.PerspectiveServer} {
		t.Run(pers.String(), func(t *testing.T) {
			for _, tc := range []struct {
				name                 string
				enabled, advertised  bool
				initialMaxPathID     protocol.PathID
				zeroLengthPeerConnID bool
				zeroLengthOwnConnID  bool
				// the client sent its Initial packets to a zero-length connection ID (after a Retry)
				zeroLengthClientDestConnID bool
				expectedErr                error
				onlyClient                 bool // the error only applies to the client
				onlyServer                 bool // the error only applies to the server
				expectMultipath            bool
			}{
				{name: "valid", enabled: true, advertised: true, initialMaxPathID: 5, expectMultipath: true},
				{name: "maximum value", enabled: true, advertised: true, initialMaxPathID: protocol.MaxPathID, expectMultipath: true},
				{name: "too large", enabled: true, advertised: true, initialMaxPathID: protocol.MaxPathID + 1, expectedErr: &qerr.TransportError{ErrorCode: qerr.TransportParameterError}},
				{name: "zero-length connection ID", enabled: true, advertised: true, initialMaxPathID: 5, zeroLengthPeerConnID: true, expectedErr: &qerr.TransportError{ErrorCode: qerr.ProtocolViolation}},
				// Multipath is enabled, but we didn't advertise it. The extension is not negotiated.
				{name: "not advertised", enabled: true, initialMaxPathID: 5},
				{name: "not advertised, too large", enabled: true, initialMaxPathID: protocol.MaxPathID + 1, expectedErr: &qerr.TransportError{ErrorCode: qerr.TransportParameterError}},
				{name: "not advertised, zero-length connection ID", enabled: true, initialMaxPathID: 5, zeroLengthPeerConnID: true, expectedErr: &qerr.TransportError{ErrorCode: qerr.ProtocolViolation}},
				// The client receives the server's transport parameters in packets sent to its own connection ID.
				// The server receives the client's transport parameters in packets sent to a connection ID chosen by the client.
				{name: "not advertised, own zero-length connection ID", enabled: true, initialMaxPathID: 5, zeroLengthOwnConnID: true, expectedErr: &qerr.TransportError{ErrorCode: qerr.ProtocolViolation}, onlyClient: true},
				// After a Retry, the client sends its Initial packets to the source connection ID of the Retry.
				// This connection ID has a zero length if the server uses zero-length connection IDs.
				{name: "zero-length client destination connection ID", enabled: true, advertised: true, initialMaxPathID: 5, zeroLengthClientDestConnID: true, expectedErr: &qerr.TransportError{ErrorCode: qerr.ProtocolViolation}, onlyServer: true, expectMultipath: true},
				{name: "not advertised, zero-length client destination connection ID", enabled: true, initialMaxPathID: 5, zeroLengthOwnConnID: true, zeroLengthClientDestConnID: true, expectedErr: &qerr.TransportError{ErrorCode: qerr.ProtocolViolation}},
				// Without multipath, the transport parameter is ignored.
				{name: "multipath disabled", initialMaxPathID: 1 << 40},
				{name: "multipath disabled, zero-length connection ID", initialMaxPathID: 5, zeroLengthPeerConnID: true, zeroLengthOwnConnID: true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					mockCtrl := gomock.NewController(t)
					cs := mocks.NewMockCryptoSetup(mockCtrl)
					var conn *testConnection
					if pers == protocol.PerspectiveClient {
						conn = newClientTestConnection(t, mockCtrl, nil, false, connectionOptCryptoSetup(cs))
					} else {
						conn = newServerTestConnection(t, mockCtrl, nil, false, connectionOptCryptoSetup(cs))
					}
					c := conn.conn
					if tc.enabled {
						c.multipathController = testMultipathController{}
					}
					c.advertisedMultipath = tc.advertised
					if pers == protocol.PerspectiveServer {
						// set from the destination connection ID of the client's first Initial packet
						require.Equal(t, conn.destConnID.Len(), c.clientDestConnIDLen)
						require.NotZero(t, c.clientDestConnIDLen)
					}
					if tc.zeroLengthOwnConnID {
						c.srcConnIDLen = 0
					}
					if tc.zeroLengthClientDestConnID && pers == protocol.PerspectiveServer {
						c.clientDestConnIDLen = 0
					}
					// the source connection ID of the packet carrying the transport parameters
					srcConnID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
					if tc.zeroLengthPeerConnID {
						srcConnID = protocol.ConnectionID{}
					}
					c.handshakeDestConnID = srcConnID
					params := &wire.TransportParameters{
						InitialSourceConnectionID: srcConnID,
						HasInitialMaxPathID:       true,
						InitialMaxPathID:          tc.initialMaxPathID,
					}
					if pers == protocol.PerspectiveClient {
						params.OriginalDestinationConnectionID = conn.destConnID
					}
					expectedErr := tc.expectedErr
					if (tc.onlyClient && pers == protocol.PerspectiveServer) || (tc.onlyServer && pers == protocol.PerspectiveClient) {
						expectedErr = nil
					}
					if tc.expectMultipath && expectedErr == nil {
						cs.EXPECT().EnableMultipath(gomock.Any())
					}
					if pers == protocol.PerspectiveServer && expectedErr == nil {
						conn.connRunner.EXPECT().Add(gomock.Any(), gomock.Any()).AnyTimes()
					}
					err := c.handleTransportParameters(params)
					if expectedErr != nil {
						require.ErrorIs(t, err, expectedErr)
						return
					}
					require.NoError(t, err)
					require.Equal(t, tc.expectMultipath, c.mp != nil)
					if tc.expectMultipath {
						require.False(t, c.mp.active)
						require.Equal(t, tc.initialMaxPathID, c.mp.peerMaxPathID)
						require.Equal(t, protocol.PathID(2), c.mp.localMaxPathID)
					}
				})
			}
		})
	}
}

// The MP-06 check of the crypto setup closes the connection.
func TestMultipathCipherSuiteCheck(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	cs := mocks.NewMockCryptoSetup(mockCtrl)
	tc := newClientTestConnection(t, mockCtrl, nil, false, connectionOptCryptoSetup(cs))
	tc.conn.advertisedMultipath = true
	cs.EXPECT().EnableMultipath(gomock.Any()).Return(&qerr.TransportError{ErrorCode: qerr.TransportParameterError})
	err := tc.conn.handleTransportParameters(&wire.TransportParameters{
		OriginalDestinationConnectionID: tc.destConnID,
		InitialSourceConnectionID:       tc.conn.handshakeDestConnID,
		HasInitialMaxPathID:             true,
	})
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.TransportParameterError})
}

// Section 4 of draft-ietf-quic-multipath-21: a path ID larger than the maximum path ID
// announced to the peer is a PROTOCOL_VIOLATION.
func TestMultipathFramesPathIDTooLarge(t *testing.T) {
	connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
	for _, tc := range []struct {
		name      string
		frameType wire.FrameType
		frame     func(protocol.PathID) wire.Frame
	}{
		{"PATH_ACK", wire.FrameTypePathAck, func(id protocol.PathID) wire.Frame {
			return &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 1}}, PathID: id, HasPathID: true}
		}},
		{"PATH_ACK_ECN", wire.FrameTypePathAckECN, func(id protocol.PathID) wire.Frame {
			return &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 1}}, ECT0: 1, PathID: id, HasPathID: true}
		}},
		{"PATH_ABANDON", wire.FrameTypePathAbandon, func(id protocol.PathID) wire.Frame {
			return &wire.PathAbandonFrame{PathID: id}
		}},
		{"PATH_STATUS_BACKUP", wire.FrameTypePathStatusBackup, func(id protocol.PathID) wire.Frame {
			return &wire.PathStatusFrame{PathID: id, SequenceNumber: 1, Backup: true}
		}},
		{"PATH_STATUS_AVAILABLE", wire.FrameTypePathStatusAvailable, func(id protocol.PathID) wire.Frame {
			return &wire.PathStatusFrame{PathID: id, SequenceNumber: 1}
		}},
		{"PATH_NEW_CONNECTION_ID", wire.FrameTypePathNewConnectionID, func(id protocol.PathID) wire.Frame {
			return &wire.PathNewConnectionIDFrame{PathID: id, ConnectionID: connID}
		}},
		{"PATH_RETIRE_CONNECTION_ID", wire.FrameTypePathRetireConnectionID, func(id protocol.PathID) wire.Frame {
			return &wire.PathRetireConnectionIDFrame{PathID: id}
		}},
		{"PATHS_BLOCKED", wire.FrameTypePathsBlocked, func(id protocol.PathID) wire.Frame {
			return &wire.PathsBlockedFrame{MaximumPathID: id}
		}},
		{"PATH_CIDS_BLOCKED", wire.FrameTypePathCIDsBlocked, func(id protocol.PathID) wire.Frame {
			return &wire.PathCIDsBlockedFrame{PathID: id}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, activate := range []bool{false, true} {
				for _, id := range []protocol.PathID{3, protocol.MaxPathID + 1, quicvarint.Max} {
					conn := newIETFMultipathTestConnection(t, protocol.PerspectiveServer, 2, 2, activate)
					err := handleTestFrame(t, conn.conn, tc.frame(id), protocol.Encryption1RTT)
					require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation, FrameType: uint64(tc.frameType)}, "path ID %d", id)
				}
				// the maximum path ID is valid
				conn := newIETFMultipathTestConnection(t, protocol.PerspectiveServer, 2, 2, activate)
				err := handleTestFrame(t, conn.conn, tc.frame(2), protocol.Encryption1RTT)
				switch {
				// PATH_ACK frames for path 2 are invalid for another reason: we never sent a packet on path 2.
				case tc.frameType == wire.FrameTypePathAck || tc.frameType == wire.FrameTypePathAckECN:
					var transportErr *qerr.TransportError
					require.ErrorAs(t, err, &transportErr)
					require.Equal(t, qerr.ProtocolViolation, transportErr.ErrorCode)
					require.ErrorContains(t, err, "didn't send any packets")
				// Connection IDs for path 2 are only issued once the extension is active.
				case tc.frameType == wire.FrameTypePathRetireConnectionID && !activate:
					var transportErr *qerr.TransportError
					require.ErrorAs(t, err, &transportErr)
					require.Equal(t, qerr.ProtocolViolation, transportErr.ErrorCode)
					require.ErrorContains(t, err, "none issued")
				default:
					require.NoError(t, err)
				}
			}
		})
	}
}

// Section 4 of draft-ietf-quic-multipath-21: the frames MUST only be sent in 1-RTT packets.
func TestMultipathFramesIn0RTTPackets(t *testing.T) {
	for _, frame := range ietfMultipathTestFrames() {
		data, err := frame.Append(nil, protocol.Version1)
		require.NoError(t, err)
		frameType, _, err := quicvarint.Parse(data)
		require.NoError(t, err)
		t.Run(fmt.Sprintf("frame type %#x", frameType), func(t *testing.T) {
			conn := newIETFMultipathTestConnection(t, protocol.PerspectiveServer, 2, 2, false)
			err := handleTestFrame(t, conn.conn, frame, protocol.Encryption0RTT)
			require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation, FrameType: frameType})
		})
	}
}

func TestMultipathMaxPathIDFrame(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value protocol.PathID
		valid bool
	}{
		{name: "too large", value: protocol.MaxPathID + 1},
		{name: "largest varint", value: quicvarint.Max},
		{name: "below initial_max_path_id", value: 1},
		{name: "equal to initial_max_path_id", value: 2, valid: true},
		{name: "largest path ID", value: protocol.MaxPathID, valid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := newIETFMultipathTestConnection(t, protocol.PerspectiveServer, 5, 2, true)
			err := handleTestFrame(t, conn.conn, &wire.MaxPathIDFrame{MaximumPathID: tc.value}, protocol.Encryption1RTT)
			if !tc.valid {
				require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation, FrameType: uint64(wire.FrameTypeMaxPathID)})
				return
			}
			require.NoError(t, err)
		})
	}

	t.Run("raising the maximum", func(t *testing.T) {
		conn := newIETFMultipathTestConnection(t, protocol.PerspectiveServer, 5, 2, true)
		c := conn.conn
		queuedFrames(c) // the connection IDs issued so far

		require.NoError(t, handleTestFrame(t, c, &wire.MaxPathIDFrame{MaximumPathID: 4}, protocol.Encryption1RTT))
		require.Equal(t, protocol.PathID(4), c.mp.peerMaxPathID)
		// connection IDs are issued for the path IDs that can be used now
		var paths []protocol.PathID
		for _, f := range queuedFrames(c) {
			if ncid, ok := f.Frame.(*wire.PathNewConnectionIDFrame); ok {
				paths = append(paths, ncid.PathID)
			}
		}
		require.ElementsMatch(t, []protocol.PathID{3, 4}, paths)

		// MAX_PATH_ID frames that don't increase the limit are ignored
		require.NoError(t, handleTestFrame(t, c, &wire.MaxPathIDFrame{MaximumPathID: 3}, protocol.Encryption1RTT))
		require.Equal(t, protocol.PathID(4), c.mp.peerMaxPathID)
		require.Empty(t, queuedFrames(c))
	})

	t.Run("before activation", func(t *testing.T) {
		conn := newIETFMultipathTestConnection(t, protocol.PerspectiveClient, 5, 2, false)
		c := conn.conn
		require.NoError(t, handleTestFrame(t, c, &wire.MaxPathIDFrame{MaximumPathID: 3}, protocol.Encryption1RTT))
		require.Equal(t, protocol.PathID(3), c.mp.peerMaxPathID)
		queuedFrames(c) // NEW_CONNECTION_ID frames for path 0
		activateMultipathTestConnection(t, conn)
		var paths []protocol.PathID
		for _, f := range queuedFrames(c) {
			if ncid, ok := f.Frame.(*wire.PathNewConnectionIDFrame); ok {
				paths = append(paths, ncid.PathID)
			}
		}
		require.ElementsMatch(t, []protocol.PathID{1, 2, 3}, paths)
	})
}

func TestMultipathPathsBlockedFrame(t *testing.T) {
	conn := newIETFMultipathTestConnection(t, protocol.PerspectiveServer, 2, 2, true)
	require.NoError(t, handleTestFrame(t, conn.conn, &wire.PathsBlockedFrame{MaximumPathID: 1}, protocol.Encryption1RTT))
	require.NoError(t, handleTestFrame(t, conn.conn, &wire.PathsBlockedFrame{MaximumPathID: 2}, protocol.Encryption1RTT))
	err := handleTestFrame(t, conn.conn, &wire.PathsBlockedFrame{MaximumPathID: 3}, protocol.Encryption1RTT)
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation, FrameType: uint64(wire.FrameTypePathsBlocked)})
}

func TestMultipathPathCIDsBlockedFrame(t *testing.T) {
	newConn := func(t *testing.T) *Conn {
		conn := newIETFMultipathTestConnection(t, protocol.PerspectiveServer, 5, 2, true)
		queuedFrames(conn.conn)
		// one connection ID was issued for the unused paths 1 and 2, none for paths 3 to 5
		require.Equal(t, uint64(1), conn.conn.connIDGenerator.NextSequenceNumber(1))
		require.Zero(t, conn.conn.connIDGenerator.NextSequenceNumber(3))
		return conn.conn
	}
	newConnIDs := func(c *Conn) (seqs []uint64) {
		for _, f := range queuedFrames(c) {
			if ncid, ok := f.Frame.(*wire.PathNewConnectionIDFrame); ok {
				require.Equal(t, protocol.PathID(1), ncid.PathID)
				seqs = append(seqs, ncid.SequenceNumber)
			}
		}
		return seqs
	}

	t.Run("blocked", func(t *testing.T) {
		c := newConn(t)
		require.NoError(t, handleTestFrame(t, c, &wire.PathCIDsBlockedFrame{PathID: 1, NextSequenceNumber: 1}, protocol.Encryption1RTT))
		// the peer's active_connection_id_limit is 4
		require.ElementsMatch(t, []uint64{1, 2, 3}, newConnIDs(c))
	})

	t.Run("outdated", func(t *testing.T) {
		c := newConn(t)
		require.NoError(t, handleTestFrame(t, c, &wire.PathCIDsBlockedFrame{PathID: 1, NextSequenceNumber: 0}, protocol.Encryption1RTT))
		require.Empty(t, newConnIDs(c))
	})

	t.Run("next sequence number too large", func(t *testing.T) {
		c := newConn(t)
		err := handleTestFrame(t, c, &wire.PathCIDsBlockedFrame{PathID: 1, NextSequenceNumber: 2}, protocol.Encryption1RTT)
		require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation, FrameType: uint64(wire.FrameTypePathCIDsBlocked)})
		err = handleTestFrame(t, c, &wire.PathCIDsBlockedFrame{PathID: 3, NextSequenceNumber: 1}, protocol.Encryption1RTT)
		require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation, FrameType: uint64(wire.FrameTypePathCIDsBlocked)})
	})

	t.Run("path ID above the peer's maximum", func(t *testing.T) {
		c := newConn(t)
		// We can't issue connection IDs for path IDs above the peer's maximum path ID.
		require.NoError(t, handleTestFrame(t, c, &wire.PathCIDsBlockedFrame{PathID: 3, NextSequenceNumber: 0}, protocol.Encryption1RTT))
		require.Empty(t, queuedFrames(c))
	})
}

// Section 4.3 of draft-ietf-quic-multipath-21: frames with an outdated sequence number are ignored.
func TestMultipathPathStatusFrames(t *testing.T) {
	for _, pathID := range []protocol.PathID{0, 1} {
		t.Run(fmt.Sprintf("path %d", pathID), func(t *testing.T) {
			conn := newIETFMultipathTestConnection(t, protocol.PerspectiveServer, 2, 2, true)
			c := conn.conn
			status := func() (peerPathStatus, bool) {
				if path, ok := c.mp.paths[pathID]; ok {
					return path.peerStatus, path.hasPeerStatus
				}
				s, ok := c.mp.pendingPeerStatus[pathID]
				return s, ok
			}
			_, ok := status()
			require.False(t, ok)

			for _, tc := range []struct {
				frame    *wire.PathStatusFrame
				expected peerPathStatus
			}{
				{&wire.PathStatusFrame{PathID: pathID, SequenceNumber: 5, Backup: true}, peerPathStatus{seq: 5, backup: true}},
				{&wire.PathStatusFrame{PathID: pathID, SequenceNumber: 3}, peerPathStatus{seq: 5, backup: true}}, // outdated
				{&wire.PathStatusFrame{PathID: pathID, SequenceNumber: 5}, peerPathStatus{seq: 5, backup: true}}, // same sequence number
				{&wire.PathStatusFrame{PathID: pathID, SequenceNumber: 6}, peerPathStatus{seq: 6}},
				{&wire.PathStatusFrame{PathID: pathID, SequenceNumber: 10, Backup: true}, peerPathStatus{seq: 10, backup: true}},
			} {
				require.NoError(t, handleTestFrame(t, c, tc.frame, protocol.Encryption1RTT))
				s, ok := status()
				require.True(t, ok)
				require.Equal(t, tc.expected, s)
			}
		})
	}

	t.Run("sequence number 0", func(t *testing.T) {
		conn := newIETFMultipathTestConnection(t, protocol.PerspectiveServer, 2, 2, true)
		c := conn.conn
		require.NoError(t, handleTestFrame(t, c, &wire.PathStatusFrame{PathID: 0, Backup: true}, protocol.Encryption1RTT))
		require.True(t, c.mp.paths[0].hasPeerStatus)
		require.True(t, c.mp.paths[0].peerStatus.backup)
	})
}

func pathAbandonFrames(frames []ackhandler.Frame) []*wire.PathAbandonFrame {
	var abandon []*wire.PathAbandonFrame
	for _, f := range frames {
		if pa, ok := f.Frame.(*wire.PathAbandonFrame); ok {
			abandon = append(abandon, pa)
		}
	}
	return abandon
}

// Section 3.4 of draft-ietf-quic-multipath-21: abandoning an unused path ID is not an error.
// The path ID can't be used anymore, and the PATH_ABANDON frame is answered.
func TestMultipathPathAbandonUnusedPath(t *testing.T) {
	t.Run("after activation", func(t *testing.T) {
		conn := newIETFMultipathTestConnection(t, protocol.PerspectiveServer, 2, 2, true)
		c := conn.conn
		queuedFrames(c)
		require.NoError(t, handleTestFrame(t, c, &wire.PathAbandonFrame{PathID: 1, ErrorCode: qerr.PathUnstableOrPoor}, protocol.Encryption1RTT))
		frames := queuedFrames(c)
		require.Equal(t, []*wire.PathAbandonFrame{{PathID: 1, ErrorCode: qerr.NoError}}, pathAbandonFrames(frames))
		require.True(t, c.mp.isAbandoned(1))
		require.True(t, c.connIDGenerator.paths[1].abandoned)
		// the connection ID issued for the path ID is retained for 3 PTOs
		require.Len(t, c.connIDGenerator.paths[1].active, 1)

		// the PATH_ABANDON frame is answered only once
		require.NoError(t, handleTestFrame(t, c, &wire.PathAbandonFrame{PathID: 1}, protocol.Encryption1RTT))
		require.Empty(t, queuedFrames(c))

		// a lost PATH_ABANDON frame is retransmitted
		require.Len(t, frames, 1)
		frames[0].Handler.OnLost(frames[0].Frame)
		require.Equal(t, []*wire.PathAbandonFrame{{PathID: 1, ErrorCode: qerr.NoError}}, pathAbandonFrames(queuedFrames(c)))

		// frames for the abandoned path ID are ignored
		require.NoError(t, handleTestFrame(t, c, &wire.PathNewConnectionIDFrame{PathID: 1, ConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4})}, protocol.Encryption1RTT))
		_, ok := c.peerConnIDs.Get(1)
		require.False(t, ok)
		require.NoError(t, handleTestFrame(t, c, &wire.PathStatusFrame{PathID: 1, Backup: true}, protocol.Encryption1RTT))
		require.NotContains(t, c.mp.pendingPeerStatus, protocol.PathID(1))
		require.NoError(t, handleTestFrame(t, c, &wire.PathCIDsBlockedFrame{PathID: 1, NextSequenceNumber: 1}, protocol.Encryption1RTT))
		require.NoError(t, handleTestFrame(t, c, &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 1}}, PathID: 1, HasPathID: true}, protocol.Encryption1RTT))
		require.Empty(t, queuedFrames(c))
		// the connection ID issued for the abandoned path ID can still be retired
		require.NoError(t, handleTestFrame(t, c, &wire.PathRetireConnectionIDFrame{PathID: 1}, protocol.Encryption1RTT))
		require.Empty(t, queuedFrames(c))

		// path ID 2 is still usable
		require.Equal(t, uint64(1), c.connIDGenerator.NextSequenceNumber(2))
	})

	t.Run("before activation", func(t *testing.T) {
		conn := newIETFMultipathTestConnection(t, protocol.PerspectiveClient, 2, 2, false)
		c := conn.conn
		queuedFrames(c)
		require.NoError(t, handleTestFrame(t, c, &wire.PathAbandonFrame{PathID: 2}, protocol.Encryption1RTT))
		require.True(t, c.mp.isAbandoned(2))
		// Frames of the multipath extension are only sent after activation.
		require.Empty(t, queuedFrames(c))
		activateMultipathTestConnection(t, conn)
		frames := queuedFrames(c)
		require.Equal(t, []*wire.PathAbandonFrame{{PathID: 2, ErrorCode: qerr.NoError}}, pathAbandonFrames(frames))
		// no connection ID was issued for the abandoned path ID
		for _, f := range frames {
			if ncid, ok := f.Frame.(*wire.PathNewConnectionIDFrame); ok {
				require.NotEqual(t, protocol.PathID(2), ncid.PathID)
			}
		}
		require.Zero(t, c.connIDGenerator.NextSequenceNumber(2))
	})
}

// Section 3.4 of draft-ietf-quic-multipath-21: if the peer abandons the only open path,
// the connection is closed.
func TestMultipathPathAbandonOnlyPath(t *testing.T) {
	conn := newIETFMultipathTestConnection(t, protocol.PerspectiveServer, 2, 2, true)
	c := conn.conn
	queuedFrames(c)
	err := handleTestFrame(t, c, &wire.PathAbandonFrame{PathID: 0}, protocol.Encryption1RTT)
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.NoViablePathError, FrameType: uint64(wire.FrameTypePathAbandon)})
	// no PATH_ABANDON frame is sent in response
	require.Empty(t, pathAbandonFrames(queuedFrames(c)))
}

// The same transfer over UDP sockets on the loopback interface,
// using the capabilities of the platform (e.g. GSO and ECN on Linux).
func TestMultipathPath0TransferUDP(t *testing.T) {
	t.Cleanup(handshake.SetKeyUpdateInterval(1))

	var clientEvents, serverEvents events.Recorder
	serverTr := &Transport{Conn: newUDPConnLocalhost(t)}
	defer serverTr.Close()
	ln, err := serverTr.ListenEarly(generateTLSConfig(), multipathTestConfig(true, protocol.PerspectiveServer, &serverEvents))
	require.NoError(t, err)
	defer ln.Close()
	clientTr := &Transport{Conn: newUDPConnLocalhost(t)}
	defer clientTr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := clientTr.Dial(ctx, ln.Addr(), generateTLSConfigWithServerName("localhost"), multipathTestConfig(true, protocol.PerspectiveClient, &clientEvents))
	require.NoError(t, err)
	defer client.CloseWithError(0, "")
	server, err := ln.Accept(ctx)
	require.NoError(t, err)

	p := &multipathTestConnPair{client: client, server: server, clientEvents: &clientEvents, serverEvents: &serverEvents}
	data := make([]byte, 1<<20)
	rand.Read(data)
	p.transfer(t, data)
	p.close(t)

	for _, side := range []struct {
		name   string
		conn   *Conn
		events *events.Recorder
	}{
		{name: "client", conn: client, events: &clientEvents},
		{name: "server", conn: server, events: &serverEvents},
	} {
		require.NotNil(t, side.conn.mp, side.name)
		frames, numWithPathID := sent1RTTFrames(side.events)
		counts := countSentFrames(frames)
		require.Zero(t, counts.ack, side.name)
		require.NotZero(t, counts.pathAck, side.name)
		require.NotZero(t, numWithPathID, side.name)
		require.Equal(t, map[protocol.PathID]struct{}{0: {}, 1: {}, 2: {}}, counts.pathNewConnIDPaths, side.name)
		require.NotZero(t, countKeyUpdates(side.events), side.name)
	}
}

// When the peer abandons the only path, the connection is closed with NO_VIABLE_PATH.
// The CONNECTION_CLOSE is sent on the path that the last packet was received on,
// and the closing period lasts 3 times the largest PTO among all paths.
func TestMultipathPathAbandonOnlyPathClosesConnection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		unpacker := NewMockUnpacker(mockCtrl)
		tc := newIETFMultipathTestConnection(t, protocol.PerspectiveServer, 2, 2, true,
			connectionOptUnpacker(unpacker),
			connectionOptHandshakeConfirmed(),
		)
		c := tc.conn
		// Simulate a second path with a much larger RTT.
		c.sentPacketHandler.AddPath(1, true)
		c.sentPacketHandler.GetPathRTTStats(1).UpdateRTT(10*time.Second, 0)
		maxPTO := c.sentPacketHandler.MaxPTO(false)
		require.Greater(t, maxPTO, c.rttStats.PTO(false))

		data, err := (&wire.PathAbandonFrame{PathID: 0, ErrorCode: qerr.NoError}).Append(nil, protocol.Version1)
		require.NoError(t, err)
		unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), protocol.PathID(0)).Return(
			protocol.PacketNumber(1), protocol.PacketNumberLen2, protocol.KeyPhaseZero, data, nil,
		)
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(shortHeaderPacket{}, errNothingToPack).AnyTimes()
		var closeErr error
		tc.packer.EXPECT().PackConnectionClose(gomock.Any(), gomock.Any(), protocol.Version1, protocol.PathID(0)).DoAndReturn(
			func(e *qerr.TransportError, _ protocol.ByteCount, _ protocol.Version, _ protocol.PathID) (*coalescedPacket, error) {
				closeErr = e
				b := getPacketBuffer()
				b.Data = append(b.Data, []byte("connection close")...)
				return &coalescedPacket{buffer: b}, nil
			},
		)
		tc.sendConn.EXPECT().Write([]byte("connection close"), gomock.Any(), gomock.Any())
		tc.connRunner.EXPECT().ReplaceWithClosed(gomock.Any(), []byte("connection close"), 3*maxPTO)
		// the connection IDs issued for unused path IDs
		tc.connRunner.EXPECT().ReplaceWithClosed(gomock.Any(), gomock.Nil(), 3*maxPTO)

		errChan := make(chan error, 1)
		go func() { errChan <- c.run() }()
		c.handlePacket(getShortHeaderPacket(t, tc.remoteAddr, tc.srcConnID, 1, []byte("encrypted")))
		synctest.Wait()

		select {
		case err := <-errChan:
			require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.NoViablePathError, FrameType: uint64(wire.FrameTypePathAbandon)})
		default:
			t.Fatal("connection should have been closed")
		}
		require.ErrorIs(t, closeErr, &qerr.TransportError{ErrorCode: qerr.NoViablePathError, FrameType: uint64(wire.FrameTypePathAbandon)})
		require.Empty(t, pathAbandonFrames(queuedFrames(c)))
	})
}

// The frames of the multipath extension are processed in 1-RTT packets received before completion of the
// handshake, for example in 1-RTT packets that couldn't be decrypted when they were received.
func TestMultipathFramesInReplayed1RTTPackets(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	cs := mocks.NewMockCryptoSetup(mockCtrl)
	unpacker := NewMockUnpacker(mockCtrl)
	tc := newIETFMultipathTestConnection(t, protocol.PerspectiveClient, 5, 2, false,
		connectionOptCryptoSetup(cs),
		connectionOptUnpacker(unpacker),
	)
	c := tc.conn
	require.False(t, c.handshakeComplete)
	remoteAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 4321}

	unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), protocol.PathID(0)).Return(
		protocol.PacketNumber(0), protocol.PacketNumberLen(0), protocol.KeyPhaseBit(0), nil, handshake.ErrKeysNotYetAvailable,
	)
	_, err := c.handleOnePacket(getShortHeaderPacket(t, remoteAddr, tc.srcConnID, 1, []byte("encrypted")), 0)
	require.NoError(t, err)
	require.Len(t, c.undecryptablePackets, 1)

	gomock.InOrder(
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventReceived1RTTReadKeys}),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent}),
	)
	require.NoError(t, c.handleHandshakeEvents(monotime.Now()))
	require.Len(t, c.undecryptablePacketsToProcess, 1)

	var data []byte
	for _, f := range []wire.Frame{
		&wire.MaxPathIDFrame{MaximumPathID: 4},
		&wire.PathNewConnectionIDFrame{PathID: 1, ConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4})},
		&wire.PathStatusFrame{PathID: 1, SequenceNumber: 1, Backup: true},
	} {
		data, err = f.Append(data, protocol.Version1)
		require.NoError(t, err)
	}
	unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), protocol.PathID(0)).Return(
		protocol.PacketNumber(1), protocol.PacketNumberLen2, protocol.KeyPhaseZero, data, nil,
	)
	for _, p := range c.undecryptablePacketsToProcess {
		processed, err := c.handleOnePacket(p.receivedPacket, p.checksum)
		require.NoError(t, err)
		require.True(t, processed)
	}
	require.Equal(t, protocol.PathID(4), c.mp.peerMaxPathID)
	require.Len(t, c.peerConnIDs.paths[1].queue, 1)
	require.Equal(t, peerPathStatus{seq: 1, backup: true}, c.mp.pendingPeerStatus[1])
}

func TestMultipathAckFrames(t *testing.T) {
	sendPacket := func(c *Conn, pathID protocol.PathID) protocol.PacketNumber {
		now := monotime.Now()
		pn, _ := c.sentPacketHandler.PeekPacketNumber(pathID, protocol.Encryption1RTT)
		require.Equal(t, pn, c.sentPacketHandler.PopPacketNumber(pathID, protocol.Encryption1RTT))
		c.sentPacketHandler.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []ackhandler.Frame{{Frame: &wire.PingFrame{}}}, protocol.Encryption1RTT, protocol.ECNNon, 100, false, false, pathID)
		return pn
	}

	t.Run("before activation", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		cs := mocks.NewMockCryptoSetup(mockCtrl)
		tc := newIETFMultipathTestConnection(t, protocol.PerspectiveServer, 2, 2, false, connectionOptCryptoSetup(cs), connectionOptHandshakeConfirmed())
		c := tc.conn
		pn := sendPacket(c, 0)

		// A PATH_ACK for path 0 acknowledges packets sent on path 0.
		cs.EXPECT().SetLargest1RTTAckedForPath(protocol.PathID(0), pn, gomock.Any())
		require.NoError(t, handleTestFrame(t, c, &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: pn, Largest: pn}}, HasPathID: true}, protocol.Encryption1RTT))
		require.Zero(t, c.sentPacketHandler.BytesInFlight())

		// Only path 0 can be used before the extension is active.
		err := handleTestFrame(t, c, &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: pn, Largest: pn}}, PathID: 1, HasPathID: true}, protocol.Encryption1RTT)
		require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation, FrameType: uint64(wire.FrameTypePathAck)})
	})

	t.Run("after activation", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		cs := mocks.NewMockCryptoSetup(mockCtrl)
		tc := newIETFMultipathTestConnection(t, protocol.PerspectiveServer, 2, 2, true, connectionOptCryptoSetup(cs), connectionOptHandshakeConfirmed())
		c := tc.conn
		pn1 := sendPacket(c, 0)
		pn2 := sendPacket(c, 0)

		// ACK frames acknowledge packets sent on path 0 (section 2.3 of draft-ietf-quic-multipath-21).
		cs.EXPECT().SetLargest1RTTAckedForPath(protocol.PathID(0), pn1, gomock.Any())
		require.NoError(t, handleTestFrame(t, c, &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: pn1, Largest: pn1}}}, protocol.Encryption1RTT))
		cs.EXPECT().SetLargest1RTTAckedForPath(protocol.PathID(0), pn2, gomock.Any())
		require.NoError(t, handleTestFrame(t, c, &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: pn2, Largest: pn2}}, HasPathID: true}, protocol.Encryption1RTT))
		require.Zero(t, c.sentPacketHandler.BytesInFlight())
	})
}

// With IETF Multipath QUIC, the PATH_ACK frames of a packet are passed to the sent packet handler.
func TestMultipathSentPacketAcks(t *testing.T) {
	now := monotime.Now()
	frames := []ackhandler.Frame{{Frame: &wire.PingFrame{}}}

	t.Run("without multipath", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptSentPacketHandler(sph))
		sph.EXPECT().SentPacket(now, protocol.PacketNumber(5), protocol.PacketNumber(10), gomock.Any(), frames, protocol.Encryption1RTT, protocol.ECNNon, protocol.ByteCount(100), false, false, protocol.PathID(0))
		tc.conn.registerPackedShortHeaderPacket(shortHeaderPacket{
			PacketNumber: 5,
			Ack:          &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 10}}},
			Frames:       frames,
			Length:       100,
		}, protocol.ECNNon, now)
	})

	t.Run("with multipath", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptSentPacketHandler(sph))
		tc.conn.mp = newMultipathState(2, 2)
		tc.conn.mp.active = true
		sph.EXPECT().SentPacket(
			now, protocol.PacketNumber(5), protocol.InvalidPacketNumber, gomock.Any(), frames, protocol.Encryption1RTT, protocol.ECNNon, protocol.ByteCount(100), false, false, protocol.PathID(0),
			ackhandler.PathAck{PathID: 0, LargestAcked: 10},
			ackhandler.PathAck{PathID: 2, LargestAcked: 20},
		)
		tc.conn.registerPackedShortHeaderPacket(shortHeaderPacket{
			PacketNumber: 5,
			Ack:          &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 10}}, HasPathID: true},
			ExtraAcks:    []*wire.AckFrame{{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 20}}, PathID: 2, HasPathID: true}},
			Frames:       frames,
			Length:       100,
			PathID:       0,
		}, protocol.ECNNon, now)
	})
}

// With IETF Multipath QUIC, the PATH_RESPONSE is sent on the path that the PATH_CHALLENGE was received on.
func TestMultipathPathResponse(t *testing.T) {
	for _, pers := range []protocol.Perspective{protocol.PerspectiveClient, protocol.PerspectiveServer} {
		t.Run(pers.String(), func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			unpacker := NewMockUnpacker(mockCtrl)
			tc := newIETFMultipathTestConnection(t, pers, 2, 2, true, connectionOptUnpacker(unpacker), connectionOptHandshakeConfirmed())
			c := tc.conn
			queuedFrames(c)
			data, err := (&wire.PathChallengeFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}).Append(nil, protocol.Version1)
			require.NoError(t, err)
			unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), protocol.PathID(0)).Return(
				protocol.PacketNumber(1), protocol.PacketNumberLen2, protocol.KeyPhaseZero, data, nil,
			)
			remoteAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 4321}
			_, err = c.handleOnePacket(getShortHeaderPacket(t, remoteAddr, tc.srcConnID, 1, []byte("encrypted")), 0)
			require.NoError(t, err)

			require.True(t, c.mp.HasPathFrames(0))
			frames, length := c.mp.AppendPathFrames(nil, 0, protocol.MaxByteCount, protocol.Version1)
			require.Equal(t, []ackhandler.Frame{{Frame: &wire.PathResponseFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}}}, frames)
			require.Equal(t, frames[0].Frame.Length(protocol.Version1), length)
			require.False(t, c.mp.HasPathFrames(0))
			require.Empty(t, queuedFrames(c))
		})
	}
}

// Only a single PATH_RESPONSE frame is sent per packet.
func TestMultipathPathFramesSinglePathResponse(t *testing.T) {
	m := newMultipathState(2, 2)
	m.queuePathFrame(0, ackhandler.Frame{Frame: &wire.PathResponseFrame{Data: [8]byte{1}}})
	m.queuePathFrame(0, ackhandler.Frame{Frame: &wire.PathResponseFrame{Data: [8]byte{2}}})
	// frames for paths that are not open are not queued
	m.queuePathFrame(1, ackhandler.Frame{Frame: &wire.PathResponseFrame{Data: [8]byte{3}}})
	require.False(t, m.HasPathFrames(1))

	frames, _ := m.AppendPathFrames(nil, 0, protocol.MaxByteCount, protocol.Version1)
	require.Equal(t, []ackhandler.Frame{{Frame: &wire.PathResponseFrame{Data: [8]byte{1}}}}, frames)
	// the frame doesn't fit
	frames, length := m.AppendPathFrames(nil, 0, 5, protocol.Version1)
	require.Empty(t, frames)
	require.Zero(t, length)
	frames, _ = m.AppendPathFrames(nil, 0, protocol.MaxByteCount, protocol.Version1)
	require.Equal(t, []ackhandler.Frame{{Frame: &wire.PathResponseFrame{Data: [8]byte{2}}}}, frames)
	require.False(t, m.HasPathFrames(0))
}

// With IETF Multipath QUIC, the destination connection ID of a 1-RTT packet determines its path.
// The client drops packets for paths that it didn't open before they are decrypted.
func TestMultipathReceivePathFromConnectionID(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	unpacker := NewMockUnpacker(mockCtrl)
	var eventRecorder events.Recorder
	tc := newIETFMultipathTestConnection(t, protocol.PerspectiveClient, 2, 2, true,
		connectionOptUnpacker(unpacker),
		connectionOptHandshakeConfirmed(),
		connectionOptTracer(&eventRecorder),
	)
	c := tc.conn
	serverAddr := c.conn.RemoteAddr()
	path1ConnID := c.connIDGenerator.paths[1].active[0]
	id, ok := c.connIDGenerator.PathForConnID(path1ConnID)
	require.True(t, ok)
	require.Equal(t, protocol.PathID(1), id)
	unknownConnID := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef, 0, 1})

	// no calls to the unpacker expected
	for _, connID := range []protocol.ConnectionID{path1ConnID, unknownConnID} {
		processed, err := c.handleOnePacket(getShortHeaderPacket(t, serverAddr, connID, 1, make([]byte, 100)), 0)
		require.NoError(t, err)
		require.False(t, processed)
	}
	var triggers []qlog.PacketDropReason
	for _, ev := range eventRecorder.Events(qlog.PacketDropped{}) {
		triggers = append(triggers, ev.(qlog.PacketDropped).Trigger)
	}
	require.Equal(t, []qlog.PacketDropReason{qlog.PacketDropUnexpectedPacket, qlog.PacketDropUnknownConnectionID}, triggers)

	// packets for path 0 are unpacked, and the qlog event contains the path ID
	data, err := (&wire.PingFrame{}).Append(nil, protocol.Version1)
	require.NoError(t, err)
	unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), protocol.PathID(0)).Return(
		protocol.PacketNumber(1), protocol.PacketNumberLen2, protocol.KeyPhaseZero, data, nil,
	)
	processed, err := c.handleOnePacket(getShortHeaderPacket(t, serverAddr, tc.srcConnID, 1, make([]byte, 100)), 0)
	require.NoError(t, err)
	require.True(t, processed)
	received := eventRecorder.Events(qlog.PacketReceived{})
	require.Len(t, received, 1)
	require.True(t, received[0].(qlog.PacketReceived).Header.HasPathID)
	require.Zero(t, received[0].(qlog.PacketReceived).Header.PathID)
}

// With IETF Multipath QUIC, the timers of the connection use the largest PTO among all paths
// (section 2.6 of draft-ietf-quic-multipath-21).
func TestMultipathMaxPTOTimers(t *testing.T) {
	tc := newIETFMultipathTestConnection(t, protocol.PerspectiveServer, 2, 2, true, connectionOptHandshakeConfirmed())
	c := tc.conn
	c.idleTimeout = time.Second
	c.keepAliveInterval = time.Millisecond
	c.config.KeepAlivePeriod = time.Millisecond
	// Simulate a second path with a much larger RTT.
	c.sentPacketHandler.AddPath(1, true)
	c.sentPacketHandler.GetPathRTTStats(1).UpdateRTT(10*time.Second, 0)
	maxPTO := c.sentPacketHandler.MaxPTO(false)
	require.Greater(t, maxPTO, c.rttStats.PTO(false))
	require.Equal(t, c.sentPacketHandler.MaxPTO(true), c.maxPTO(true))

	require.Equal(t, c.idleTimeoutStartTime().Add(3*c.sentPacketHandler.MaxPTO(true)), c.nextIdleTimeoutTime())
	require.Equal(t, c.lastPacketReceivedTime.Add(c.sentPacketHandler.MaxPTO(true)*3/2), c.nextKeepAliveTime())

	// retired connection IDs are kept for 3 times the largest PTO
	now := monotime.Now()
	for _, f := range []wire.Frame{
		&wire.PathRetireConnectionIDFrame{PathID: 1, SequenceNumber: 0},
		&wire.RetireConnectionIDFrame{SequenceNumber: 0},
	} {
		data, err := f.Append(nil, protocol.Version1)
		require.NoError(t, err)
		_, _, _, err = c.handleFrames(data, protocol.ConnectionID{}, protocol.Encryption1RTT, nil, now)
		require.NoError(t, err)
	}
	require.Len(t, c.connIDGenerator.connIDsToRetire, 2)
	for _, r := range c.connIDGenerator.connIDsToRetire {
		require.Equal(t, now.Add(3*maxPTO), r.t)
	}
}

// Without IETF Multipath QUIC, the timers use the PTO of the connection.
func TestMultipathMaxPTOWithoutMultipath(t *testing.T) {
	tc := newServerTestConnection(t, nil, nil, false)
	c := tc.conn
	c.sentPacketHandler.AddPath(1, true)
	require.Equal(t, c.rttStats.PTO(true), c.maxPTO(true))
	require.Equal(t, c.rttStats.PTO(false), c.maxPTO(false))
}
