package handshake

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/internal/testdata"
	"github.com/AeonDave/mp-quic-go/internal/utils"
	"github.com/AeonDave/mp-quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

type mockClientSessionCache struct {
	cache tls.ClientSessionCache
	puts  chan *tls.ClientSessionState
}

var _ tls.ClientSessionCache = &mockClientSessionCache{}

func newMockClientSessionCache() *mockClientSessionCache {
	return &mockClientSessionCache{
		puts:  make(chan *tls.ClientSessionState, 1),
		cache: tls.NewLRUClientSessionCache(1),
	}
}

func (m *mockClientSessionCache) Get(sessionKey string) (session *tls.ClientSessionState, ok bool) {
	return m.cache.Get(sessionKey)
}

func (m *mockClientSessionCache) Put(sessionKey string, cs *tls.ClientSessionState) {
	m.puts <- cs
	m.cache.Put(sessionKey, cs)
}

func getTLSConfigs() (clientConf, serverConf *tls.Config) {
	clientConf = &tls.Config{
		ServerName: "localhost",
		RootCAs:    testdata.GetRootCA(),
		NextProtos: []string{"crypto-setup"},
	}
	serverConf = testdata.GetTLSConfig()
	serverConf.NextProtos = []string{"crypto-setup"}
	return clientConf, serverConf
}

func TestErrorBeforeClientHelloGeneration(t *testing.T) {
	tlsConf := testdata.GetTLSConfig()
	tlsConf.InsecureSkipVerify = true
	tlsConf.NextProtos = []string{""}
	cl := NewCryptoSetupClient(
		protocol.ConnectionID{},
		&wire.TransportParameters{},
		tlsConf,
		false,
		utils.NewRTTStats(),
		nil,
		utils.DefaultLogger.WithPrefix("client"),
		protocol.Version1,
		nil,
		false,
	)

	err := cl.StartHandshake(context.Background())
	var terr *qerr.TransportError
	require.ErrorAs(t, err, &terr)
	require.Equal(t, uint64(0x100+0x50), uint64(terr.ErrorCode))
	require.ErrorContains(t, err, "tls: invalid NextProtos value")
}

func TestMessageReceivedAtWrongEncryptionLevel(t *testing.T) {
	var token protocol.StatelessResetToken
	server := NewCryptoSetupServer(
		protocol.ConnectionID{},
		&net.UDPAddr{IP: net.IPv6loopback, Port: 1234},
		&net.UDPAddr{IP: net.IPv6loopback, Port: 4321},
		&wire.TransportParameters{StatelessResetToken: &token},
		testdata.GetTLSConfig(),
		false,
		newTestTicketRegister().use,
		utils.NewRTTStats(),
		nil,
		utils.DefaultLogger.WithPrefix("server"),
		protocol.Version1,
		nil,
	)

	require.NoError(t, server.StartHandshake(context.Background()))

	fakeCH := append([]byte{typeClientHello, 0, 0, 6}, []byte("foobar")...)
	// wrong encryption level
	err := server.HandleMessage(fakeCH, protocol.EncryptionHandshake)
	require.ErrorContains(t, err, "tls: handshake data received at wrong level")
}

// The clientEvents and serverEvents contain all events that were not processed by the function,
// i.e. not EventWriteInitialData, EventWriteHandshakeData, EventHandshakeComplete.
func handshake(t *testing.T, client, server CryptoSetup) (clientEvents []Event, clientErr error, serverEvents []Event, serverErr error) {
	t.Helper()
	return handshakeWithEventHandler(t, client, server, nil)
}

// handshakeWithEventHandler runs the handshake.
// onEvent is called for the events that are not processed by the function, as soon as they occur.
func handshakeWithEventHandler(
	t *testing.T,
	client, server CryptoSetup,
	onEvent func(CryptoSetup, Event),
) (clientEvents []Event, clientErr error, serverEvents []Event, serverErr error) {
	t.Helper()
	require.NoError(t, client.StartHandshake(context.Background()))
	require.NoError(t, server.StartHandshake(context.Background()))

	var clientHandshakeComplete, serverHandshakeComplete bool

	for {
	clientLoop:
		for {
			ev := client.NextEvent()
			switch ev.Kind {
			case EventNoEvent:
				break clientLoop
			case EventWriteInitialData:
				serverErr = server.HandleMessage(ev.Data, protocol.EncryptionInitial)
				if serverErr != nil {
					return
				}
			case EventWriteHandshakeData:
				serverErr = server.HandleMessage(ev.Data, protocol.EncryptionHandshake)
				if serverErr != nil {
					return
				}
			case EventHandshakeComplete:
				clientHandshakeComplete = true
			default:
				if onEvent != nil {
					onEvent(client, ev)
				}
				clientEvents = append(clientEvents, ev)
			}
		}

	serverLoop:
		for {
			ev := server.NextEvent()
			switch ev.Kind {
			case EventNoEvent:
				break serverLoop
			case EventWriteInitialData:
				clientErr = client.HandleMessage(ev.Data, protocol.EncryptionInitial)
				if clientErr != nil {
					return
				}
			case EventWriteHandshakeData:
				clientErr = client.HandleMessage(ev.Data, protocol.EncryptionHandshake)
				if clientErr != nil {
					return
				}
			case EventHandshakeComplete:
				serverHandshakeComplete = true
				ticket, err := server.GetSessionTicket()
				require.NoError(t, err)
				if ticket != nil {
					require.NoError(t, client.HandleMessage(ticket, protocol.Encryption1RTT))
				}
			default:
				if onEvent != nil {
					onEvent(server, ev)
				}
				serverEvents = append(serverEvents, ev)
			}
		}

		if clientHandshakeComplete && serverHandshakeComplete {
			break
		}
	}
	return
}

func handshakeWithTLSConf(
	t *testing.T,
	clientConf, serverConf *tls.Config,
	clientRTTStats, serverRTTStats *utils.RTTStats,
	clientTransportParameters, serverTransportParameters *wire.TransportParameters,
	enable0RTT bool,
) (CryptoSetup /* client */, []Event /* more client events */, error, /* client error */
	CryptoSetup /* server */, []Event /* more server events */, error, /* server error */
) {
	t.Helper()
	return handshakeWithTicketRegister(
		t,
		clientConf, serverConf,
		clientRTTStats, serverRTTStats,
		clientTransportParameters, serverTransportParameters,
		enable0RTT,
		newTestTicketRegister().use,
	)
}

// A testTicketRegister records the session tickets used for 0-RTT, and allows using each ticket only once.
type testTicketRegister struct {
	mx     sync.Mutex
	issued map[SessionTicketID]time.Time
}

func newTestTicketRegister() *testTicketRegister {
	return &testTicketRegister{issued: make(map[SessionTicketID]time.Time)}
}

func (r *testTicketRegister) use(id SessionTicketID, issued time.Time) bool {
	r.mx.Lock()
	defer r.mx.Unlock()
	if _, ok := r.issued[id]; ok {
		return false
	}
	r.issued[id] = issued
	return true
}

func handshakeWithTicketRegister(
	t *testing.T,
	clientConf, serverConf *tls.Config,
	clientRTTStats, serverRTTStats *utils.RTTStats,
	clientTransportParameters, serverTransportParameters *wire.TransportParameters,
	enable0RTT bool,
	useTicketFor0RTT func(SessionTicketID, time.Time) bool,
) (CryptoSetup /* client */, []Event /* more client events */, error, /* client error */
	CryptoSetup /* server */, []Event /* more server events */, error, /* server error */
) {
	t.Helper()
	client := NewCryptoSetupClient(
		protocol.ConnectionID{},
		clientTransportParameters,
		clientConf,
		enable0RTT,
		clientRTTStats,
		nil,
		utils.DefaultLogger.WithPrefix("client"),
		protocol.Version1,
		nil,
		false,
	)

	if serverTransportParameters.StatelessResetToken == nil {
		var token protocol.StatelessResetToken
		serverTransportParameters.StatelessResetToken = &token
	}
	server := NewCryptoSetupServer(
		protocol.ConnectionID{},
		&net.UDPAddr{IP: net.IPv6loopback, Port: 1234},
		&net.UDPAddr{IP: net.IPv6loopback, Port: 4321},
		serverTransportParameters,
		serverConf,
		enable0RTT,
		useTicketFor0RTT,
		serverRTTStats,
		nil,
		utils.DefaultLogger.WithPrefix("server"),
		protocol.Version1,
		nil,
	)
	cEvents, cErr, sEvents, sErr := handshake(t, client, server)
	return client, cEvents, cErr, server, sEvents, sErr
}

func TestHandshake(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	_, _, clientErr, _, _, serverErr := handshakeWithTLSConf(
		t,
		clientConf, serverConf,
		utils.NewRTTStats(), utils.NewRTTStats(),
		&wire.TransportParameters{ActiveConnectionIDLimit: 2}, &wire.TransportParameters{ActiveConnectionIDLimit: 2},
		false,
	)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
}

func TestHelloRetryRequest(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	serverConf.CurvePreferences = []tls.CurveID{tls.CurveP384}
	var helloRetryRequest bool
	serverConf.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		helloRetryRequest = info.HelloRetryRequest
		return nil, nil
	}
	_, _, clientErr, _, _, serverErr := handshakeWithTLSConf(
		t,
		clientConf, serverConf,
		utils.NewRTTStats(), utils.NewRTTStats(),
		&wire.TransportParameters{ActiveConnectionIDLimit: 2}, &wire.TransportParameters{ActiveConnectionIDLimit: 2},
		false,
	)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
	require.True(t, helloRetryRequest)
}

func TestWithClientAuth(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{},
		SignatureAlgorithm:    x509.PureEd25519,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	require.NoError(t, err)
	clientCert := tls.Certificate{
		PrivateKey:  priv,
		Certificate: [][]byte{certDER},
	}

	clientConf, serverConf := getTLSConfigs()
	clientConf.Certificates = []tls.Certificate{clientCert}
	serverConf.ClientAuth = tls.RequireAnyClientCert
	_, _, clientErr, _, _, serverErr := handshakeWithTLSConf(
		t,
		clientConf, serverConf,
		utils.NewRTTStats(), utils.NewRTTStats(),
		&wire.TransportParameters{ActiveConnectionIDLimit: 2}, &wire.TransportParameters{ActiveConnectionIDLimit: 2},
		false,
	)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
}

func TestTransportParameters(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	cTransportParameters := &wire.TransportParameters{ActiveConnectionIDLimit: 2, MaxIdleTimeout: 42 * time.Second}
	client := NewCryptoSetupClient(
		protocol.ConnectionID{},
		cTransportParameters,
		clientConf,
		false,
		utils.NewRTTStats(),
		nil,
		utils.DefaultLogger.WithPrefix("client"),
		protocol.Version1,
		nil,
		false,
	)

	var token protocol.StatelessResetToken
	sTransportParameters := &wire.TransportParameters{
		MaxIdleTimeout:          1337 * time.Second,
		StatelessResetToken:     &token,
		ActiveConnectionIDLimit: 2,
	}
	server := NewCryptoSetupServer(
		protocol.ConnectionID{},
		&net.UDPAddr{IP: net.IPv6loopback, Port: 1234},
		&net.UDPAddr{IP: net.IPv6loopback, Port: 4321},
		sTransportParameters,
		serverConf,
		false,
		newTestTicketRegister().use,
		utils.NewRTTStats(),
		nil,
		utils.DefaultLogger.WithPrefix("server"),
		protocol.Version1,
		nil,
	)

	clientEvents, cErr, serverEvents, sErr := handshake(t, client, server)
	require.NoError(t, cErr)
	require.NoError(t, sErr)
	var clientReceivedTransportParameters *wire.TransportParameters
	for _, ev := range clientEvents {
		if ev.Kind == EventReceivedTransportParameters {
			clientReceivedTransportParameters = ev.TransportParameters
		}
	}
	require.NotNil(t, clientReceivedTransportParameters)
	require.Equal(t, 1337*time.Second, clientReceivedTransportParameters.MaxIdleTimeout)

	var serverReceivedTransportParameters *wire.TransportParameters
	for _, ev := range serverEvents {
		if ev.Kind == EventReceivedTransportParameters {
			serverReceivedTransportParameters = ev.TransportParameters
		}
	}
	require.NotNil(t, serverReceivedTransportParameters)
	require.Equal(t, 42*time.Second, serverReceivedTransportParameters.MaxIdleTimeout)
}

func TestNewSessionTicketAtWrongEncryptionLevel(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	client, _, clientErr, _, _, serverErr := handshakeWithTLSConf(
		t,
		clientConf, serverConf,
		utils.NewRTTStats(), utils.NewRTTStats(),
		&wire.TransportParameters{ActiveConnectionIDLimit: 2}, &wire.TransportParameters{ActiveConnectionIDLimit: 2},
		false,
	)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)

	// inject an invalid session ticket
	b := append([]byte{uint8(typeNewSessionTicket), 0, 0, 6}, []byte("foobar")...)
	err := client.HandleMessage(b, protocol.EncryptionHandshake)
	require.ErrorContains(t, err, "tls: handshake data received at wrong level")
}

func TestHandlingNewSessionTicketFails(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	client, _, clientErr, _, _, serverErr := handshakeWithTLSConf(
		t,
		clientConf, serverConf,
		utils.NewRTTStats(), utils.NewRTTStats(),
		&wire.TransportParameters{ActiveConnectionIDLimit: 2}, &wire.TransportParameters{ActiveConnectionIDLimit: 2},
		false,
	)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)

	// inject an invalid session ticket
	b := append([]byte{uint8(typeNewSessionTicket), 0, 0, 6}, []byte("foobar")...)
	err := client.HandleMessage(b, protocol.Encryption1RTT)
	require.IsType(t, &qerr.TransportError{}, err)
	require.True(t, err.(*qerr.TransportError).ErrorCode.IsCryptoError())
}

func TestSessionResumption(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	csc := newMockClientSessionCache()
	clientConf.ClientSessionCache = csc
	client, _, clientErr, server, _, serverErr := handshakeWithTLSConf(
		t,
		clientConf, serverConf,
		utils.NewRTTStats(), utils.NewRTTStats(),
		&wire.TransportParameters{ActiveConnectionIDLimit: 2}, &wire.TransportParameters{ActiveConnectionIDLimit: 2},
		false,
	)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
	select {
	case <-csc.puts:
	case <-time.After(time.Second):
		t.Fatal("didn't receive a session ticket")
	}
	require.False(t, server.ConnectionState().DidResume)
	require.False(t, client.ConnectionState().DidResume)

	clientRTTStats := utils.NewRTTStats()
	serverRTTStats := utils.NewRTTStats()
	client, _, clientErr, server, _, serverErr = handshakeWithTLSConf(
		t,
		clientConf, serverConf,
		clientRTTStats, serverRTTStats,
		&wire.TransportParameters{ActiveConnectionIDLimit: 2}, &wire.TransportParameters{ActiveConnectionIDLimit: 2},
		false,
	)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
	select {
	case <-csc.puts:
	case <-time.After(time.Second):
		t.Fatal("didn't receive a session ticket")
	}
	require.True(t, server.ConnectionState().DidResume)
	require.True(t, client.ConnectionState().DidResume)
}

func TestSessionResumptionDisabled(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	csc := newMockClientSessionCache()
	clientConf.ClientSessionCache = csc
	client, _, clientErr, server, _, serverErr := handshakeWithTLSConf(
		t,
		clientConf, serverConf,
		utils.NewRTTStats(), utils.NewRTTStats(),
		&wire.TransportParameters{ActiveConnectionIDLimit: 2}, &wire.TransportParameters{ActiveConnectionIDLimit: 2},
		false,
	)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
	select {
	case <-csc.puts:
	case <-time.After(time.Second):
		t.Fatal("didn't receive a session ticket")
	}
	require.False(t, server.ConnectionState().DidResume)
	require.False(t, client.ConnectionState().DidResume)

	serverConf.SessionTicketsDisabled = true
	client, _, clientErr, server, _, serverErr = handshakeWithTLSConf(
		t,
		clientConf, serverConf,
		utils.NewRTTStats(), utils.NewRTTStats(),
		&wire.TransportParameters{ActiveConnectionIDLimit: 2}, &wire.TransportParameters{ActiveConnectionIDLimit: 2},
		false,
	)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
	select {
	case <-csc.puts:
		t.Fatal("didn't expect to receive a session ticket")
	case <-time.After(25 * time.Millisecond):
	}
	require.False(t, server.ConnectionState().DidResume)
	require.False(t, client.ConnectionState().DidResume)
}

func Test0RTT(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	csc := newMockClientSessionCache()
	clientConf.ClientSessionCache = csc
	const initialMaxData protocol.ByteCount = 1337
	client, _, clientErr, server, _, serverErr := handshakeWithTLSConf(
		t,
		clientConf, serverConf,
		utils.NewRTTStats(), utils.NewRTTStats(),
		&wire.TransportParameters{ActiveConnectionIDLimit: 2},
		&wire.TransportParameters{ActiveConnectionIDLimit: 2, InitialMaxData: initialMaxData},
		true,
	)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
	select {
	case <-csc.puts:
	case <-time.After(time.Second):
		t.Fatal("didn't receive a session ticket")
	}
	require.False(t, server.ConnectionState().DidResume)
	require.False(t, client.ConnectionState().DidResume)

	client, clientEvents, clientErr, server, serverEvents, serverErr := handshakeWithTLSConf(
		t,
		clientConf, serverConf,
		utils.NewRTTStats(), utils.NewRTTStats(),
		&wire.TransportParameters{ActiveConnectionIDLimit: 2},
		&wire.TransportParameters{ActiveConnectionIDLimit: 2, InitialMaxData: initialMaxData},
		true,
	)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)

	var tp *wire.TransportParameters
	for _, ev := range clientEvents {
		switch ev.Kind {
		case EventRestoredTransportParameters:
			tp = ev.TransportParameters
		}
	}
	require.NotNil(t, tp)
	require.Equal(t, initialMaxData, tp.InitialMaxData)

	var serverReceived0RTTKeys bool
	for _, ev := range serverEvents {
		switch ev.Kind {
		case EventReceived0RTTReadKeys:
			serverReceived0RTTKeys = true
		}
	}
	require.True(t, serverReceived0RTTKeys)

	require.True(t, server.ConnectionState().DidResume)
	require.True(t, client.ConnectionState().DidResume)
	require.True(t, server.ConnectionState().Used0RTT)
	require.True(t, client.ConnectionState().Used0RTT)
}

// A client that receives a single session ticket uses it for 0-RTT twice.
type replayingSessionCache struct {
	mx    sync.Mutex
	state *tls.ClientSessionState
}

func (c *replayingSessionCache) Get(string) (*tls.ClientSessionState, bool) {
	c.mx.Lock()
	defer c.mx.Unlock()
	return c.state, c.state != nil
}

func (c *replayingSessionCache) Put(_ string, state *tls.ClientSessionState) {
	c.mx.Lock()
	defer c.mx.Unlock()
	if c.state == nil {
		c.state = state
	}
}

// A server accepts 0-RTT only once per session ticket (section 9.2 of RFC 9001, section 8.1 of RFC 8446).
// A replayed ClientHello resumes the session without 0-RTT.
func Test0RTTReplay(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	csc := &replayingSessionCache{}
	clientConf.ClientSessionCache = csc
	register := newTestTicketRegister()
	handshakeAndCheck := func(t *testing.T, useTicketFor0RTT func(SessionTicketID, time.Time) bool) (client, server CryptoSetup) {
		t.Helper()
		client, _, clientErr, server, _, serverErr := handshakeWithTicketRegister(
			t,
			clientConf, serverConf,
			utils.NewRTTStats(), utils.NewRTTStats(),
			&wire.TransportParameters{ActiveConnectionIDLimit: 2},
			&wire.TransportParameters{ActiveConnectionIDLimit: 2},
			true,
			useTicketFor0RTT,
		)
		require.NoError(t, clientErr)
		require.NoError(t, serverErr)
		return client, server
	}

	before := time.Now()
	_, server := handshakeAndCheck(t, register.use)
	require.False(t, server.ConnectionState().DidResume)
	require.Empty(t, register.issued)

	client, server := handshakeAndCheck(t, register.use)
	require.True(t, server.ConnectionState().Used0RTT)
	require.True(t, client.ConnectionState().Used0RTT)
	require.Len(t, register.issued, 1)
	for _, issued := range register.issued {
		require.WithinRange(t, issued, before.Add(-time.Microsecond), time.Now())
	}

	// the same session ticket is used again
	client, server = handshakeAndCheck(t, register.use)
	require.True(t, server.ConnectionState().DidResume)
	require.True(t, client.ConnectionState().DidResume)
	require.False(t, server.ConnectionState().Used0RTT)
	require.False(t, client.ConnectionState().Used0RTT)
	require.Len(t, register.issued, 1)

	// without a register, 0-RTT is rejected
	client, server = handshakeAndCheck(t, nil)
	require.True(t, server.ConnectionState().DidResume)
	require.False(t, server.ConnectionState().Used0RTT)
	require.False(t, client.ConnectionState().Used0RTT)
}

func Test0RTTRejectionOnTransportParametersChanged(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	csc := newMockClientSessionCache()
	clientConf.ClientSessionCache = csc
	const initialMaxData protocol.ByteCount = 1337
	client, _, clientErr, server, _, serverErr := handshakeWithTLSConf(
		t,
		clientConf, serverConf,
		utils.NewRTTStats(), utils.NewRTTStats(),
		&wire.TransportParameters{ActiveConnectionIDLimit: 2},
		&wire.TransportParameters{ActiveConnectionIDLimit: 2, InitialMaxData: initialMaxData},
		true,
	)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
	select {
	case <-csc.puts:
	case <-time.After(time.Second):
		t.Fatal("didn't receive a session ticket")
	}
	require.False(t, server.ConnectionState().DidResume)
	require.False(t, client.ConnectionState().DidResume)

	clientRTTStats := utils.NewRTTStats()
	client, clientEvents, clientErr, server, _, serverErr := handshakeWithTLSConf(
		t,
		clientConf, serverConf,
		clientRTTStats, utils.NewRTTStats(),
		&wire.TransportParameters{ActiveConnectionIDLimit: 2},
		&wire.TransportParameters{ActiveConnectionIDLimit: 2, InitialMaxData: initialMaxData - 1},
		true,
	)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)

	var tp *wire.TransportParameters
	for _, ev := range clientEvents {
		switch ev.Kind {
		case EventRestoredTransportParameters:
			tp = ev.TransportParameters
		}
	}
	require.NotNil(t, tp)
	require.Equal(t, initialMaxData, tp.InitialMaxData)

	require.True(t, server.ConnectionState().DidResume)
	require.True(t, client.ConnectionState().DidResume)
	require.False(t, server.ConnectionState().Used0RTT)
	require.False(t, client.ConnectionState().Used0RTT)
}

func TestHandleQUICErrorEvent(t *testing.T) {
	cs := newCryptoSetup(
		protocol.ConnectionID{},
		&wire.TransportParameters{},
		utils.NewRTTStats(),
		nil,
		utils.DefaultLogger,
		protocol.PerspectiveClient,
		protocol.Version1,
	)
	alertErr := fmt.Errorf("handshake failed: %w", tls.AlertError(0x50))
	err := cs.handleEvent(tls.QUICEvent{Kind: tls.QUICErrorEvent, Err: alertErr})
	require.ErrorIs(t, err, alertErr)

	var transportErr *qerr.TransportError
	require.ErrorAs(t, wrapError(err), &transportErr)
	require.Equal(t, qerr.TransportErrorCode(0x100+0x50), transportErr.ErrorCode)
}

func TestEnableMultipath(t *testing.T) {
	t.Run("without HelloRetryRequest", func(t *testing.T) {
		testEnableMultipath(t, false)
	})
	t.Run("with HelloRetryRequest", func(t *testing.T) {
		testEnableMultipath(t, true)
	})
}

func testEnableMultipath(t *testing.T, helloRetryRequest bool) {
	clientConf, serverConf := getTLSConfigs()
	if helloRetryRequest {
		serverConf.CurvePreferences = []tls.CurveID{tls.CurveP384}
	}
	client := NewCryptoSetupClient(
		protocol.ConnectionID{},
		&wire.TransportParameters{ActiveConnectionIDLimit: 2},
		clientConf,
		false,
		utils.NewRTTStats(),
		nil,
		utils.DefaultLogger.WithPrefix("client"),
		protocol.Version1,
		nil,
		false,
	)
	var token protocol.StatelessResetToken
	server := NewCryptoSetupServer(
		protocol.ConnectionID{},
		&net.UDPAddr{IP: net.IPv6loopback, Port: 1234},
		&net.UDPAddr{IP: net.IPv6loopback, Port: 4321},
		&wire.TransportParameters{ActiveConnectionIDLimit: 2, StatelessResetToken: &token},
		serverConf,
		false,
		newTestTicketRegister().use,
		utils.NewRTTStats(),
		nil,
		utils.DefaultLogger.WithPrefix("server"),
		protocol.Version1,
		nil,
	)

	const maxPTO = 1337 * time.Millisecond
	var enabled []CryptoSetup
	_, clientErr, _, serverErr := handshakeWithEventHandler(t, client, server, func(cs CryptoSetup, ev Event) {
		// multipath is enabled when the peer's transport parameters are received
		if ev.Kind == EventReceivedTransportParameters {
			require.NoError(t, cs.EnableMultipath(func() time.Duration { return maxPTO }))
			enabled = append(enabled, cs)
		}
	})
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
	require.ElementsMatch(t, []CryptoSetup{client, server}, enabled)

	for _, cs := range []*cryptoSetup{client.(*cryptoSetup), server.(*cryptoSetup)} {
		require.Equal(t, cs.ConnectionState().CipherSuite, cs.suite.ID)
		require.True(t, cs.aead.multipath)
		require.Equal(t, maxPTO, cs.aead.pto())
	}
}

func TestEnableMultipathWithShortNonce(t *testing.T) {
	cs := newCryptoSetup(
		protocol.ConnectionID{},
		&wire.TransportParameters{},
		utils.NewRTTStats(),
		nil,
		utils.DefaultLogger,
		protocol.PerspectiveClient,
		protocol.Version1,
	)
	// a cipher suite with an 8-byte nonce
	suite := getCipherSuite(tls.TLS_AES_128_GCM_SHA256)
	suite.NonceLen = 8
	cs.suite = suite

	err := cs.EnableMultipath(func() time.Duration { return time.Second })
	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.TransportParameterError, transportErr.ErrorCode)
	require.Equal(t, "cipher suite TLS_AES_128_GCM_SHA256 can't be used with multipath", transportErr.ErrorMessage)
	require.False(t, cs.aead.multipath)
}

func TestEnableMultipathBeforeCipherSuiteNegotiation(t *testing.T) {
	cs := newCryptoSetup(
		protocol.ConnectionID{},
		&wire.TransportParameters{},
		utils.NewRTTStats(),
		nil,
		utils.DefaultLogger,
		protocol.PerspectiveServer,
		protocol.Version1,
	)
	err := cs.EnableMultipath(func() time.Duration { return time.Second })
	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.InternalError, transportErr.ErrorCode)
	require.False(t, cs.aead.multipath)
}

func newSessionTicketMessage(extensions []byte) []byte {
	body := []byte{0, 0, 0x1c, 0x20} // ticket_lifetime
	body = append(body, 1, 2, 3, 4)  // ticket_age_add
	body = append(body, 2, 0xa, 0xb) // ticket_nonce
	body = append(body, 0, 3, 1, 2, 3)
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)
	return append([]byte{typeNewSessionTicket, 0, byte(len(body) >> 8), byte(len(body))}, body...)
}

func earlyDataExtension(maxEarlyDataSize uint32) []byte {
	b := []byte{0, extensionEarlyData, 0, 4}
	return binary.BigEndian.AppendUint32(b, maxEarlyDataSize)
}

// A post-handshake CertificateRequest is a PROTOCOL_VIOLATION (section 4.4 of RFC 9001).
func TestPostHandshakeCertificateRequest(t *testing.T) {
	h := &cryptoSetup{perspective: protocol.PerspectiveClient}
	msg := []byte{typeCertificateRequest, 0, 0, 4, 0, 0, 0, 0}
	// the message is split across two CRYPTO frames
	require.NoError(t, h.checkPostHandshakeMessages(msg[:3]))
	err := h.checkPostHandshakeMessages(msg[3:])
	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.ProtocolViolation, transportErr.ErrorCode)
}

// The max_early_data_size of a NewSessionTicket is 0xffffffff, other values are a PROTOCOL_VIOLATION
// (section 4.6.1 of RFC 9001).
func TestNewSessionTicketEarlyDataSize(t *testing.T) {
	h := &cryptoSetup{perspective: protocol.PerspectiveClient}
	require.NoError(t, h.checkPostHandshakeMessages(newSessionTicketMessage(nil)))
	ticket := newSessionTicketMessage(earlyDataExtension(0xffffffff))
	for i := range ticket {
		require.NoError(t, h.checkPostHandshakeMessages(ticket[i:i+1]))
	}
	require.Nil(t, h.postHandshakeData)

	for _, size := range []uint32{0, 0x1337} {
		h := &cryptoSetup{perspective: protocol.PerspectiveClient}
		err := h.checkPostHandshakeMessages(newSessionTicketMessage(append([]byte{0, 0x2b, 0, 0}, earlyDataExtension(size)...)))
		var transportErr *qerr.TransportError
		require.ErrorAs(t, err, &transportErr)
		require.Equal(t, qerr.ProtocolViolation, transportErr.ErrorCode)
	}
}
