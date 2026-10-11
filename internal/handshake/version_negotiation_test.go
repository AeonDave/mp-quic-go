package handshake

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/internal/utils"
	"github.com/AeonDave/mp-quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

type versionNegotiationTestEndpoints struct {
	clientVersion     protocol.Version
	clientVersions    []protocol.Version // the client's preferences
	clientVI          *wire.VersionInformation
	serverPreferences []protocol.Version
	serverVI          *wire.VersionInformation
	enable0RTT        bool
	clientConf        *tls.Config
	serverConf        *tls.Config
}

func (e *versionNegotiationTestEndpoints) newEndpoints() (client, server CryptoSetup) {
	connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	client = NewCryptoSetupClient(
		connID,
		&wire.TransportParameters{ActiveConnectionIDLimit: 2, VersionInformation: e.clientVI},
		e.clientConf,
		e.enable0RTT,
		utils.NewRTTStats(),
		nil,
		utils.DefaultLogger.WithPrefix("client"),
		e.clientVersion,
		e.clientVersions,
		false,
	)
	var token protocol.StatelessResetToken
	server = NewCryptoSetupServer(
		connID,
		&net.UDPAddr{IP: net.IPv6loopback, Port: 1234},
		&net.UDPAddr{IP: net.IPv6loopback, Port: 4321},
		&wire.TransportParameters{ActiveConnectionIDLimit: 2, StatelessResetToken: &token, VersionInformation: e.serverVI},
		e.serverConf,
		e.enable0RTT,
		newTestTicketRegister().use,
		utils.NewRTTStats(),
		nil,
		utils.DefaultLogger.WithPrefix("server"),
		e.clientVersion,
		e.serverPreferences,
	)
	return client, server
}

// handshakeFollowingVersion runs the handshake, and switches the client's version when the server
// switches its version. In a QUIC connection, the client learns the version from the long header of the
// server's Initial packet carrying the ServerHello.
func handshakeFollowingVersion(t *testing.T, client, server CryptoSetup) (clientEvents []Event, clientErr error, serverEvents []Event, serverErr error) {
	t.Helper()
	return handshakeWithEventHandler(t, client, server, func(cs CryptoSetup, ev Event) {
		if cs == server && ev.Kind == EventVersionNegotiated {
			client.SwitchVersion(ev.Version)
		}
	})
}

func requireKeysMatch(t *testing.T, client, server CryptoSetup) {
	t.Helper()
	hdr := []byte("header")
	msg := []byte("lorem ipsum")

	sealer, err := client.GetHandshakeSealer()
	require.NoError(t, err)
	opener, err := server.GetHandshakeOpener()
	require.NoError(t, err)
	opened, err := opener.Open(nil, sealer.Seal(nil, msg, 42, hdr), 42, hdr)
	require.NoError(t, err)
	require.Equal(t, msg, opened)

	oneRTTSealer, err := server.Get1RTTSealer()
	require.NoError(t, err)
	oneRTTOpener, err := client.Get1RTTOpener()
	require.NoError(t, err)
	opened, err = oneRTTOpener.Open(nil, oneRTTSealer.Seal(nil, msg, 42, hdr), monotime.Now(), 42, protocol.KeyPhaseZero, hdr)
	require.NoError(t, err)
	require.Equal(t, msg, opened)
}

func TestCompatibleVersionNegotiation(t *testing.T) {
	t.Run("from version 1 to version 2", func(t *testing.T) {
		testCompatibleVersionNegotiation(t, protocol.Version1, protocol.Version2)
	})
	t.Run("from version 2 to version 1", func(t *testing.T) {
		testCompatibleVersionNegotiation(t, protocol.Version2, protocol.Version1)
	})
}

func testCompatibleVersionNegotiation(t *testing.T, chosen, negotiated protocol.Version) {
	clientConf, serverConf := getTLSConfigs()
	e := &versionNegotiationTestEndpoints{
		clientVersion:     chosen,
		clientVersions:    []protocol.Version{chosen, negotiated},
		clientVI:          &wire.VersionInformation{ChosenVersion: chosen, AvailableVersions: []protocol.Version{chosen, negotiated}},
		serverPreferences: []protocol.Version{negotiated, chosen},
		serverVI:          &wire.VersionInformation{ChosenVersion: chosen, AvailableVersions: []protocol.Version{negotiated, chosen}},
		clientConf:        clientConf,
		serverConf:        serverConf,
	}
	client, server := e.newEndpoints()
	clientEvents, clientErr, serverEvents, serverErr := handshakeFollowingVersion(t, client, server)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)

	// The server switches the version when it receives the ClientHello, before it handles the transport parameters.
	require.Len(t, serverEvents, 4)
	require.Equal(t, Event{Kind: EventVersionNegotiated, Version: negotiated}, serverEvents[0])
	require.Equal(t, EventReceivedTransportParameters, serverEvents[1].Kind)

	var serverParams *wire.TransportParameters
	for _, ev := range clientEvents {
		if ev.Kind == EventReceivedTransportParameters {
			serverParams = ev.TransportParameters
		}
	}
	require.NotNil(t, serverParams)
	require.Equal(t, &wire.VersionInformation{
		ChosenVersion:     negotiated,
		AvailableVersions: []protocol.Version{negotiated, chosen},
	}, serverParams.VersionInformation)

	for _, cs := range []*cryptoSetup{client.(*cryptoSetup), server.(*cryptoSetup)} {
		require.Equal(t, negotiated, cs.version)
		require.Equal(t, negotiated, cs.aead.version)
		require.Equal(t, chosen, cs.chosenVersion)
	}
	requireKeysMatch(t, client, server)
}

func TestCompatibleVersionNegotiationServerKeepsVersion(t *testing.T) {
	for _, tc := range []struct {
		name              string
		serverPreferences []protocol.Version
		clientAvailable   []protocol.Version
	}{
		{name: "no preferences", clientAvailable: []protocol.Version{protocol.Version1, protocol.Version2}},
		{name: "preferring the Chosen Version", serverPreferences: []protocol.Version{protocol.Version1, protocol.Version2}, clientAvailable: []protocol.Version{protocol.Version1, protocol.Version2}},
		{name: "client doesn't offer version 2", serverPreferences: []protocol.Version{protocol.Version2, protocol.Version1}, clientAvailable: []protocol.Version{protocol.Version1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientConf, serverConf := getTLSConfigs()
			e := &versionNegotiationTestEndpoints{
				clientVersion:     protocol.Version1,
				clientVersions:    []protocol.Version{protocol.Version1, protocol.Version2},
				clientVI:          &wire.VersionInformation{ChosenVersion: protocol.Version1, AvailableVersions: tc.clientAvailable},
				serverPreferences: tc.serverPreferences,
				serverVI:          &wire.VersionInformation{ChosenVersion: protocol.Version1, AvailableVersions: []protocol.Version{protocol.Version2, protocol.Version1}},
				clientConf:        clientConf,
				serverConf:        serverConf,
			}
			client, server := e.newEndpoints()
			_, clientErr, serverEvents, serverErr := handshakeFollowingVersion(t, client, server)
			require.NoError(t, clientErr)
			require.NoError(t, serverErr)
			for _, ev := range serverEvents {
				require.NotEqual(t, EventVersionNegotiated, ev.Kind)
			}
			require.Equal(t, protocol.Version1, client.(*cryptoSetup).version)
			require.Equal(t, protocol.Version1, server.(*cryptoSetup).version)
			requireKeysMatch(t, client, server)
		})
	}
}

// The server can't switch versions if it doesn't send the version_information transport parameter.
func TestCompatibleVersionNegotiationWithoutServerVersionInformation(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	e := &versionNegotiationTestEndpoints{
		clientVersion:     protocol.Version1,
		clientVersions:    []protocol.Version{protocol.Version1, protocol.Version2},
		clientVI:          &wire.VersionInformation{ChosenVersion: protocol.Version1, AvailableVersions: []protocol.Version{protocol.Version1, protocol.Version2}},
		serverPreferences: []protocol.Version{protocol.Version2, protocol.Version1},
		clientConf:        clientConf,
		serverConf:        serverConf,
	}
	client, server := e.newEndpoints()
	_, clientErr, _, serverErr := handshakeFollowingVersion(t, client, server)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
	require.Equal(t, protocol.Version1, server.(*cryptoSetup).version)
}

// The server completes the handshake if the client doesn't send the version_information transport parameter.
func TestCompatibleVersionNegotiationWithoutClientVersionInformation(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	e := &versionNegotiationTestEndpoints{
		clientVersion:     protocol.Version1,
		clientVersions:    []protocol.Version{protocol.Version1, protocol.Version2},
		serverPreferences: []protocol.Version{protocol.Version2, protocol.Version1},
		serverVI:          &wire.VersionInformation{ChosenVersion: protocol.Version1, AvailableVersions: []protocol.Version{protocol.Version2, protocol.Version1}},
		clientConf:        clientConf,
		serverConf:        serverConf,
	}
	client, server := e.newEndpoints()
	_, clientErr, _, serverErr := handshakeFollowingVersion(t, client, server)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
	require.Equal(t, protocol.Version1, server.(*cryptoSetup).version)
}

func TestServerRejectsMismatchingChosenVersion(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	e := &versionNegotiationTestEndpoints{
		clientVersion: protocol.Version1,
		// the long header used version 1, but the client claims to have chosen version 2
		clientVI:   &wire.VersionInformation{ChosenVersion: protocol.Version2, AvailableVersions: []protocol.Version{protocol.Version2, protocol.Version1}},
		serverVI:   &wire.VersionInformation{ChosenVersion: protocol.Version1, AvailableVersions: []protocol.Version{protocol.Version1}},
		clientConf: clientConf,
		serverConf: serverConf,
	}
	client, server := e.newEndpoints()
	_, _, _, serverErr := handshakeFollowingVersion(t, client, server)
	require.Equal(t, &qerr.TransportError{
		ErrorCode:    qerr.VersionNegotiationErrorCode,
		ErrorMessage: "client's Chosen Version (v2) doesn't match the version in use (v1)",
	}, serverErr)
}

// A transport parameter that can't be parsed is a TRANSPORT_PARAMETER_ERROR (section 7.4 of RFC 9000),
// and an invalid Version Information is a parsing failure (section 4 of RFC 9368).
func TestInvalidVersionInformationIsTransportParameterError(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	e := &versionNegotiationTestEndpoints{
		clientVersion: protocol.Version1,
		clientVI:      &wire.VersionInformation{ChosenVersion: protocol.Version1, AvailableVersions: []protocol.Version{protocol.Version2}},
		clientConf:    clientConf,
		serverConf:    serverConf,
	}
	client, server := e.newEndpoints()
	_, _, _, serverErr := handshakeFollowingVersion(t, client, server)
	require.Equal(t, &qerr.TransportError{
		ErrorCode:    qerr.TransportParameterError,
		ErrorMessage: "version_information: Chosen Version v1 not contained in Available Versions [v2]",
	}, serverErr)
}

func TestClientValidatesServerVersionInformation(t *testing.T) {
	const (
		v1 = protocol.Version1
		v2 = protocol.Version2
	)
	vi := func(chosen protocol.Version, available ...protocol.Version) *wire.VersionInformation {
		return &wire.VersionInformation{ChosenVersion: chosen, AvailableVersions: available}
	}
	for _, tc := range []struct {
		name           string
		chosen         protocol.Version   // the client's Chosen Version
		negotiated     protocol.Version   // learned from the long header
		versions       []protocol.Version // the client's preferences
		offered        *wire.VersionInformation
		reactedToVN    bool
		serverVI       *wire.VersionInformation
		expectedErrMsg string
	}{
		{
			name:       "valid",
			chosen:     v1,
			negotiated: v1,
			versions:   []protocol.Version{v1, v2},
			offered:    vi(v1, v1, v2),
			serverVI:   vi(v1, v1, v2),
		},
		{
			name:       "valid, after compatible version negotiation",
			chosen:     v1,
			negotiated: v2,
			versions:   []protocol.Version{v1, v2},
			offered:    vi(v1, v1, v2),
			serverVI:   vi(v2, v2),
		},
		{
			name:       "missing",
			chosen:     v1,
			negotiated: v1,
			versions:   []protocol.Version{v1, v2},
			offered:    vi(v1, v1, v2),
		},
		{
			name:           "missing, after switching the version",
			chosen:         v1,
			negotiated:     v2,
			versions:       []protocol.Version{v1, v2},
			offered:        vi(v1, v1, v2),
			expectedErrMsg: "missing version_information after switching to v2",
		},
		{
			name:        "missing, after Version Negotiation, using version 1",
			chosen:      v1,
			negotiated:  v1,
			versions:    []protocol.Version{0x1a2a3a4a, v1},
			offered:     vi(v1, v1),
			reactedToVN: true,
		},
		{
			name:           "missing, after Version Negotiation, using version 2",
			chosen:         v2,
			negotiated:     v2,
			versions:       []protocol.Version{0x1a2a3a4a, v2},
			offered:        vi(v2, v2),
			reactedToVN:    true,
			expectedErrMsg: "missing version_information after Version Negotiation",
		},
		{
			name:           "Chosen Version not offered",
			chosen:         v1,
			negotiated:     v1,
			versions:       []protocol.Version{v1},
			offered:        vi(v1, v1),
			serverVI:       vi(v2, v1, v2),
			expectedErrMsg: "server's Chosen Version (v2) wasn't offered ([v1])",
		},
		{
			name:           "Chosen Version doesn't match the long header",
			chosen:         v1,
			negotiated:     v1,
			versions:       []protocol.Version{v1, v2},
			offered:        vi(v1, v1, v2),
			serverVI:       vi(v2, v1, v2),
			expectedErrMsg: "server's Chosen Version (v2) doesn't match the Negotiated Version (v1)",
		},
		{
			name:           "long header switched, but Chosen Version wasn't",
			chosen:         v1,
			negotiated:     v2,
			versions:       []protocol.Version{v1, v2},
			offered:        vi(v1, v1, v2),
			serverVI:       vi(v1, v1, v2),
			expectedErrMsg: "server's Chosen Version (v1) doesn't match the Negotiated Version (v2)",
		},
		{
			name:        "after Version Negotiation",
			chosen:      v1,
			negotiated:  v1,
			versions:    []protocol.Version{0x1a2a3a4a, v1, v2},
			offered:     vi(v1, v1, v2),
			reactedToVN: true,
			serverVI:    vi(v1, v1, 0x5a6a7a8a),
		},
		{
			// figure 1 of RFC 9368
			name:        "compatible version negotiation after Version Negotiation",
			chosen:      v1,
			negotiated:  v2,
			versions:    []protocol.Version{0x1a2a3a4a, v1, v2},
			offered:     vi(v1, v1, v2),
			reactedToVN: true,
			serverVI:    vi(v2, v2, v1),
		},
		{
			name:           "empty Available Versions after Version Negotiation",
			chosen:         v1,
			negotiated:     v1,
			versions:       []protocol.Version{0x1a2a3a4a, v1},
			offered:        vi(v1, v1),
			reactedToVN:    true,
			serverVI:       vi(v1),
			expectedErrMsg: "empty Available Versions after Version Negotiation",
		},
		{
			// The client prefers version 2, but an attacker forged a Version Negotiation packet only listing version 1.
			name:           "downgrade",
			chosen:         v1,
			negotiated:     v1,
			versions:       []protocol.Version{v2, v1},
			offered:        vi(v1, v1),
			reactedToVN:    true,
			serverVI:       vi(v1, v1, v2),
			expectedErrMsg: "version downgrade detected: attempted v1, server supports [v1 v2]",
		},
		{
			// The server switched to version 2 using compatible version negotiation,
			// revealing that the Version Negotiation packet was forged.
			name:           "downgrade, followed by compatible version negotiation",
			chosen:         v1,
			negotiated:     v2,
			versions:       []protocol.Version{v2, v1},
			offered:        vi(v1, v2, v1),
			reactedToVN:    true,
			serverVI:       vi(v2, v2, v1),
			expectedErrMsg: "version downgrade detected: attempted v1, server supports [v2 v1]",
		},
		{
			// The server supports version 1 and 2, but only version 1 is fully deployed.
			name:        "version not fully deployed",
			chosen:      v1,
			negotiated:  v1,
			versions:    []protocol.Version{v2, v1},
			offered:     vi(v1, v1),
			reactedToVN: true,
			serverVI:    vi(v1, v1),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := newCryptoSetup(
				protocol.ConnectionID{},
				&wire.TransportParameters{VersionInformation: tc.offered},
				utils.NewRTTStats(),
				nil,
				utils.DefaultLogger,
				protocol.PerspectiveClient,
				tc.chosen,
			)
			cs.versions = tc.versions
			cs.reactedToVersionNegotiation = tc.reactedToVN
			if tc.negotiated != tc.chosen {
				cs.SwitchVersion(tc.negotiated)
			}
			err := cs.validateVersionInformation(tc.serverVI)
			if tc.expectedErrMsg == "" {
				require.NoError(t, err)
				return
			}
			require.Equal(t, &qerr.TransportError{
				ErrorCode:    qerr.VersionNegotiationErrorCode,
				ErrorMessage: tc.expectedErrMsg,
			}, err)
		})
	}
}

func TestInitialOpenersDuringCompatibleVersionNegotiation(t *testing.T) {
	connID := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})
	hdr := []byte("header")
	msg := []byte("lorem ipsum")
	sealAndOpen := func(sealer LongHeaderSealer, opener LongHeaderOpener) error {
		_, err := opener.Open(nil, sealer.Seal(nil, msg, 42, hdr), 42, hdr)
		return err
	}

	t.Run("server", func(t *testing.T) {
		server := newCryptoSetup(connID, &wire.TransportParameters{}, utils.NewRTTStats(), nil, utils.DefaultLogger, protocol.PerspectiveServer, protocol.Version1)
		server.switchVersion(protocol.Version2)

		clientSealerV1, _ := NewInitialAEAD(connID, protocol.PerspectiveClient, protocol.Version1)
		clientSealerV2, _ := NewInitialAEAD(connID, protocol.PerspectiveClient, protocol.Version2)
		openerV1, err := server.GetInitialOpener(protocol.Version1)
		require.NoError(t, err)
		require.NoError(t, sealAndOpen(clientSealerV1, openerV1))
		openerV2, err := server.GetInitialOpener(protocol.Version2)
		require.NoError(t, err)
		require.NoError(t, sealAndOpen(clientSealerV2, openerV2))
		require.Error(t, sealAndOpen(clientSealerV1, openerV2))
		_, err = server.GetInitialOpener(0x1234)
		require.ErrorIs(t, err, ErrUnexpectedVersion)

		// the server sends Initial packets using the Negotiated Version
		sealer, err := server.GetInitialSealer()
		require.NoError(t, err)
		_, clientOpenerV2 := NewInitialAEAD(connID, protocol.PerspectiveClient, protocol.Version2)
		require.NoError(t, sealAndOpen(sealer, clientOpenerV2))

		server.DiscardInitialKeys()
		_, err = server.GetInitialOpener(protocol.Version1)
		require.ErrorIs(t, err, ErrKeysDropped)
		_, err = server.GetInitialOpener(protocol.Version2)
		require.ErrorIs(t, err, ErrKeysDropped)
	})

	t.Run("client", func(t *testing.T) {
		client := newCryptoSetup(connID, &wire.TransportParameters{}, utils.NewRTTStats(), nil, utils.DefaultLogger, protocol.PerspectiveClient, protocol.Version1)
		serverSealerV2, _ := NewInitialAEAD(connID, protocol.PerspectiveServer, protocol.Version2)
		opener, err := client.GetInitialOpener(protocol.Version2)
		require.NoError(t, err)
		require.NoError(t, sealAndOpen(serverSealerV2, opener))
		// incompatible versions are rejected
		_, err = client.GetInitialOpener(0x1234)
		require.ErrorIs(t, err, ErrUnexpectedVersion)
		// trying a version doesn't switch the version
		require.Equal(t, protocol.Version1, client.version)
		sealer, err := client.GetInitialSealer()
		require.NoError(t, err)
		_, serverOpenerV1 := NewInitialAEAD(connID, protocol.PerspectiveServer, protocol.Version1)
		require.NoError(t, sealAndOpen(sealer, serverOpenerV1))

		client.SwitchVersion(protocol.Version2)
		require.Equal(t, protocol.Version2, client.version)
		opener, err = client.GetInitialOpener(protocol.Version2)
		require.NoError(t, err)
		require.NoError(t, sealAndOpen(serverSealerV2, opener))
		// After switching, packets using the Chosen Version are not accepted any more.
		_, err = client.GetInitialOpener(protocol.Version1)
		require.ErrorIs(t, err, ErrUnexpectedVersion)
		// The client sends Initial packets using the Negotiated Version.
		sealer, err = client.GetInitialSealer()
		require.NoError(t, err)
		_, serverOpenerV2 := NewInitialAEAD(connID, protocol.PerspectiveServer, protocol.Version2)
		require.NoError(t, sealAndOpen(sealer, serverOpenerV2))
	})

	t.Run("client, after a Retry", func(t *testing.T) {
		client := newCryptoSetup(connID, &wire.TransportParameters{}, utils.NewRTTStats(), nil, utils.DefaultLogger, protocol.PerspectiveClient, protocol.Version1)
		newConnID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
		client.ChangeConnectionID(newConnID)
		client.SwitchVersion(protocol.Version2)
		serverSealer, _ := NewInitialAEAD(newConnID, protocol.PerspectiveServer, protocol.Version2)
		opener, err := client.GetInitialOpener(protocol.Version2)
		require.NoError(t, err)
		require.NoError(t, sealAndOpen(serverSealer, opener))
	})
}

func TestCompatibleVersionNegotiationWith0RTT(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	csc := newMockClientSessionCache()
	clientConf.ClientSessionCache = csc
	e := &versionNegotiationTestEndpoints{
		clientVersion:     protocol.Version1,
		clientVersions:    []protocol.Version{protocol.Version1, protocol.Version2},
		clientVI:          &wire.VersionInformation{ChosenVersion: protocol.Version1, AvailableVersions: []protocol.Version{protocol.Version1, protocol.Version2}},
		serverPreferences: []protocol.Version{protocol.Version1},
		serverVI:          &wire.VersionInformation{ChosenVersion: protocol.Version1, AvailableVersions: []protocol.Version{protocol.Version1, protocol.Version2}},
		enable0RTT:        true,
		clientConf:        clientConf,
		serverConf:        serverConf,
	}
	client, server := e.newEndpoints()
	_, clientErr, _, serverErr := handshakeFollowingVersion(t, client, server)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
	select {
	case <-csc.puts:
	case <-time.After(time.Second):
		t.Fatal("didn't receive a session ticket")
	}

	// resume the session, and switch to version 2
	e.serverPreferences = []protocol.Version{protocol.Version2, protocol.Version1}
	client, server = e.newEndpoints()
	var zeroRTTSealer LongHeaderSealer
	var zeroRTTOpener LongHeaderOpener
	_, clientErr, _, serverErr = handshakeWithEventHandler(t, client, server, func(cs CryptoSetup, ev Event) {
		switch ev.Kind {
		case EventRestoredTransportParameters:
			var err error
			zeroRTTSealer, err = client.Get0RTTSealer()
			require.NoError(t, err)
		case EventReceived0RTTReadKeys:
			var err error
			zeroRTTOpener, err = server.Get0RTTOpener()
			require.NoError(t, err)
		case EventVersionNegotiated:
			client.SwitchVersion(ev.Version)
		}
	})
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
	require.True(t, server.ConnectionState().Used0RTT)
	require.True(t, client.ConnectionState().Used0RTT)
	require.Equal(t, protocol.Version2, client.(*cryptoSetup).version)
	require.Equal(t, protocol.Version2, server.(*cryptoSetup).version)
	requireKeysMatch(t, client, server)

	// 0-RTT packets use the Chosen Version
	require.NotNil(t, zeroRTTSealer)
	require.NotNil(t, zeroRTTOpener)
	hdr := []byte("header")
	opened, err := zeroRTTOpener.Open(nil, zeroRTTSealer.Seal(nil, []byte("0-RTT"), 1, hdr), 1, hdr)
	require.NoError(t, err)
	require.Equal(t, []byte("0-RTT"), opened)
}

// Errors returned when parsing the peer's transport parameters keep their error code,
// e.g. a TRANSPORT_PARAMETER_ERROR (section 7.4 of RFC 9000).
func TestTransportParameterParsingErrorCode(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	e := &versionNegotiationTestEndpoints{
		clientVersion: protocol.Version1,
		clientConf:    clientConf,
		serverConf:    serverConf,
	}
	client, server := e.newEndpoints()
	// a max_udp_payload_size smaller than 1200 is invalid
	client.(*cryptoSetup).conn.SetTransportParameters(
		(&wire.TransportParameters{ActiveConnectionIDLimit: 2, MaxUDPPayloadSize: 1199}).Marshal(protocol.PerspectiveClient),
	)
	_, _, _, serverErr := handshakeFollowingVersion(t, client, server)
	require.Equal(t, &qerr.TransportError{
		ErrorCode:    qerr.TransportParameterError,
		ErrorMessage: "invalid value for max_udp_payload_size: 1199 (minimum 1200)",
	}, serverErr)
}

// The server selects the Negotiated Version using the first ClientHello, and sends its HelloRetryRequest
// using the Negotiated Version.
func TestCompatibleVersionNegotiationWithHelloRetryRequest(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	serverConf.CurvePreferences = []tls.CurveID{tls.CurveP384}
	var helloRetryRequest bool
	serverConf.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		helloRetryRequest = info.HelloRetryRequest
		return nil, nil
	}
	e := &versionNegotiationTestEndpoints{
		clientVersion:     protocol.Version1,
		clientVersions:    []protocol.Version{protocol.Version1, protocol.Version2},
		clientVI:          &wire.VersionInformation{ChosenVersion: protocol.Version1, AvailableVersions: []protocol.Version{protocol.Version1, protocol.Version2}},
		serverPreferences: []protocol.Version{protocol.Version2, protocol.Version1},
		serverVI:          &wire.VersionInformation{ChosenVersion: protocol.Version1, AvailableVersions: []protocol.Version{protocol.Version2, protocol.Version1}},
		clientConf:        clientConf,
		serverConf:        serverConf,
	}
	client, server := e.newEndpoints()
	_, clientErr, serverEvents, serverErr := handshakeFollowingVersion(t, client, server)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
	require.True(t, helloRetryRequest)
	require.Equal(t, Event{Kind: EventVersionNegotiated, Version: protocol.Version2}, serverEvents[0])
	for _, ev := range serverEvents[1:] {
		require.NotEqual(t, EventVersionNegotiated, ev.Kind)
	}
	for _, cs := range []*cryptoSetup{client.(*cryptoSetup), server.(*cryptoSetup)} {
		require.Equal(t, protocol.Version2, cs.version)
		require.Equal(t, protocol.Version1, cs.chosenVersion)
	}
	requireKeysMatch(t, client, server)
}

// The ClientHello is parsed once it was received completely, even if it is split across multiple messages.
func TestCompatibleVersionNegotiationClientHelloSplit(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	e := &versionNegotiationTestEndpoints{
		clientVersion:     protocol.Version1,
		clientVersions:    []protocol.Version{protocol.Version1, protocol.Version2},
		clientVI:          &wire.VersionInformation{ChosenVersion: protocol.Version1, AvailableVersions: []protocol.Version{protocol.Version1, protocol.Version2}},
		serverPreferences: []protocol.Version{protocol.Version2, protocol.Version1},
		serverVI:          &wire.VersionInformation{ChosenVersion: protocol.Version1, AvailableVersions: []protocol.Version{protocol.Version2, protocol.Version1}},
		clientConf:        clientConf,
		serverConf:        serverConf,
	}
	client, server := e.newEndpoints()
	require.NoError(t, client.StartHandshake(context.Background()))
	require.NoError(t, server.StartHandshake(context.Background()))
	ev := client.NextEvent()
	require.Equal(t, EventWriteInitialData, ev.Kind)
	clientHello := ev.Data
	require.Greater(t, len(clientHello), 100)

	for _, chunk := range [][]byte{clientHello[:2], clientHello[2:100], clientHello[100 : len(clientHello)-1]} {
		require.NoError(t, server.HandleMessage(chunk, protocol.EncryptionInitial))
		require.Equal(t, EventNoEvent, server.NextEvent().Kind)
		require.Equal(t, protocol.Version1, server.(*cryptoSetup).version)
	}
	require.NoError(t, server.HandleMessage(clientHello[len(clientHello)-1:], protocol.EncryptionInitial))
	require.Equal(t, Event{Kind: EventVersionNegotiated, Version: protocol.Version2}, server.NextEvent())
	require.Equal(t, protocol.Version2, server.(*cryptoSetup).version)
}

// The second ClientHello sent after a HelloRetryRequest must carry the same Version Information.
func TestServerRejectsChangedVersionInformation(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	e := &versionNegotiationTestEndpoints{
		clientVersion:     protocol.Version1,
		serverPreferences: []protocol.Version{protocol.Version2, protocol.Version1},
		serverVI:          &wire.VersionInformation{ChosenVersion: protocol.Version1, AvailableVersions: []protocol.Version{protocol.Version2, protocol.Version1}},
		clientConf:        clientConf,
		serverConf:        serverConf,
	}
	_, server := e.newEndpoints()
	cs := server.(*cryptoSetup)
	v, err := cs.negotiateVersion(&wire.VersionInformation{
		ChosenVersion:     protocol.Version1,
		AvailableVersions: []protocol.Version{protocol.Version1, protocol.Version2},
	})
	require.NoError(t, err)
	require.Equal(t, protocol.Version2, v)
	cs.switchVersion(v)

	// the same Version Information
	v, err = cs.negotiateVersion(&wire.VersionInformation{
		ChosenVersion:     protocol.Version1,
		AvailableVersions: []protocol.Version{protocol.Version1, protocol.Version2},
	})
	require.NoError(t, err)
	require.Equal(t, protocol.Version2, v)

	_, err = cs.negotiateVersion(&wire.VersionInformation{
		ChosenVersion:     protocol.Version1,
		AvailableVersions: []protocol.Version{protocol.Version1},
	})
	require.Equal(t, &qerr.TransportError{
		ErrorCode:    qerr.VersionNegotiationErrorCode,
		ErrorMessage: "client's Version Information changed after the HelloRetryRequest",
	}, err)
}

// newTestClientHello returns the ClientHello of a client sending the transport parameters.
func newTestClientHello(t testing.TB, params *wire.TransportParameters) []byte {
	t.Helper()
	clientConf, _ := getTLSConfigs()
	client := NewCryptoSetupClient(
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		params,
		clientConf,
		false,
		utils.NewRTTStats(),
		nil,
		utils.DefaultLogger,
		protocol.Version1,
		[]protocol.Version{protocol.Version1},
		false,
	)
	require.NoError(t, client.StartHandshake(context.Background()))
	ev := client.NextEvent()
	require.Equal(t, EventWriteInitialData, ev.Kind)
	return ev.Data
}

func TestClientHelloTransportParameters(t *testing.T) {
	params := &wire.TransportParameters{
		ActiveConnectionIDLimit: 2,
		VersionInformation:      &wire.VersionInformation{ChosenVersion: protocol.Version1, AvailableVersions: []protocol.Version{protocol.Version1}},
	}
	clientHello := newTestClientHello(t, params)

	b, ok := clientHelloTransportParameters(clientHello)
	require.True(t, ok)
	var tp wire.TransportParameters
	require.NoError(t, tp.Unmarshal(b, protocol.PerspectiveClient))
	require.Equal(t, params.VersionInformation, tp.VersionInformation)
	require.Equal(t, params.ActiveConnectionIDLimit, tp.ActiveConnectionIDLimit)

	// truncated messages
	for i := range len(clientHello) {
		_, ok := clientHelloTransportParameters(clientHello[:i])
		require.False(t, ok)
	}
	// not a ClientHello
	msg := slices.Clone(clientHello)
	msg[0] = 2
	_, ok = clientHelloTransportParameters(msg)
	require.False(t, ok)
}

func FuzzClientHelloTransportParameters(f *testing.F) {
	f.Add(newTestClientHello(f, &wire.TransportParameters{
		ActiveConnectionIDLimit: 2,
		VersionInformation:      &wire.VersionInformation{ChosenVersion: protocol.Version1, AvailableVersions: []protocol.Version{protocol.Version1, protocol.Version2}},
	}))
	f.Add([]byte{1, 0, 0, 0})

	f.Fuzz(func(t *testing.T, msg []byte) {
		b, ok := clientHelloTransportParameters(msg)
		if !ok {
			return
		}
		if !bytes.Contains(msg, b) {
			t.Fatal("the transport parameters are not part of the message")
		}
	})
}

// The packet number space of the Initial packets continues when the Initial keys change during compatible version
// negotiation. Packet numbers received with the new keys are decoded relative to the largest packet number received
// with the keys of the previous version.
func TestCompatibleVersionNegotiationInitialPacketNumbers(t *testing.T) {
	const largestPN protocol.PacketNumber = 2138409609
	connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	hdr := []byte("header")

	// receive a packet with the Initial keys of version 1
	receiveVersion1Packet := func(t *testing.T, cs CryptoSetup, sender protocol.Perspective) {
		t.Helper()
		sealer, _ := NewInitialAEAD(connID, sender, protocol.Version1)
		opener, err := cs.GetInitialOpener(protocol.Version1)
		require.NoError(t, err)
		_, err = opener.Open(nil, sealer.Seal(nil, []byte("foobar"), largestPN, hdr), largestPN, hdr)
		require.NoError(t, err)
	}
	requireDecodesNextPacketNumber := func(t *testing.T, cs CryptoSetup) {
		t.Helper()
		opener, err := cs.GetInitialOpener(protocol.Version2)
		require.NoError(t, err)
		require.Equal(t, largestPN+1, opener.DecodePacketNumber((largestPN+1)&0xffff, protocol.PacketNumberLen2))
	}

	clientConf, serverConf := getTLSConfigs()
	e := &versionNegotiationTestEndpoints{
		clientVersion:     protocol.Version1,
		clientVersions:    []protocol.Version{protocol.Version1, protocol.Version2},
		serverPreferences: []protocol.Version{protocol.Version2, protocol.Version1},
		clientConf:        clientConf,
		serverConf:        serverConf,
	}

	t.Run("server", func(t *testing.T) {
		_, server := e.newEndpoints()
		receiveVersion1Packet(t, server, protocol.PerspectiveClient)
		server.(*cryptoSetup).switchVersion(protocol.Version2)
		requireDecodesNextPacketNumber(t, server)
	})

	t.Run("client", func(t *testing.T) {
		client, _ := e.newEndpoints()
		receiveVersion1Packet(t, client, protocol.PerspectiveServer)
		// the opener used for the first packet of another version
		requireDecodesNextPacketNumber(t, client)
		client.SwitchVersion(protocol.Version2)
		requireDecodesNextPacketNumber(t, client)
	})
}

func clientHelloWithSessionID(sessionID []byte) []byte {
	body := []byte{3, 3}                      // legacy_version
	body = append(body, make([]byte, 32)...)  // random
	body = append(body, byte(len(sessionID))) // legacy_session_id
	body = append(body, sessionID...)
	body = append(body, 0, 2, 0x13, 0x01) // cipher_suites
	body = append(body, 1, 0)             // legacy_compression_methods
	body = append(body, 0, 0)             // extensions
	return append([]byte{typeClientHello, 0, byte(len(body) >> 8), byte(len(body))}, body...)
}

// A ClientHello with a non-empty legacy_session_id is a PROTOCOL_VIOLATION (section 8.4 of RFC 9001).
func TestServerRejectsLegacySessionID(t *testing.T) {
	h := &cryptoSetup{perspective: protocol.PerspectiveServer}
	require.NoError(t, h.negotiateVersionFromClientHello(clientHelloWithSessionID(nil)))
	require.True(t, h.parsedClientHello)

	h = &cryptoSetup{perspective: protocol.PerspectiveServer}
	msg := clientHelloWithSessionID(make([]byte, 32))
	require.NoError(t, h.negotiateVersionFromClientHello(msg[:10]))
	err := h.negotiateVersionFromClientHello(msg[10:])
	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.ProtocolViolation, transportErr.ErrorCode)
}
