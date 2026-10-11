package handshake

import (
	"crypto/tls"
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/wire"
	"github.com/AeonDave/mp-quic-go/quicvarint"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarshalUnmarshalSessionTicket(t *testing.T) {
	ticket := &sessionTicket{
		Parameters: &wire.TransportParameters{
			InitialMaxStreamDataBidiLocal:  1,
			InitialMaxStreamDataBidiRemote: 2,
			ActiveConnectionIDLimit:        10,
			MaxDatagramFrameSize:           20,
		},
	}
	var t2 sessionTicket
	require.NoError(t, t2.Unmarshal(ticket.Marshal()))
	require.EqualValues(t, 1, t2.Parameters.InitialMaxStreamDataBidiLocal)
	require.EqualValues(t, 2, t2.Parameters.InitialMaxStreamDataBidiRemote)
	require.EqualValues(t, 10, t2.Parameters.ActiveConnectionIDLimit)
	require.EqualValues(t, 20, t2.Parameters.MaxDatagramFrameSize)
}

func TestUnmarshalRefusesTooShortTicket(t *testing.T) {
	err := (&sessionTicket{}).Unmarshal([]byte{})
	require.EqualError(t, err, "failed to read session ticket revision")
}

func TestUnmarshalRefusesUnknownRevision(t *testing.T) {
	b := quicvarint.Append(nil, 1337)
	err := (&sessionTicket{}).Unmarshal(b)
	require.EqualError(t, err, "unknown session ticket revision: 1337")
}

func TestUnmarshal0RTTRefusesInvalidTransportParameters(t *testing.T) {
	b := quicvarint.Append(nil, sessionTicketRevision)
	b = quicvarint.Append(b, uint64(protocol.Version1))
	b = append(b, make([]byte, 16)...) // ID
	b = quicvarint.Append(b, 1234)     // issue time
	b = append(b, []byte("foobar")...)
	err := (&sessionTicket{}).Unmarshal(b)
	require.ErrorContains(t, err, "unmarshaling transport parameters from session ticket failed")
}

// Every session ticket has a random ID and the time it was issued, which are used to accept 0-RTT only once per
// ticket (section 8.1 of RFC 8446).
func TestSessionTicketIDAndIssueTime(t *testing.T) {
	params := &wire.TransportParameters{ActiveConnectionIDLimit: 2, MaxDatagramFrameSize: protocol.InvalidByteCount}
	now := time.Now()
	ticket := newSessionTicket(protocol.Version1, params, now)
	require.NotZero(t, ticket.ID)
	require.NotEqual(t, ticket.ID, newSessionTicket(protocol.Version1, params, now).ID)

	b := ticket.Marshal()
	var t2 sessionTicket
	require.NoError(t, t2.Unmarshal(b))
	require.Equal(t, ticket.ID, t2.ID)
	require.Equal(t, now.UnixMicro(), t2.Issued.UnixMicro())
	require.Equal(t, protocol.Version1, t2.Version)

	// truncated tickets
	_, l, err := parseSessionTicketHeader(b)
	require.NoError(t, err)
	require.EqualError(t, (&sessionTicket{}).Unmarshal(b[:l+15]), "failed to read the session ticket ID")
	require.EqualError(t, (&sessionTicket{}).Unmarshal(b[:l+16]), "failed to read the issue time of the session ticket")
}

func TestSessionTicketVersion(t *testing.T) {
	for _, v := range []protocol.Version{protocol.Version1, protocol.Version2} {
		ticket := &sessionTicket{
			Version:    v,
			Parameters: &wire.TransportParameters{ActiveConnectionIDLimit: 2, MaxDatagramFrameSize: protocol.InvalidByteCount},
		}
		var t2 sessionTicket
		require.NoError(t, t2.Unmarshal(ticket.Marshal()))
		require.Equal(t, v, t2.Version)
	}

	// version too large
	b := quicvarint.Append(nil, sessionTicketRevision)
	b = quicvarint.Append(b, math.MaxUint32+1)
	_, _, err := parseSessionTicketHeader(b)
	require.EqualError(t, err, "failed to read the QUIC version of the session ticket")
	// missing version
	_, _, err = parseSessionTicketHeader(quicvarint.Append(nil, sessionTicketRevision))
	require.EqualError(t, err, "failed to read the QUIC version of the session ticket")
	// tickets of the previous revision don't contain the version
	_, _, err = parseSessionTicketHeader(quicvarint.Append(nil, sessionTicketRevision-1))
	require.EqualError(t, err, fmt.Sprintf("unknown session ticket revision: %d", sessionTicketRevision-1))
}

func TestUnwrapSessionForVersion(t *testing.T) {
	extra := func(v protocol.Version) [][]byte {
		return [][]byte{addSessionStateExtraPrefix((&sessionTicket{
			Version:    v,
			Parameters: &wire.TransportParameters{ActiveConnectionIDLimit: 2, MaxDatagramFrameSize: protocol.InvalidByteCount},
		}).Marshal())}
	}
	for _, tc := range []struct {
		name     string
		extra    [][]byte
		accepted bool
	}{
		{name: "same version", extra: extra(protocol.Version2), accepted: true},
		{name: "other version", extra: extra(protocol.Version1)},
		{name: "no version", extra: [][]byte{addSessionStateExtraPrefix(quicvarint.Append(nil, sessionTicketRevision-1))}},
		{name: "no extra data"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := &tls.SessionState{Extra: tc.extra}
			var called bool
			unwrap := unwrapSessionForVersion(func(identity []byte, _ tls.ConnectionState) (*tls.SessionState, error) {
				called = true
				require.Equal(t, []byte("identity"), identity)
				return state, nil
			}, protocol.Version2)
			s, err := unwrap([]byte("identity"), tls.ConnectionState{})
			require.NoError(t, err)
			require.True(t, called)
			if tc.accepted {
				require.Same(t, state, s)
			} else {
				require.Nil(t, s)
			}
		})
	}

	t.Run("errors", func(t *testing.T) {
		unwrap := unwrapSessionForVersion(func([]byte, tls.ConnectionState) (*tls.SessionState, error) {
			return nil, assert.AnError
		}, protocol.Version2)
		_, err := unwrap(nil, tls.ConnectionState{})
		require.ErrorIs(t, err, assert.AnError)
	})
}

func TestRestrictSessionTicketsToVersionGetConfigForClient(t *testing.T) {
	var unwrapCalled bool
	withUnwrap := &tls.Config{
		UnwrapSession: func([]byte, tls.ConnectionState) (*tls.SessionState, error) {
			unwrapCalled = true
			return &tls.SessionState{}, nil
		},
	}
	withoutUnwrap := &tls.Config{}
	var returnConf *tls.Config
	conf := &tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { return returnConf, nil },
	}
	restricted := restrictSessionTicketsToVersion(conf, protocol.Version1)
	require.NotSame(t, conf, restricted)
	require.Nil(t, conf.UnwrapSession)
	require.NotNil(t, restricted.UnwrapSession)

	// the UnwrapSession callback of a config returned by GetConfigForClient is wrapped
	returnConf = withUnwrap
	c, err := restricted.GetConfigForClient(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.NotSame(t, withUnwrap, c)
	s, err := c.UnwrapSession(nil, tls.ConnectionState{})
	require.NoError(t, err)
	require.True(t, unwrapCalled)
	require.Nil(t, s) // no session ticket data of this module

	// configs without an UnwrapSession callback are returned unmodified
	returnConf = withoutUnwrap
	c, err = restricted.GetConfigForClient(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.Same(t, withoutUnwrap, c)
}

type recordingSessionCache struct {
	mx    sync.Mutex
	cache map[string]*tls.ClientSessionState
	puts  chan string
}

func newRecordingSessionCache() *recordingSessionCache {
	return &recordingSessionCache{cache: make(map[string]*tls.ClientSessionState), puts: make(chan string, 10)}
}

func (c *recordingSessionCache) Get(key string) (*tls.ClientSessionState, bool) {
	c.mx.Lock()
	defer c.mx.Unlock()
	s, ok := c.cache[key]
	return s, ok
}

func (c *recordingSessionCache) Put(key string, state *tls.ClientSessionState) {
	c.mx.Lock()
	c.cache[key] = state
	c.mx.Unlock()
	c.puts <- key
}

func TestSessionTicketsScopedToVersion(t *testing.T) {
	newEndpoints := func(t *testing.T, cache tls.ClientSessionCache, chosen protocol.Version, serverPreferences []protocol.Version) (CryptoSetup, CryptoSetup) {
		clientConf, serverConf := getTLSConfigs()
		clientConf.ClientSessionCache = cache
		// all handshakes use the same session ticket key
		serverConf.SetSessionTicketKeys([][32]byte{{1, 2, 3}})
		e := &versionNegotiationTestEndpoints{
			clientVersion:     chosen,
			clientVersions:    []protocol.Version{chosen, protocol.Version2},
			clientVI:          &wire.VersionInformation{ChosenVersion: chosen, AvailableVersions: protocol.CompatibleVersions([]protocol.Version{chosen, protocol.Version2}, chosen)},
			serverPreferences: serverPreferences,
			serverVI:          &wire.VersionInformation{ChosenVersion: chosen, AvailableVersions: []protocol.Version{protocol.Version2, protocol.Version1}},
			enable0RTT:        true,
			clientConf:        clientConf,
			serverConf:        serverConf,
		}
		return e.newEndpoints()
	}
	handshakeAndGetTicket := func(t *testing.T, cache *recordingSessionCache, chosen protocol.Version, serverPreferences []protocol.Version) (client, server CryptoSetup, key string) {
		t.Helper()
		client, server = newEndpoints(t, cache, chosen, serverPreferences)
		_, clientErr, _, serverErr := handshakeFollowingVersion(t, client, server)
		require.NoError(t, clientErr)
		require.NoError(t, serverErr)
		select {
		case key = <-cache.puts:
		case <-time.After(time.Second):
			t.Fatal("didn't receive a session ticket")
		}
		return client, server, key
	}

	t.Run("version 1", func(t *testing.T) {
		cache := newRecordingSessionCache()
		_, _, key := handshakeAndGetTicket(t, cache, protocol.Version1, nil)
		// the key used by crypto/tls
		require.Equal(t, "localhost", key)
		client, server, _ := handshakeAndGetTicket(t, cache, protocol.Version1, nil)
		require.True(t, client.ConnectionState().DidResume)
		require.True(t, server.ConnectionState().DidResume)
	})

	t.Run("version 2", func(t *testing.T) {
		cache := newRecordingSessionCache()
		_, _, key := handshakeAndGetTicket(t, cache, protocol.Version2, nil)
		require.Equal(t, "localhost|quic-version=0x6b3343cf", key)
		client, server, _ := handshakeAndGetTicket(t, cache, protocol.Version2, nil)
		require.True(t, client.ConnectionState().DidResume)
		require.True(t, server.ConnectionState().DidResume)

		// the client doesn't use the ticket for a connection using version 1
		client, server, _ = handshakeAndGetTicket(t, cache, protocol.Version1, nil)
		require.False(t, client.ConnectionState().DidResume)
		require.False(t, server.ConnectionState().DidResume)
	})

	t.Run("after compatible version negotiation", func(t *testing.T) {
		cache := newRecordingSessionCache()
		client, _, key := handshakeAndGetTicket(t, cache, protocol.Version1, []protocol.Version{protocol.Version2, protocol.Version1})
		require.Equal(t, protocol.Version2, client.(*cryptoSetup).version)
		// the ticket belongs to the Negotiated Version
		require.Equal(t, "localhost|quic-version=0x6b3343cf", key)
		client, server, _ := handshakeAndGetTicket(t, cache, protocol.Version2, nil)
		require.True(t, client.ConnectionState().DidResume)
		require.True(t, server.ConnectionState().DidResume)
		require.True(t, client.ConnectionState().Used0RTT)
		require.True(t, server.ConnectionState().Used0RTT)
	})

	t.Run("server rejects tickets of other versions", func(t *testing.T) {
		cache := newRecordingSessionCache()
		_, _, key := handshakeAndGetTicket(t, cache, protocol.Version2, nil)
		// a client that uses the ticket of version 2 for version 1
		state, ok := cache.Get(key)
		require.True(t, ok)
		cache.Put("localhost", state)
		<-cache.puts
		client, server, _ := handshakeAndGetTicket(t, cache, protocol.Version1, nil)
		require.False(t, client.ConnectionState().DidResume)
		require.False(t, server.ConnectionState().DidResume)
		require.False(t, server.ConnectionState().Used0RTT)
	})
}
