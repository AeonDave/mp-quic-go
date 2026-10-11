package handshake

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/wire"
	"github.com/AeonDave/mp-quic-go/quicvarint"
)

const sessionTicketRevision = 7

// A SessionTicketID identifies a session ticket issued by a server.
// It is used to accept 0-RTT only once per session ticket (see section 8.1 of RFC 8446).
type SessionTicketID [16]byte

type sessionTicket struct {
	// The QUIC version of the connection that the ticket was issued on.
	// Session tickets are specific to a QUIC version (section 5 of RFC 9369).
	Version protocol.Version
	// A random ID, and the time the ticket was issued (with microsecond precision).
	ID         SessionTicketID
	Issued     time.Time
	Parameters *wire.TransportParameters
}

func newSessionTicket(v protocol.Version, params *wire.TransportParameters, now time.Time) *sessionTicket {
	t := &sessionTicket{Version: v, Issued: now, Parameters: params}
	rand.Read(t.ID[:])
	return t
}

func (t *sessionTicket) Marshal() []byte {
	b := make([]byte, 0, 256)
	b = quicvarint.Append(b, sessionTicketRevision)
	b = quicvarint.Append(b, uint64(t.Version))
	b = append(b, t.ID[:]...)
	b = quicvarint.Append(b, uint64(max(t.Issued.UnixMicro(), 0)))
	return t.Parameters.MarshalForSessionTicket(b)
}

func (t *sessionTicket) Unmarshal(b []byte) error {
	v, l, err := parseSessionTicketHeader(b)
	if err != nil {
		return err
	}
	b = b[l:]
	t.Version = v
	if len(b) < len(t.ID) {
		return errors.New("failed to read the session ticket ID")
	}
	b = b[copy(t.ID[:], b):]
	issued, l, err := quicvarint.Parse(b)
	if err != nil {
		return errors.New("failed to read the issue time of the session ticket")
	}
	b = b[l:]
	t.Issued = time.UnixMicro(int64(issued))
	var tp wire.TransportParameters
	if err := tp.UnmarshalFromSessionTicket(b); err != nil {
		return fmt.Errorf("unmarshaling transport parameters from session ticket failed: %s", err.Error())
	}
	t.Parameters = &tp
	return nil
}

const extraPrefix = "quic-go1"

func addSessionStateExtraPrefix(b []byte) []byte {
	return append([]byte(extraPrefix), b...)
}

func findSessionStateExtraData(extras [][]byte) []byte {
	prefix := []byte(extraPrefix)
	for _, extra := range extras {
		if data, ok := bytes.CutPrefix(extra, prefix); ok {
			return data
		}
	}
	return nil
}

// parseSessionTicketHeader parses the revision and the QUIC version of a session ticket.
// It returns the number of bytes consumed.
func parseSessionTicketHeader(b []byte) (protocol.Version, int, error) {
	rev, l, err := quicvarint.Parse(b)
	if err != nil {
		return 0, 0, errors.New("failed to read session ticket revision")
	}
	if rev != sessionTicketRevision {
		return 0, 0, fmt.Errorf("unknown session ticket revision: %d", rev)
	}
	v, l2, err := quicvarint.Parse(b[l:])
	if err != nil || v > math.MaxUint32 {
		return 0, 0, errors.New("failed to read the QUIC version of the session ticket")
	}
	return protocol.Version(v), l + l2, nil
}

// restrictSessionTicketsToVersion makes the server only resume sessions whose session ticket was issued on a
// connection using the QUIC version v, the version of the client's first flight (section 5 of RFC 9369).
// Other tickets are rejected, resulting in a full handshake.
//
// It returns a copy of the config, with an UnwrapSession callback that checks the version.
// If the GetConfigForClient callback of the config returns a config without an UnwrapSession callback,
// crypto/tls decrypts the ticket with keys that can't be accessed here. For these configs, a ticket of another
// version is still used for resumption, but 0-RTT is rejected (see cryptoSetup.handleSessionTicket).
func restrictSessionTicketsToVersion(conf *tls.Config, v protocol.Version) *tls.Config {
	// Workaround for https://github.com/golang/go/issues/60506.
	// This initializes the session tickets _before_ cloning the config.
	_, _ = conf.DecryptTicket(nil, tls.ConnectionState{})
	conf = conf.Clone()
	unwrap := conf.UnwrapSession
	if unwrap == nil {
		unwrap = conf.DecryptTicket
	}
	conf.UnwrapSession = unwrapSessionForVersion(unwrap, v)
	if gcfc := conf.GetConfigForClient; gcfc != nil {
		conf.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			c, err := gcfc(info)
			if c != nil && c.UnwrapSession != nil {
				c = c.Clone()
				c.UnwrapSession = unwrapSessionForVersion(c.UnwrapSession, v)
			}
			return c, err
		}
	}
	return conf
}

func unwrapSessionForVersion(
	unwrap func([]byte, tls.ConnectionState) (*tls.SessionState, error),
	v protocol.Version,
) func([]byte, tls.ConnectionState) (*tls.SessionState, error) {
	return func(identity []byte, cs tls.ConnectionState) (*tls.SessionState, error) {
		state, err := unwrap(identity, cs)
		if err != nil || state == nil {
			return state, err
		}
		ticketVersion, _, err := parseSessionTicketHeader(findSessionStateExtraData(state.Extra))
		if err != nil || ticketVersion != v {
			// reject the ticket: the handshake continues without resumption
			return nil, nil
		}
		return state, nil
	}
}

// A versionedSessionCache stores the client's session tickets by the QUIC version of the connection that received
// them: Clients must not use a session ticket of one version to initiate a connection with another version
// (section 5 of RFC 9369).
// After compatible version negotiation, a ticket belongs to the Negotiated Version. It is used for connections that
// start with that version.
type versionedSessionCache struct {
	tls.ClientSessionCache
	cs *cryptoSetup
}

func (c *versionedSessionCache) Get(key string) (*tls.ClientSessionState, bool) {
	return c.ClientSessionCache.Get(versionedSessionCacheKey(key, c.cs.version))
}

func (c *versionedSessionCache) Put(key string, state *tls.ClientSessionState) {
	c.ClientSessionCache.Put(versionedSessionCacheKey(key, c.cs.version), state)
}

// versionedSessionCacheKey returns the cache key for a QUIC version.
// The key for QUIC version 1 is the key used by crypto/tls, as before tickets were scoped to versions.
func versionedSessionCacheKey(key string, v protocol.Version) string {
	if v == protocol.Version1 {
		return key
	}
	return fmt.Sprintf("%s|quic-version=%#x", key, uint32(v))
}
