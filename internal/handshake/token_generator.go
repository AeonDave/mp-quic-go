package handshake

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"math"
	"net"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
)

const (
	tokenPrefixIP byte = iota
	tokenPrefixString
)

// MaxTokenAddrs is the maximum number of client addresses that a token sent in a NEW_TOKEN frame can be valid for.
// A server using IETF Multipath QUIC issues tokens that are valid for the most recently validated addresses
// of the client (section 3.1.3 of draft-ietf-quic-multipath-21).
const MaxTokenAddrs = 4

// A Token is derived from the client address and can be used to verify the ownership of this address.
type Token struct {
	IsRetryToken      bool
	SentTime          time.Time
	encodedRemoteAddr []byte
	// other addresses that the token is valid for, only used for tokens sent in NEW_TOKEN frames
	encodedAdditionalAddrs [][]byte
	// only set for tokens sent in NEW_TOKEN frames
	RTT time.Duration
	// only set for retry tokens
	OriginalDestConnectionID protocol.ConnectionID
	RetrySrcConnectionID     protocol.ConnectionID
	// The QUIC version of the connection that the token was issued on.
	// Tokens are specific to a QUIC version (section 5 of RFC 9369).
	Version protocol.Version
}

// ValidateRemoteAddr validates the address, but does not check expiration.
// A token sent in a NEW_TOKEN frame might be valid for multiple addresses.
func (t *Token) ValidateRemoteAddr(addr net.Addr) bool {
	encoded := encodeRemoteAddr(addr)
	if bytes.Equal(encoded, t.encodedRemoteAddr) {
		return true
	}
	for _, a := range t.encodedAdditionalAddrs {
		if bytes.Equal(encoded, a) {
			return true
		}
	}
	return false
}

// token is the struct that is used for ASN1 serialization and deserialization
type token struct {
	IsRetryToken             bool
	RemoteAddr               []byte
	Timestamp                int64
	RTT                      int64 // in mus
	OriginalDestConnectionID []byte
	RetrySrcConnectionID     []byte
	// Additional addresses that a token sent in a NEW_TOKEN frame is valid for.
	// The field is omitted if there are no additional addresses,
	// so that tokens valid for a single address are encoded as before this field was added.
	AdditionalRemoteAddrs [][]byte `asn1:"optional,explicit,tag:0"`
	// The QUIC version. The field is omitted for QUIC version 1,
	// so that tokens for version 1 are encoded as before this field was added.
	Version int64 `asn1:"optional,explicit,tag:1"`
}

func encodeTokenVersion(v protocol.Version) int64 {
	if v == protocol.Version1 {
		return 0
	}
	return int64(v)
}

func decodeTokenVersion(v int64) protocol.Version {
	if v == 0 {
		return protocol.Version1
	}
	return protocol.Version(v)
}

// A TokenGenerator generates tokens
type TokenGenerator struct {
	tokenProtector tokenProtector
}

// NewTokenGenerator initializes a new TokenGenerator
func NewTokenGenerator(key TokenProtectorKey) *TokenGenerator {
	return &TokenGenerator{tokenProtector: *newTokenProtector(key)}
}

// NewRetryToken generates a new token for a Retry for a given source address,
// sent on a connection using the QUIC version v.
func (g *TokenGenerator) NewRetryToken(
	raddr net.Addr,
	origDestConnID protocol.ConnectionID,
	retrySrcConnID protocol.ConnectionID,
	v protocol.Version,
) ([]byte, error) {
	data, err := asn1.Marshal(token{
		IsRetryToken:             true,
		RemoteAddr:               encodeRemoteAddr(raddr),
		OriginalDestConnectionID: origDestConnID.Bytes(),
		RetrySrcConnectionID:     retrySrcConnID.Bytes(),
		Timestamp:                time.Now().UnixNano(),
		Version:                  encodeTokenVersion(v),
	})
	if err != nil {
		return nil, err
	}
	return g.tokenProtector.NewToken(data)
}

// NewToken generates a new token to be sent in a NEW_TOKEN frame on a connection using the QUIC version v.
// The token is valid for raddr, and for up to MaxTokenAddrs-1 additional addresses.
func (g *TokenGenerator) NewToken(raddr net.Addr, rtt time.Duration, v protocol.Version, additionalAddrs ...net.Addr) ([]byte, error) {
	if len(additionalAddrs) >= MaxTokenAddrs {
		return nil, fmt.Errorf("too many addresses for a token: %d", len(additionalAddrs)+1)
	}
	var additional [][]byte
	for _, addr := range additionalAddrs {
		additional = append(additional, encodeRemoteAddr(addr))
	}
	data, err := asn1.Marshal(token{
		RemoteAddr:            encodeRemoteAddr(raddr),
		Timestamp:             time.Now().UnixNano(),
		RTT:                   rtt.Microseconds(),
		AdditionalRemoteAddrs: additional,
		Version:               encodeTokenVersion(v),
	})
	if err != nil {
		return nil, err
	}
	return g.tokenProtector.NewToken(data)
}

// DecodeToken decodes a token
func (g *TokenGenerator) DecodeToken(encrypted []byte) (*Token, error) {
	// if the client didn't send any token, DecodeToken will be called with a nil-slice
	if len(encrypted) == 0 {
		return nil, nil
	}

	data, err := g.tokenProtector.DecodeToken(encrypted)
	if err != nil {
		return nil, err
	}
	t := &token{}
	rest, err := asn1.Unmarshal(data, t)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("rest when unpacking token: %d", len(rest))
	}
	if t.Version < 0 || t.Version > math.MaxUint32 {
		return nil, fmt.Errorf("invalid QUIC version in token: %d", t.Version)
	}
	token := &Token{
		IsRetryToken:      t.IsRetryToken,
		SentTime:          time.Unix(0, t.Timestamp),
		encodedRemoteAddr: t.RemoteAddr,
		Version:           decodeTokenVersion(t.Version),
	}
	if t.IsRetryToken {
		token.OriginalDestConnectionID = protocol.ParseConnectionID(t.OriginalDestConnectionID)
		token.RetrySrcConnectionID = protocol.ParseConnectionID(t.RetrySrcConnectionID)
	} else {
		token.RTT = time.Duration(t.RTT) * time.Microsecond
		if len(t.AdditionalRemoteAddrs) >= MaxTokenAddrs {
			return nil, fmt.Errorf("token valid for too many addresses: %d", len(t.AdditionalRemoteAddrs)+1)
		}
		token.encodedAdditionalAddrs = t.AdditionalRemoteAddrs
	}
	return token, nil
}

// SameTokenAddr says if a token valid for one of the addresses is also valid for the other one.
func SameTokenAddr(a, b net.Addr) bool {
	return bytes.Equal(encodeRemoteAddr(a), encodeRemoteAddr(b))
}

// encodeRemoteAddr encodes a remote address such that it can be saved in the token
func encodeRemoteAddr(remoteAddr net.Addr) []byte {
	if udpAddr, ok := remoteAddr.(*net.UDPAddr); ok {
		return append([]byte{tokenPrefixIP}, udpAddr.IP...)
	}
	return append([]byte{tokenPrefixString}, []byte(remoteAddr.String())...)
}
