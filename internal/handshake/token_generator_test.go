package handshake

import (
	"crypto/rand"
	"encoding/asn1"
	"net"
	"testing"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func newTokenGenerator(t *testing.T) *TokenGenerator {
	var key TokenProtectorKey
	_, err := rand.Read(key[:])
	require.NoError(t, err)
	return NewTokenGenerator(key)
}

func TestTokenGeneratorNilTokens(t *testing.T) {
	tokenGen := newTokenGenerator(t)
	nilToken, err := tokenGen.DecodeToken(nil)
	require.NoError(t, err)
	require.Nil(t, nilToken)
}

func TestTokenGeneratorValidToken(t *testing.T) {
	tokenGen := newTokenGenerator(t)

	addr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}
	connID1 := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})
	connID2 := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xc0, 0xde})
	tokenEnc, err := tokenGen.NewRetryToken(addr, connID1, connID2, protocol.Version1)
	require.NoError(t, err)
	decodedToken, err := tokenGen.DecodeToken(tokenEnc)
	require.NoError(t, err)
	require.True(t, decodedToken.ValidateRemoteAddr(addr))
	require.False(t, decodedToken.ValidateRemoteAddr(&net.UDPAddr{IP: net.IPv4(192, 168, 0, 2), Port: 1337}))
	require.WithinDuration(t, time.Now(), decodedToken.SentTime, 100*time.Millisecond)
	require.Equal(t, connID1, decodedToken.OriginalDestConnectionID)
	require.Equal(t, connID2, decodedToken.RetrySrcConnectionID)
}

func TestTokenGeneratorRejectsInvalidTokens(t *testing.T) {
	tokenGen := newTokenGenerator(t)

	_, err := tokenGen.DecodeToken([]byte("invalid token"))
	require.ErrorContains(t, err, "too short")
}

func TestTokenGeneratorDecodingFailed(t *testing.T) {
	tokenGen := newTokenGenerator(t)

	invalidToken, err := tokenGen.tokenProtector.NewToken([]byte("foobar"))
	require.NoError(t, err)
	_, err = tokenGen.DecodeToken(invalidToken)
	require.ErrorContains(t, err, "asn1")
}

func TestTokenGeneratorAdditionalPayload(t *testing.T) {
	tokenGen := newTokenGenerator(t)

	tok, err := asn1.Marshal(token{RemoteAddr: []byte("foobar")})
	require.NoError(t, err)
	tok = append(tok, []byte("rest")...)
	enc, err := tokenGen.tokenProtector.NewToken(tok)
	require.NoError(t, err)
	_, err = tokenGen.DecodeToken(enc)
	require.EqualError(t, err, "rest when unpacking token: 4")
}

func TestTokenGeneratorEmptyTokens(t *testing.T) {
	tokenGen := newTokenGenerator(t)

	emptyTok, err := asn1.Marshal(token{RemoteAddr: []byte("")})
	require.NoError(t, err)
	emptyEnc, err := tokenGen.tokenProtector.NewToken(emptyTok)
	require.NoError(t, err)
	_, err = tokenGen.DecodeToken(emptyEnc)
	require.NoError(t, err)
}

func TestTokenGeneratorIPv6(t *testing.T) {
	tokenGen := newTokenGenerator(t)

	addresses := []string{
		"2001:db8::68",
		"2001:0000:4136:e378:8000:63bf:3fff:fdd2",
		"2001::1",
		"ff01:0:0:0:0:0:0:2",
	}
	for _, addr := range addresses {
		ip := net.ParseIP(addr)
		require.NotNil(t, ip)
		raddr := &net.UDPAddr{IP: ip, Port: 1337}
		tokenEnc, err := tokenGen.NewRetryToken(raddr, protocol.ConnectionID{}, protocol.ConnectionID{}, protocol.Version1)
		require.NoError(t, err)
		token, err := tokenGen.DecodeToken(tokenEnc)
		require.NoError(t, err)
		require.True(t, token.ValidateRemoteAddr(raddr))
		require.WithinDuration(t, time.Now(), token.SentTime, 100*time.Millisecond)
	}
}

func TestTokenGeneratorNonUDPAddr(t *testing.T) {
	tokenGen := newTokenGenerator(t)

	raddr := &net.TCPAddr{IP: net.IPv4(192, 168, 13, 37), Port: 1337}
	tokenEnc, err := tokenGen.NewRetryToken(raddr, protocol.ConnectionID{}, protocol.ConnectionID{}, protocol.Version1)
	require.NoError(t, err)
	token, err := tokenGen.DecodeToken(tokenEnc)
	require.NoError(t, err)
	require.True(t, token.ValidateRemoteAddr(raddr))
	require.False(t, token.ValidateRemoteAddr(&net.TCPAddr{IP: net.IPv4(192, 168, 13, 37), Port: 1338}))
	require.WithinDuration(t, time.Now(), token.SentTime, 100*time.Millisecond)
}

// legacyToken is the encoding of tokens before tokens could be valid for multiple addresses.
type legacyToken struct {
	IsRetryToken             bool
	RemoteAddr               []byte
	Timestamp                int64
	RTT                      int64
	OriginalDestConnectionID []byte
	RetrySrcConnectionID     []byte
}

// A token for a single address is encoded exactly like before tokens could be valid for multiple addresses.
func TestTokenGeneratorSingleAddressEncoding(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}
	encoded, err := asn1.Marshal(token{RemoteAddr: encodeRemoteAddr(addr), Timestamp: 1234567890, RTT: 4242})
	require.NoError(t, err)
	legacy, err := asn1.Marshal(legacyToken{RemoteAddr: encodeRemoteAddr(addr), Timestamp: 1234567890, RTT: 4242})
	require.NoError(t, err)
	require.Equal(t, legacy, encoded)

	// the same applies to tokens created by NewToken
	tokenGen := newTokenGenerator(t)
	tokenEnc, err := tokenGen.NewToken(addr, 1337*time.Microsecond, protocol.Version1)
	require.NoError(t, err)
	data, err := tokenGen.tokenProtector.DecodeToken(tokenEnc)
	require.NoError(t, err)
	var lt legacyToken
	rest, err := asn1.Unmarshal(data, &lt)
	require.NoError(t, err)
	require.Empty(t, rest)
	reencoded, err := asn1.Marshal(lt)
	require.NoError(t, err)
	require.Equal(t, data, reencoded)
	require.Equal(t, encodeRemoteAddr(addr), lt.RemoteAddr)
	require.Equal(t, int64(1337), lt.RTT)
}

// Tokens issued before tokens could be valid for multiple addresses are still accepted.
func TestTokenGeneratorLegacyToken(t *testing.T) {
	tokenGen := newTokenGenerator(t)
	addr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}
	data, err := asn1.Marshal(legacyToken{RemoteAddr: encodeRemoteAddr(addr), Timestamp: time.Now().UnixNano(), RTT: 1000})
	require.NoError(t, err)
	tokenEnc, err := tokenGen.tokenProtector.NewToken(data)
	require.NoError(t, err)
	tok, err := tokenGen.DecodeToken(tokenEnc)
	require.NoError(t, err)
	require.False(t, tok.IsRetryToken)
	require.True(t, tok.ValidateRemoteAddr(addr))
	require.False(t, tok.ValidateRemoteAddr(&net.UDPAddr{IP: net.IPv4(192, 168, 0, 2), Port: 1337}))
	require.Equal(t, time.Millisecond, tok.RTT)
}

// A server using IETF Multipath QUIC issues tokens that are valid for multiple addresses of the client
// (section 3.1.3 of draft-ietf-quic-multipath-21).
func TestTokenGeneratorMultipleAddresses(t *testing.T) {
	tokenGen := newTokenGenerator(t)
	addrs := []net.Addr{
		&net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337},
		&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1338},
		&net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1339},
		&net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 1340},
	}
	tokenEnc, err := tokenGen.NewToken(addrs[0], 10*time.Millisecond, protocol.Version1, addrs[1:]...)
	require.NoError(t, err)
	tok, err := tokenGen.DecodeToken(tokenEnc)
	require.NoError(t, err)
	require.False(t, tok.IsRetryToken)
	require.Equal(t, 10*time.Millisecond, tok.RTT)
	for _, addr := range addrs {
		require.True(t, tok.ValidateRemoteAddr(addr), "address %s", addr)
	}
	// the port is not part of the token
	require.True(t, tok.ValidateRemoteAddr(&net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 1}))
	require.False(t, tok.ValidateRemoteAddr(&net.UDPAddr{IP: net.IPv4(10, 0, 0, 3), Port: 1340}))

	// A decoder that doesn't know about the additional addresses ignores them.
	data, err := tokenGen.tokenProtector.DecodeToken(tokenEnc)
	require.NoError(t, err)
	var lt legacyToken
	rest, err := asn1.Unmarshal(data, &lt)
	require.NoError(t, err)
	require.Empty(t, rest)
	require.Equal(t, encodeRemoteAddr(addrs[0]), lt.RemoteAddr)

	// a token can't be valid for more than MaxTokenAddrs addresses
	_, err = tokenGen.NewToken(addrs[0], 0, protocol.Version1, append(addrs[1:], &net.UDPAddr{IP: net.IPv4(10, 0, 0, 3), Port: 1})...)
	require.EqualError(t, err, "too many addresses for a token: 5")
}

func TestTokenGeneratorTooManyAddresses(t *testing.T) {
	tokenGen := newTokenGenerator(t)
	addr := encodeRemoteAddr(&net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1})
	data, err := asn1.Marshal(token{RemoteAddr: addr, AdditionalRemoteAddrs: [][]byte{addr, addr, addr, addr}})
	require.NoError(t, err)
	tokenEnc, err := tokenGen.tokenProtector.NewToken(data)
	require.NoError(t, err)
	_, err = tokenGen.DecodeToken(tokenEnc)
	require.EqualError(t, err, "token valid for too many addresses: 5")
}

func TestTokenGeneratorSameTokenAddr(t *testing.T) {
	require.True(t, SameTokenAddr(&net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1}, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 2}))
	require.False(t, SameTokenAddr(&net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1}, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 1}))
}

func BenchmarkTokenGeneratorDecodeToken(b *testing.B) {
	b.ReportAllocs()

	var key TokenProtectorKey
	_, err := rand.Read(key[:])
	require.NoError(b, err)
	tokenGen := NewTokenGenerator(key)
	addr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}
	connID1 := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})
	connID2 := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
	tokenEnc, err := tokenGen.NewRetryToken(addr, connID1, connID2, protocol.Version1)
	require.NoError(b, err)

	for b.Loop() {
		if _, err := tokenGen.DecodeToken(tokenEnc); err != nil {
			b.Fatal(err)
		}
	}
}

// Tokens are specific to a QUIC version (section 5 of RFC 9369).
func TestTokenGeneratorVersion(t *testing.T) {
	tokenGen := newTokenGenerator(t)
	addr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}
	for _, v := range []protocol.Version{protocol.Version1, protocol.Version2} {
		enc, err := tokenGen.NewToken(addr, time.Millisecond, v)
		require.NoError(t, err)
		tok, err := tokenGen.DecodeToken(enc)
		require.NoError(t, err)
		require.Equal(t, v, tok.Version)

		enc, err = tokenGen.NewRetryToken(addr, protocol.ParseConnectionID([]byte{1, 2, 3, 4}), protocol.ParseConnectionID([]byte{5, 6, 7, 8}), v)
		require.NoError(t, err)
		tok, err = tokenGen.DecodeToken(enc)
		require.NoError(t, err)
		require.True(t, tok.IsRetryToken)
		require.Equal(t, v, tok.Version)
	}

	// invalid versions are rejected
	data, err := asn1.Marshal(token{RemoteAddr: encodeRemoteAddr(addr), Timestamp: time.Now().UnixNano(), Version: -1})
	require.NoError(t, err)
	enc, err := tokenGen.tokenProtector.NewToken(data)
	require.NoError(t, err)
	_, err = tokenGen.DecodeToken(enc)
	require.EqualError(t, err, "invalid QUIC version in token: -1")
}
