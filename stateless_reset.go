package quic

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"hash"
	"sync"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
)

type statelessResetter struct {
	mx sync.Mutex
	h  hash.Hash
}

// newStatelessRetter creates a new stateless reset generator.
// It is valid to use a nil key. In that case, a random key will be used.
// This makes is impossible for on-path attackers to shut down established connections.
func newStatelessResetter(key *StatelessResetKey) *statelessResetter {
	var h hash.Hash
	if key != nil {
		h = hmac.New(sha256.New, key[:])
	} else {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		h = hmac.New(sha256.New, b)
	}
	return &statelessResetter{h: h}
}

func (r *statelessResetter) GetStatelessResetToken(connID protocol.ConnectionID) protocol.StatelessResetToken {
	r.mx.Lock()
	defer r.mx.Unlock()

	var token protocol.StatelessResetToken
	r.h.Write(connID.Bytes())
	copy(token[:], r.h.Sum(nil))
	r.h.Reset()
	return token
}

// A resetTokenMap maps the peers' stateless reset tokens to their connections.
// The tokens are stored and looked up as HMAC-SHA256 values computed with a random key, so that the time a lookup
// takes doesn't reveal anything about the stored tokens (section 10.3.1 of RFC 9000).
// It is not safe for concurrent use.
type resetTokenMap struct {
	h hash.Hash
	m map[[16]byte]packetHandler
}

func newResetTokenMap() *resetTokenMap {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return &resetTokenMap{
		h: hmac.New(sha256.New, key),
		m: make(map[[16]byte]packetHandler),
	}
}

func (m *resetTokenMap) key(token protocol.StatelessResetToken) [16]byte {
	var k [16]byte
	m.h.Write(token[:])
	copy(k[:], m.h.Sum(nil))
	m.h.Reset()
	return k
}

func (m *resetTokenMap) Add(token protocol.StatelessResetToken, handler packetHandler) {
	m.m[m.key(token)] = handler
}

func (m *resetTokenMap) Remove(token protocol.StatelessResetToken) {
	delete(m.m, m.key(token))
}

func (m *resetTokenMap) Get(token protocol.StatelessResetToken) (packetHandler, bool) {
	h, ok := m.m[m.key(token)]
	return h, ok
}
