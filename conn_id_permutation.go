package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
)

// The number of rounds of the Feistel network.
const connIDPermutationRounds = 8

var errConnIDSpaceExhausted = errors.New("all connection IDs of this length were issued")

// A connIDPermutation generates the connection IDs that a connection issues when the Transport uses the built-in
// connection ID generator. A connection ID is never issued twice on a connection (section 5.1 of RFC 9000):
// the n-th connection ID is the encryption of n with a format-preserving cipher, a Feistel network over the bits of
// the connection ID, using AES with a random key of the connection as the round function. The cipher is a
// permutation of the connection IDs of the length, so distinct counters give distinct connection IDs, without
// remembering the connection IDs issued.
// The connection IDs look random and can't be linked to each other without the key (section 9.5 of RFC 9000).
//
// The connection IDs that the connection didn't generate this way, like the connection ID chosen before the
// connection was created, are checked separately, see connIDGenerator.connIDInUse.
type connIDPermutation struct {
	block   cipher.Block
	connLen int
	next    uint64 // the counter of the next connection ID
}

var _ ConnectionIDGenerator = &connIDPermutation{}

func newConnIDPermutation(connLen int) *connIDPermutation {
	var key [16]byte
	rand.Read(key[:])
	return newConnIDPermutationWithKey(connLen, key)
}

func newConnIDPermutationWithKey(connLen int, key [16]byte) *connIDPermutation {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err) // can't happen for a 16 byte key
	}
	return &connIDPermutation{block: block, connLen: connLen}
}

func (p *connIDPermutation) ConnectionIDLen() int { return p.connLen }

// GenerateConnectionID returns the next connection ID.
// It returns an error once all connection IDs of the length were generated, which only happens for connection IDs
// shorter than 8 bytes.
func (p *connIDPermutation) GenerateConnectionID() (protocol.ConnectionID, error) {
	if p.connLen < 8 && p.next>>(8*p.connLen) != 0 {
		return protocol.ConnectionID{}, errConnIDSpaceExhausted
	}
	b := make([]byte, p.connLen)
	for i, v := 0, p.next; i < len(b) && v > 0; i, v = i+1, v>>8 {
		b[len(b)-1-i] = byte(v)
	}
	p.next++
	return protocol.ParseConnectionID(p.encrypt(b)), nil
}

// encrypt applies the Feistel network to the 8*n bits of b (n = len(b)), which are split into two halves of
// 4*n bits each. Every round replaces the left half by the right half, and the right half by the left half XORed
// with the round function of the right half. This is a permutation for any round function.
func (p *connIDPermutation) encrypt(b []byte) []byte {
	halfBits := uint(4 * len(b))
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), halfBits), big.NewInt(1))
	x := new(big.Int).SetBytes(b)
	left := new(big.Int).Rsh(x, halfBits)
	right := new(big.Int).And(x, mask)
	halfLen := (len(b) + 1) / 2 // the number of bytes needed for a half
	var in, out [aes.BlockSize]byte
	for round := range connIDPermutationRounds {
		// The input of the round function is the round number, the length of the connection ID,
		// and the right half (at most 80 bits for connection IDs of up to 20 bytes).
		clear(in[:])
		in[0] = byte(round)
		in[1] = byte(len(b))
		right.FillBytes(in[2 : 2+halfLen])
		p.block.Encrypt(out[:], in[:])
		f := new(big.Int).SetBytes(out[:halfLen])
		f.And(f, mask)
		left, right = right, f.Xor(f, left)
	}
	x.Lsh(left, halfBits).Or(x, right)
	return x.FillBytes(make([]byte, len(b)))
}
