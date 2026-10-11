package quic

import (
	"math/bits"
	"testing"

	"github.com/AeonDave/mp-quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

// For short connection IDs, all connection IDs of the length are generated exactly once.
func TestConnIDPermutationShortConnIDs(t *testing.T) {
	for _, connLen := range []int{1, 2} {
		p := newConnIDPermutation(connLen)
		require.Equal(t, connLen, p.ConnectionIDLen())
		seen := make(map[protocol.ConnectionID]struct{}, 1<<(8*connLen))
		for range 1 << (8 * connLen) {
			connID, err := p.GenerateConnectionID()
			require.NoError(t, err)
			require.Equal(t, connLen, connID.Len())
			seen[connID] = struct{}{}
		}
		require.Len(t, seen, 1<<(8*connLen))
		_, err := p.GenerateConnectionID()
		require.ErrorIs(t, err, errConnIDSpaceExhausted)
	}
}

func TestConnIDPermutationLengths(t *testing.T) {
	for connLen := 1; connLen <= protocol.MaxConnIDLen; connLen++ {
		p := newConnIDPermutation(connLen)
		n := min(1000, 1<<(8*min(connLen, 3)))
		seen := make(map[protocol.ConnectionID]struct{}, n)
		for range n {
			connID, err := p.GenerateConnectionID()
			require.NoError(t, err)
			require.Equal(t, connLen, connID.Len())
			seen[connID] = struct{}{}
		}
		require.Len(t, seen, n, "connection ID length %d", connLen)
	}
}

// The connection IDs depend on the key, and consecutive connection IDs don't look related.
func TestConnIDPermutationKey(t *testing.T) {
	generate := func(key [16]byte) []protocol.ConnectionID {
		p := newConnIDPermutationWithKey(8, key)
		connIDs := make([]protocol.ConnectionID, 1000)
		for i := range connIDs {
			connID, err := p.GenerateConnectionID()
			require.NoError(t, err)
			connIDs[i] = connID
		}
		return connIDs
	}
	connIDs1 := generate([16]byte{1})
	require.Equal(t, connIDs1, generate([16]byte{1}))
	connIDs2 := generate([16]byte{2})
	var numEqual int
	for i := range connIDs1 {
		if connIDs1[i] == connIDs2[i] {
			numEqual++
		}
	}
	require.Zero(t, numEqual)

	// On average, half of the 64 bits of consecutive connection IDs differ.
	var differentBits int
	for i := 1; i < len(connIDs1); i++ {
		a, b := connIDs1[i-1].Bytes(), connIDs1[i].Bytes()
		for j := range a {
			differentBits += bits.OnesCount8(a[j] ^ b[j])
		}
	}
	avg := float64(differentBits) / float64(len(connIDs1)-1)
	require.InDelta(t, 32, avg, 2)
}
