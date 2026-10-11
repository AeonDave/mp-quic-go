package utils

import (
	"math/rand/v2"
	"testing"

	"github.com/AeonDave/mp-quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestPathIDSet(t *testing.T) {
	var s PathIDSet
	require.False(t, s.Contains(0))
	require.Zero(t, s.Len())

	s.Add(3)
	s.Add(1)
	require.True(t, s.Contains(1))
	require.False(t, s.Contains(2))
	require.True(t, s.Contains(3))
	require.Equal(t, []pathIDRange{{1, 1}, {3, 3}}, s.ranges)
	// adding 2 merges the ranges
	s.Add(2)
	require.Equal(t, []pathIDRange{{1, 3}}, s.ranges)
	// adding a path ID twice is a no-op
	s.Add(2)
	s.Add(3)
	require.Equal(t, []pathIDRange{{1, 3}}, s.ranges)
	s.Add(0)
	s.Add(4)
	require.Equal(t, []pathIDRange{{0, 4}}, s.ranges)
	s.Add(protocol.MaxPathID)
	require.Equal(t, []pathIDRange{{0, 4}, {protocol.MaxPathID, protocol.MaxPathID}}, s.ranges)
	require.Equal(t, 6, s.Len())
	require.False(t, s.Contains(5))
	require.True(t, s.Contains(protocol.MaxPathID))
}

// The set only stores a range for every gap between the path IDs in it.
func TestPathIDSetCompact(t *testing.T) {
	var s PathIDSet
	// path 0 stays open, all other paths are closed
	for id := protocol.PathID(1); id <= 10000; id++ {
		s.Add(id)
	}
	require.Len(t, s.ranges, 1)
	require.Equal(t, 10000, s.Len())
}

func TestPathIDSetRandom(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for range 100 {
		var s PathIDSet
		m := make(map[protocol.PathID]struct{})
		for range 200 {
			id := protocol.PathID(r.IntN(100))
			s.Add(id)
			m[id] = struct{}{}
		}
		for id := range protocol.PathID(110) {
			_, ok := m[id]
			require.Equal(t, ok, s.Contains(id), "path ID %d", id)
		}
		require.Equal(t, len(m), s.Len())
		for i := 1; i < len(s.ranges); i++ {
			require.Less(t, s.ranges[i-1].end+1, s.ranges[i].start)
		}
	}
}
