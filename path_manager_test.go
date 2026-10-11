package quic

import (
	"crypto/rand"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/utils"
	"github.com/AeonDave/mp-quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

// The path is established by receiving a non-probing packet.
// The first non-probing packet is received after path validation has completed.
// This is the typical scenario when the client initiates connection migration.
func TestPathManagerIntentionalMigration(t *testing.T) {
	connIDs := []protocol.ConnectionID{
		protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
		protocol.ParseConnectionID([]byte{2, 3, 4, 5, 6, 7, 8, 9}),
		protocol.ParseConnectionID([]byte{3, 4, 5, 6, 7, 8, 9, 0}),
	}
	var retiredConnIDs []protocol.ConnectionID
	pm := newPathManager(
		func(id pathID) (protocol.ConnectionID, bool) { return connIDs[id], true },
		func(id pathID) { retiredConnIDs = append(retiredConnIDs, connIDs[id]) },
		func() time.Duration { return time.Second },
		utils.DefaultLogger,
	)
	now := monotime.Now()
	connID, frames, shouldSwitch := pm.HandlePacket(
		&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000},
		now,
		&wire.PathChallengeFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}},
		false,
	)
	require.Equal(t, connIDs[0], connID)
	require.Len(t, frames, 2)
	require.IsType(t, &wire.PathChallengeFrame{}, frames[0].Frame)
	pc1 := frames[0].Frame.(*wire.PathChallengeFrame)
	require.NotZero(t, pc1.Data)
	require.NotEqual(t, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, pc1.Data)
	require.IsType(t, &wire.PathResponseFrame{}, frames[1].Frame)
	require.Equal(t, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, frames[1].Frame.(*wire.PathResponseFrame).Data)
	require.False(t, shouldSwitch)

	// receiving another packet for the same path doesn't trigger another PATH_CHALLENGE
	connID, frames, shouldSwitch = pm.HandlePacket(
		&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000},
		now,
		nil,
		false,
	)
	require.Zero(t, connID)
	require.Empty(t, frames)
	require.False(t, shouldSwitch)

	// receiving a packet for a different path triggers another PATH_CHALLENGE
	addr2 := &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 1000}
	connID, frames, shouldSwitch = pm.HandlePacket(addr2, now, nil, false)
	require.Equal(t, connIDs[1], connID)
	require.Len(t, frames, 1)
	require.IsType(t, &wire.PathChallengeFrame{}, frames[0].Frame)
	pc2 := frames[0].Frame.(*wire.PathChallengeFrame)
	require.NotEqual(t, pc1.Data, pc2.Data)
	require.False(t, shouldSwitch)

	// acknowledging the PATH_CHALLENGE doesn't confirm the path
	for _, f := range frames {
		f.Handler.OnAcked(f.Frame)
	}
	connID, frames, shouldSwitch = pm.HandlePacket(
		&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000},
		now,
		nil,
		false,
	)
	require.Zero(t, connID)
	require.Empty(t, frames)
	require.False(t, shouldSwitch)

	// receiving a PATH_RESPONSE for the second path confirms the path
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: pc2.Data})
	connID, frames, shouldSwitch = pm.HandlePacket(addr2, now, nil, false)
	require.Zero(t, connID)
	require.Empty(t, frames)
	require.False(t, shouldSwitch) // no non-probing packet received yet
	require.Empty(t, retiredConnIDs)

	// confirming the path doesn't remove other paths
	connID, frames, shouldSwitch = pm.HandlePacket(
		&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000},
		now,
		nil,
		false,
	)
	require.Zero(t, connID)
	require.Empty(t, frames)
	require.False(t, shouldSwitch)

	// now receive a non-probing packet for the new path
	connID, frames, shouldSwitch = pm.HandlePacket(
		&net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 1000},
		now,
		nil,
		true,
	)
	require.Zero(t, connID)
	require.Empty(t, frames)
	require.True(t, shouldSwitch)

	// now switch to the new path
	pm.SwitchToPath(&net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 1000})

	// switching to the path removes other paths
	connID, frames, shouldSwitch = pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}, now, nil, false)
	require.Equal(t, connIDs[2], connID)
	require.NotEmpty(t, frames)
	require.NotEqual(t, frames[0].Frame.(*wire.PathChallengeFrame).Data, pc1.Data)
	require.False(t, shouldSwitch)
	require.Equal(t, []protocol.ConnectionID{connIDs[0]}, retiredConnIDs)
}

func TestPathManagerMultipleProbes(t *testing.T) {
	connIDs := []protocol.ConnectionID{
		protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
	}
	pm := newPathManager(
		func(id pathID) (protocol.ConnectionID, bool) { return connIDs[id], true },
		func(id pathID) {},
		func() time.Duration { return time.Second },
		utils.DefaultLogger,
	)
	now := monotime.Now()
	// first receive a packet without a PATH_CHALLENGE
	connID, frames, shouldSwitch := pm.HandlePacket(
		&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000},
		now,
		nil,
		false,
	)
	require.Equal(t, connIDs[0], connID)
	require.Len(t, frames, 1)
	require.IsType(t, &wire.PathChallengeFrame{}, frames[0].Frame)
	require.False(t, shouldSwitch)

	// now receive a packet on the same path with a PATH_CHALLENGE
	connID, frames, shouldSwitch = pm.HandlePacket(
		&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000},
		now,
		&wire.PathChallengeFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}},
		false,
	)
	require.Equal(t, connIDs[0], connID)
	require.Len(t, frames, 1)
	require.Equal(t, &wire.PathResponseFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}, frames[0].Frame)
	require.False(t, shouldSwitch)

	// now receive another packet on the same path with a PATH_RESPONSE
	connID, frames, shouldSwitch = pm.HandlePacket(
		&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000},
		now,
		&wire.PathChallengeFrame{Data: [8]byte{8, 7, 6, 5, 4, 3, 2, 1}},
		false,
	)
	require.Equal(t, connIDs[0], connID)
	require.Len(t, frames, 1)
	require.Equal(t, &wire.PathResponseFrame{Data: [8]byte{8, 7, 6, 5, 4, 3, 2, 1}}, frames[0].Frame)
	require.False(t, shouldSwitch)

	// lose the response packet
	frames[0].Handler.OnLost(frames[0].Frame)
}

// The first packet received on the new path is already a non-probing packet.
// We still need to validate the new path, but we can then switch over immediately.
// This is the typical scenario when a NAT rebinding happens.
func TestPathManagerNATRebinding(t *testing.T) {
	connIDs := []protocol.ConnectionID{
		protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
	}
	var retiredConnIDs []protocol.ConnectionID
	pm := newPathManager(
		func(id pathID) (protocol.ConnectionID, bool) { return connIDs[id], true },
		func(id pathID) { retiredConnIDs = append(retiredConnIDs, connIDs[id]) },
		func() time.Duration { return time.Second },
		utils.DefaultLogger,
	)

	now := monotime.Now()
	connID, frames, shouldSwitch := pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}, now, nil, true)
	require.Equal(t, connIDs[0], connID)
	require.Len(t, frames, 1)
	require.IsType(t, &wire.PathChallengeFrame{}, frames[0].Frame)
	pc1 := frames[0].Frame.(*wire.PathChallengeFrame)
	require.NotZero(t, pc1.Data)
	require.False(t, shouldSwitch)

	// receiving a PATH_RESPONSE for the second path confirms the path
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: pc1.Data})
	// we now switch to the new path, as soon as the next packet on that path is received
	connID, frames, shouldSwitch = pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}, now, nil, false)
	require.Zero(t, connID)
	require.Empty(t, frames)
	require.True(t, shouldSwitch)
}

func TestPathManagerLimits(t *testing.T) {
	var connIDs []protocol.ConnectionID
	for range 2*maxPaths + 2 {
		b := make([]byte, 8)
		rand.Read(b)
		connIDs = append(connIDs, protocol.ParseConnectionID(b))
	}
	var retiredConnIDs []protocol.ConnectionID
	pm := newPathManager(
		func(id pathID) (protocol.ConnectionID, bool) { return connIDs[id], true },
		func(id pathID) { retiredConnIDs = append(retiredConnIDs, connIDs[id]) },
		func() time.Duration { return time.Second },
		utils.DefaultLogger,
	)

	now := monotime.Now()
	firstPathTime := now
	var firstPathConnID protocol.ConnectionID
	require.Greater(t, pathTimeout, maxPaths*time.Second)
	for i := range maxPaths {
		connID, frames, _ := pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000 + i}, now, nil, true)
		require.NotEmpty(t, frames)
		require.Equal(t, connIDs[i], connID)
		if i == 0 {
			firstPathConnID = connID
		}
		now = now.Add(time.Second)
	}
	// the maximum number of paths is already being probed
	now = firstPathTime.Add(pathTimeout).Add(-time.Nanosecond)
	connID, frames, _ := pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 2000}, now, nil, true)
	require.Zero(t, connID)
	require.Empty(t, frames)

	// receiving another packet after the pathTimeout of the first path evicts the first path
	now = firstPathTime.Add(pathTimeout)
	connIDIndex := maxPaths
	connID, frames, _ = pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000 + maxPaths}, now, nil, true)
	require.NotEmpty(t, frames)
	require.Equal(t, connIDs[connIDIndex], connID)
	require.Equal(t, []protocol.ConnectionID{firstPathConnID}, retiredConnIDs)
	connIDIndex++

	// switching to a new path frees is up all paths
	var f1 []ackhandler.Frame
	pm.SwitchToPath(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000})
	for i := range maxPaths {
		connID, frames, _ := pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 3000 + i}, now, nil, true)
		if i == 0 {
			f1 = frames
		}
		require.NotEmpty(t, frames)
		require.Equal(t, connIDs[connIDIndex], connID)
		connIDIndex++
	}
	// again, the maximum number of paths is already being probed
	connID, frames, _ = pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 2000}, now, nil, true)
	require.Zero(t, connID)
	require.Empty(t, frames)

	// losing the frame removes this path
	f1[0].Handler.OnLost(f1[0].Frame)

	// we can open exactly one more path
	connID, frames, _ = pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 4000}, now, nil, true)
	require.NotEmpty(t, frames)
	require.Equal(t, connIDs[connIDIndex], connID)
	connID, frames, _ = pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 4001}, now, nil, true)
	require.Zero(t, connID)
	require.Empty(t, frames)
}

// A PATH_CHALLENGE received on a known path is answered (section 8.2.2 of RFC 9000),
// even if the maximum number of paths is being probed. No other path is evicted.
func TestPathManagerChallengeOnKnownPath(t *testing.T) {
	var connIDs []protocol.ConnectionID
	for range maxPaths {
		b := make([]byte, 8)
		rand.Read(b)
		connIDs = append(connIDs, protocol.ParseConnectionID(b))
	}
	var retiredConnIDs []protocol.ConnectionID
	pm := newPathManager(
		func(id pathID) (protocol.ConnectionID, bool) { return connIDs[id], true },
		func(id pathID) { retiredConnIDs = append(retiredConnIDs, connIDs[id]) },
		func() time.Duration { return time.Hour }, // no PATH_CHALLENGE is sent again in this test
		utils.DefaultLogger,
	)

	now := monotime.Now()
	for i := range maxPaths {
		connID, frames, _ := pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000 + i}, now, nil, false)
		require.Equal(t, connIDs[i], connID)
		require.Len(t, frames, 1)
	}
	connID, frames, _ := pm.HandlePacket(
		&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1001},
		now,
		&wire.PathChallengeFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}},
		false,
	)
	require.Equal(t, connIDs[1], connID)
	require.Len(t, frames, 1)
	require.Equal(t, &wire.PathResponseFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}, frames[0].Frame)

	// The first path didn't receive a packet for pathTimeout.
	// Answering a PATH_CHALLENGE on another known path doesn't evict it.
	now = now.Add(pathTimeout)
	connID, frames, _ = pm.HandlePacket(
		&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1002},
		now,
		&wire.PathChallengeFrame{Data: [8]byte{8, 7, 6, 5, 4, 3, 2, 1}},
		false,
	)
	require.Equal(t, connIDs[2], connID)
	require.Len(t, frames, 1)
	require.Equal(t, &wire.PathResponseFrame{Data: [8]byte{8, 7, 6, 5, 4, 3, 2, 1}}, frames[0].Frame)
	require.Empty(t, retiredConnIDs)
	// the first path is still known
	connID, frames, _ = pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}, now, nil, false)
	require.Zero(t, connID)
	require.Empty(t, frames)
}

type mockAddr struct {
	str string
}

func (a *mockAddr) Network() string { return "mock" }
func (a *mockAddr) String() string  { return a.str }

func TestAddrsEqual(t *testing.T) {
	tests := []struct {
		name     string
		addr1    net.Addr
		addr2    net.Addr
		expected bool
	}{
		{
			name:     "nil addresses",
			addr1:    nil,
			addr2:    nil,
			expected: false,
		},
		{
			name:     "one nil address",
			addr1:    &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234},
			addr2:    nil,
			expected: false,
		},
		{
			name:     "same IPv4 addresses",
			addr1:    &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234},
			addr2:    &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234},
			expected: true,
		},
		{
			name:     "different IPv4 addresses",
			addr1:    &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234},
			addr2:    &net.UDPAddr{IP: net.IPv4(4, 3, 2, 1), Port: 1234},
			expected: false,
		},
		{
			name:     "different ports",
			addr1:    &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234},
			addr2:    &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 4321},
			expected: false,
		},
		{
			name:     "same IPv6 addresses",
			addr1:    &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1234},
			addr2:    &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1234},
			expected: true,
		},
		{
			name:     "different IPv6 addresses",
			addr1:    &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1234},
			addr2:    &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 1234},
			expected: false,
		},
		{
			name:     "non-UDP addresses with same string representation",
			addr1:    &mockAddr{str: "192.0.2.1:1234"},
			addr2:    &mockAddr{str: "192.0.2.1:1234"},
			expected: true,
		},
		{
			name:     "non-UDP addresses with different string representation",
			addr1:    &mockAddr{str: "192.0.2.1:1234"},
			addr2:    &mockAddr{str: "192.0.2.2:1234"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := addrsEqual(tt.addr1, tt.addr2)
			require.Equal(t, tt.expected, result)
		})
	}
}

// A server that sent a preferred address distinguishes the paths by the local address as well.
// The paths from the original and from the preferred address to the same remote address are different paths.
func TestPathManagerLocalAddr(t *testing.T) {
	connIDs := []protocol.ConnectionID{
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		protocol.ParseConnectionID([]byte{2, 3, 4, 5}),
	}
	var retiredConnIDs []protocol.ConnectionID
	pm := newPathManager(
		func(id pathID) (protocol.ConnectionID, bool) { return connIDs[id], true },
		func(id pathID) { retiredConnIDs = append(retiredConnIDs, connIDs[id]) },
		func() time.Duration { return time.Second },
		utils.DefaultLogger,
	)
	now := monotime.Now()
	addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}
	preferred := netip.MustParseAddr("192.0.2.1")

	// the path from the original address
	connID, frames, _ := pm.HandlePacket(addr, now, nil, true)
	require.Equal(t, connIDs[0], connID)
	require.Len(t, frames, 1)
	pc1 := frames[0].Frame.(*wire.PathChallengeFrame)

	// the path from the preferred address is a new path
	connID, frames, shouldSwitch := pm.HandlePacketOnLocalAddr(addr, preferred, packetInfo{}, now, nil, true)
	require.Equal(t, connIDs[1], connID)
	require.Len(t, frames, 1)
	pc2 := frames[0].Frame.(*wire.PathChallengeFrame)
	require.NotEqual(t, pc1.Data, pc2.Data)
	require.False(t, shouldSwitch)

	// validating the path from the original address doesn't validate the path from the preferred address
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: pc1.Data})
	_, frames, shouldSwitch = pm.HandlePacketOnLocalAddr(addr, preferred, packetInfo{}, now, nil, true)
	require.Empty(t, frames)
	require.False(t, shouldSwitch)
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: pc2.Data})
	_, frames, shouldSwitch = pm.HandlePacketOnLocalAddr(addr, preferred, packetInfo{}, now, nil, true)
	require.Empty(t, frames)
	require.True(t, shouldSwitch)

	// switching to the path from the preferred address retires the connection ID of the other path
	id, ok := pm.SwitchToPathOnLocalAddr(addr, preferred)
	require.True(t, ok)
	require.Equal(t, pathID(1), id)
	require.Equal(t, []protocol.ConnectionID{connIDs[0]}, retiredConnIDs)
	_, ok = pm.SwitchToPathOnLocalAddr(addr, preferred)
	require.False(t, ok)
}

// If the anti-amplification limit didn't allow expanding the datagram containing the PATH_CHALLENGE to 1200 bytes,
// the PATH_RESPONSE only validates the client's address. The path MTU is validated by a second PATH_CHALLENGE,
// sent in an expanded datagram (section 8.2.1 of RFC 9000).
func TestPathManagerChallengeNotExpanded(t *testing.T) {
	connIDs := []protocol.ConnectionID{
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		protocol.ParseConnectionID([]byte{2, 3, 4, 5}),
	}
	pm := newPathManager(
		func(id pathID) (protocol.ConnectionID, bool) { return connIDs[id], true },
		func(id pathID) { t.Fatalf("unexpected retirement of connection ID %d", id) },
		func() time.Duration { return time.Second },
		utils.DefaultLogger,
	)
	now := monotime.Now()
	addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}
	info := packetInfo{addr: netip.MustParseAddr("192.0.2.1"), ifIndex: 42}

	connID, frames, shouldSwitch := pm.HandlePacketOnLocalAddr(addr, netip.Addr{}, info, now, nil, true)
	require.Equal(t, connIDs[0], connID)
	require.Len(t, frames, 1)
	require.False(t, shouldSwitch)
	pc1 := frames[0].Frame.(*wire.PathChallengeFrame)
	pm.ChallengeNotExpanded(pc1.Data)
	require.False(t, pm.AddrValidated(addr, netip.Addr{}))
	_, _, _, _, ok := pm.PopDueChallenge(now)
	require.False(t, ok)

	// the PATH_RESPONSE validates the address, but not the path
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: pc1.Data})
	require.True(t, pm.AddrValidated(addr, netip.Addr{}))
	require.False(t, pm.AddrValidated(addr, netip.MustParseAddr("192.0.2.2")))
	_, frames, shouldSwitch = pm.HandlePacketOnLocalAddr(addr, netip.Addr{}, info, now, nil, true)
	require.Empty(t, frames)
	require.False(t, shouldSwitch)

	// a second PATH_CHALLENGE is sent on the path
	connID, remoteAddr, pi, f, ok := pm.PopDueChallenge(now)
	require.True(t, ok)
	require.Equal(t, connIDs[0], connID)
	require.Equal(t, addr, remoteAddr)
	require.Equal(t, info, pi)
	pc2 := f.Frame.(*wire.PathChallengeFrame)
	require.NotEqual(t, pc1.Data, pc2.Data)
	_, _, _, _, ok = pm.PopDueChallenge(now)
	require.False(t, ok)

	// a late PATH_RESPONSE for the first PATH_CHALLENGE doesn't validate the path
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: pc1.Data})
	_, _, shouldSwitch = pm.HandlePacketOnLocalAddr(addr, netip.Addr{}, info, now, nil, true)
	require.False(t, shouldSwitch)

	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: pc2.Data})
	_, frames, shouldSwitch = pm.HandlePacketOnLocalAddr(addr, netip.Addr{}, info, now, nil, true)
	require.Empty(t, frames)
	require.True(t, shouldSwitch)
}

// If the second PATH_CHALLENGE, which validates the path MTU, is lost, the path is not validated.
func TestPathManagerChallengeNotExpandedLost(t *testing.T) {
	var retired []pathID
	pm := newPathManager(
		func(id pathID) (protocol.ConnectionID, bool) {
			return protocol.ParseConnectionID([]byte{1, 2, 3, byte(id)}), true
		},
		func(id pathID) { retired = append(retired, id) },
		func() time.Duration { return time.Second },
		utils.DefaultLogger,
	)
	now := monotime.Now()
	addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}
	_, frames, _ := pm.HandlePacket(addr, now, nil, true)
	pc := frames[0].Frame.(*wire.PathChallengeFrame)
	pm.ChallengeNotExpanded(pc.Data)
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: pc.Data})
	_, _, _, f, ok := pm.PopDueChallenge(now)
	require.True(t, ok)
	f.Handler.OnLost(f.Frame)
	require.Equal(t, []pathID{0}, retired)
	require.False(t, pm.AddrValidated(addr, netip.Addr{}))
	// a packet received from the address starts a new path validation
	_, frames, _ = pm.HandlePacket(addr, now, nil, true)
	require.Len(t, frames, 1)
	require.IsType(t, &wire.PathChallengeFrame{}, frames[0].Frame)
}

// After switching to a new path, the previously active path is validated (section 9.3.3 of RFC 9000).
func TestPathManagerPreviousPath(t *testing.T) {
	var retired []pathID
	pm := newPathManager(
		func(id pathID) (protocol.ConnectionID, bool) {
			return protocol.ParseConnectionID([]byte{1, 2, 3, byte(id)}), true
		},
		func(id pathID) { retired = append(retired, id) },
		func() time.Duration { return time.Second },
		utils.DefaultLogger,
	)
	now := monotime.Now()
	addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}
	prevAddr := &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 1000}
	prevInfo := packetInfo{addr: netip.MustParseAddr("192.0.2.1")}

	_, frames, _ := pm.HandlePacket(addr, now, nil, true)
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: frames[0].Frame.(*wire.PathChallengeFrame).Data})
	pm.SwitchToPath(addr)

	prevID := pm.AddPreviousPath(prevAddr, netip.Addr{}, prevInfo, now)
	require.Equal(t, pathID(1), prevID)
	// the previous address was validated before
	require.True(t, pm.AddrValidated(prevAddr, netip.Addr{}))
	connID, remoteAddr, info, f, ok := pm.PopDueChallenge(now)
	require.True(t, ok)
	require.Equal(t, protocol.ParseConnectionID([]byte{1, 2, 3, 1}), connID)
	require.Equal(t, prevAddr, remoteAddr)
	require.Equal(t, prevInfo, info)
	pc := f.Frame.(*wire.PathChallengeFrame)

	// a non-probing packet received on the previous path only switches back once the path is validated
	_, frames, shouldSwitch := pm.HandlePacket(prevAddr, now, nil, true)
	require.Empty(t, frames)
	require.False(t, shouldSwitch)
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: pc.Data})
	_, frames, shouldSwitch = pm.HandlePacket(prevAddr, now, nil, true)
	require.Empty(t, frames)
	require.True(t, shouldSwitch)
	require.Empty(t, retired)
}

// The peer might not respond to a PATH_CHALLENGE, e.g. if it doesn't have an unused connection ID.
// Packets received on the path trigger another PATH_CHALLENGE after a PTO, with exponential backoff.
func TestPathManagerRetryPathChallenge(t *testing.T) {
	const pto = 100 * time.Millisecond
	connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	pm := newPathManager(
		func(id pathID) (protocol.ConnectionID, bool) { return connID, true },
		func(id pathID) { t.Fatalf("unexpected retirement of connection ID %d", id) },
		func() time.Duration { return pto },
		utils.DefaultLogger,
	)
	addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}
	start := monotime.Now()

	_, frames, _ := pm.HandlePacket(addr, start, nil, false)
	require.Len(t, frames, 1)
	pc1 := frames[0].Frame.(*wire.PathChallengeFrame)

	// no new PATH_CHALLENGE before the PTO expires
	_, frames, _ = pm.HandlePacket(addr, start.Add(pto-time.Nanosecond), nil, false)
	require.Empty(t, frames)

	c, frames, _ := pm.HandlePacket(addr, start.Add(pto), nil, false)
	require.Equal(t, connID, c)
	require.Len(t, frames, 1)
	pc2 := frames[0].Frame.(*wire.PathChallengeFrame)
	require.NotEqual(t, pc1.Data, pc2.Data)

	// the next PATH_CHALLENGE is sent after twice the PTO
	_, frames, _ = pm.HandlePacket(addr, start.Add(3*pto-time.Nanosecond), nil, false)
	require.Empty(t, frames)
	_, frames, _ = pm.HandlePacket(addr, start.Add(3*pto), nil, false)
	require.Len(t, frames, 1)
	require.IsType(t, &wire.PathChallengeFrame{}, frames[0].Frame)

	// a delayed response to the first PATH_CHALLENGE still validates the path
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: pc1.Data})
	_, frames, shouldSwitch := pm.HandlePacket(addr, start.Add(time.Hour), nil, true)
	require.Empty(t, frames)
	require.True(t, shouldSwitch)
}

func TestPathManagerRetryPathChallengeLimit(t *testing.T) {
	const pto = 100 * time.Millisecond
	pm := newPathManager(
		func(id pathID) (protocol.ConnectionID, bool) {
			return protocol.ParseConnectionID([]byte{1, 2, 3, 4}), true
		},
		func(id pathID) {},
		func() time.Duration { return pto },
		utils.DefaultLogger,
	)
	addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}
	now := monotime.Now()

	var challenges [][8]byte
	for range 2 * maxPathChallenges {
		_, frames, _ := pm.HandlePacket(addr, now, nil, false)
		if len(frames) > 0 {
			require.Len(t, frames, 1)
			challenges = append(challenges, frames[0].Frame.(*wire.PathChallengeFrame).Data)
		}
		now = now.Add(time.Hour)
	}
	require.Len(t, challenges, maxPathChallenges)

	// a PATH_CHALLENGE received on the path is still answered
	_, frames, _ := pm.HandlePacket(addr, now, &wire.PathChallengeFrame{Data: [8]byte{1}}, false)
	require.Len(t, frames, 1)
	require.Equal(t, &wire.PathResponseFrame{Data: [8]byte{1}}, frames[0].Frame)

	// a response to any of the PATH_CHALLENGEs validates the path
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: challenges[2]})
	_, _, shouldSwitch := pm.HandlePacket(addr, now, nil, true)
	require.True(t, shouldSwitch)
}

// The packet containing the PATH_CHALLENGE is acknowledged, but the PATH_RESPONSE is lost.
// Packets received on the path after the PTO trigger another PATH_CHALLENGE, which validates the path.
// A PATH_CHALLENGE sent with a PATH_RESPONSE is also retried.
func TestPathManagerAcknowledgedPathChallengeLostResponse(t *testing.T) {
	const pto = 100 * time.Millisecond
	var retired []pathID
	pm := newPathManager(
		func(id pathID) (protocol.ConnectionID, bool) {
			return protocol.ParseConnectionID([]byte{1, 2, 3, byte(id)}), true
		},
		func(id pathID) { retired = append(retired, id) },
		func() time.Duration { return pto },
		utils.DefaultLogger,
	)
	addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}
	now := monotime.Now()

	_, frames, _ := pm.HandlePacket(addr, now, &wire.PathChallengeFrame{Data: [8]byte{1}}, true)
	require.Len(t, frames, 2)
	pc1 := frames[0].Frame.(*wire.PathChallengeFrame)
	for _, f := range frames {
		f.Handler.OnAcked(f.Frame)
	}
	_, frames, shouldSwitch := pm.HandlePacket(addr, now.Add(pto/2), nil, true)
	require.Empty(t, frames)
	require.False(t, shouldSwitch)

	connID, frames, shouldSwitch := pm.HandlePacket(addr, now.Add(pto), nil, true)
	require.Equal(t, protocol.ParseConnectionID([]byte{1, 2, 3, 0}), connID)
	require.Len(t, frames, 1)
	require.False(t, shouldSwitch)
	pc2 := frames[0].Frame.(*wire.PathChallengeFrame)
	require.NotEqual(t, pc1.Data, pc2.Data)

	// losing an earlier PATH_CHALLENGE doesn't remove the path, its PATH_RESPONSE might still be received
	frames[0].Handler.OnLost(pc1)
	require.Empty(t, retired)

	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: pc2.Data})
	_, frames, shouldSwitch = pm.HandlePacket(addr, now.Add(2*pto), nil, true)
	require.Empty(t, frames)
	require.True(t, shouldSwitch)
	// no more PATH_CHALLENGEs are sent on a validated path
	_, frames, _ = pm.HandlePacket(addr, now.Add(time.Hour), nil, true)
	require.Empty(t, frames)
}

// Losing the most recent PATH_CHALLENGE removes the path, as it does without retries.
// A packet received from the address starts a new path validation.
func TestPathManagerRetriedPathChallengeLost(t *testing.T) {
	const pto = 100 * time.Millisecond
	var retired []pathID
	pm := newPathManager(
		func(id pathID) (protocol.ConnectionID, bool) {
			return protocol.ParseConnectionID([]byte{1, 2, 3, byte(id)}), true
		},
		func(id pathID) { retired = append(retired, id) },
		func() time.Duration { return pto },
		utils.DefaultLogger,
	)
	addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}
	now := monotime.Now()

	_, frames, _ := pm.HandlePacket(addr, now, nil, true)
	require.Len(t, frames, 1)
	_, frames, _ = pm.HandlePacket(addr, now.Add(pto), nil, true)
	require.Len(t, frames, 1)
	frames[0].Handler.OnLost(frames[0].Frame)
	require.Equal(t, []pathID{0}, retired)

	connID, frames, _ := pm.HandlePacket(addr, now.Add(pto), nil, true)
	require.Equal(t, protocol.ParseConnectionID([]byte{1, 2, 3, 1}), connID)
	require.Len(t, frames, 1)
}

// The second PATH_CHALLENGE, which validates the path MTU, is retried as well.
func TestPathManagerRetryPathChallengeNotExpanded(t *testing.T) {
	const pto = 100 * time.Millisecond
	pm := newPathManager(
		func(id pathID) (protocol.ConnectionID, bool) {
			return protocol.ParseConnectionID([]byte{1, 2, 3, byte(id)}), true
		},
		func(id pathID) { t.Fatalf("unexpected retirement of connection ID %d", id) },
		func() time.Duration { return pto },
		utils.DefaultLogger,
	)
	addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}
	now := monotime.Now()

	_, frames, _ := pm.HandlePacket(addr, now, nil, true)
	require.Len(t, frames, 1)
	pc1 := frames[0].Frame.(*wire.PathChallengeFrame)
	pm.ChallengeNotExpanded(pc1.Data)
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: pc1.Data})
	require.True(t, pm.AddrValidated(addr, netip.Addr{}))

	// no retry while the second PATH_CHALLENGE is due
	_, frames, _ = pm.HandlePacket(addr, now.Add(time.Hour), nil, true)
	require.Empty(t, frames)
	_, _, _, f, ok := pm.PopDueChallenge(now.Add(time.Hour))
	require.True(t, ok)
	pc2 := f.Frame.(*wire.PathChallengeFrame)

	// the PATH_RESPONSE is lost
	_, frames, _ = pm.HandlePacket(addr, now.Add(time.Hour+pto), nil, true)
	require.Len(t, frames, 1)
	pc3 := frames[0].Frame.(*wire.PathChallengeFrame)
	require.NotEqual(t, pc2.Data, pc3.Data)
	pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: pc3.Data})
	_, _, shouldSwitch := pm.HandlePacket(addr, now.Add(time.Hour+2*pto), nil, true)
	require.True(t, shouldSwitch)
}
