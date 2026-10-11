package quic

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/utils"
	"github.com/AeonDave/mp-quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

// Packets received on different local addresses belong to different 4-tuples.
// SwitchToTuple returns the ID of the 4-tuple that the path switched to.
func TestTupleManagerTuples(t *testing.T) {
	connIDs := []protocol.ConnectionID{
		protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
		protocol.ParseConnectionID([]byte{2, 3, 4, 5, 6, 7, 8, 9}),
		protocol.ParseConnectionID([]byte{3, 4, 5, 6, 7, 8, 9, 0}),
	}
	var retiredConnIDs []protocol.ConnectionID
	m := newTupleManager(
		func(id pathID) (protocol.ConnectionID, bool) { return connIDs[id], true },
		func(id pathID) { retiredConnIDs = append(retiredConnIDs, connIDs[id]) },
		func() time.Duration { return time.Second },
		utils.DefaultLogger,
	)
	now := monotime.Now()
	remoteAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}
	local1 := netip.MustParseAddr("10.0.0.1")
	local2 := netip.MustParseAddr("10.0.0.2")

	connID, frames, shouldSwitch := m.HandlePacketOnTuple(remoteAddr, packetInfo{addr: local1}, now, nil, true)
	require.Equal(t, connIDs[0], connID)
	require.Len(t, frames, 1)
	require.False(t, shouldSwitch)
	challenge1 := frames[0].Frame.(*wire.PathChallengeFrame)
	// the same remote address, received on another local address
	connID, frames, shouldSwitch = m.HandlePacketOnTuple(remoteAddr, packetInfo{addr: local2}, now, nil, true)
	require.Equal(t, connIDs[1], connID)
	require.Len(t, frames, 1)
	require.False(t, shouldSwitch)
	// the first 4-tuple is known
	connID, frames, _ = m.HandlePacketOnTuple(remoteAddr, packetInfo{addr: local1}, now, nil, true)
	require.Zero(t, connID)
	require.Empty(t, frames)

	m.HandlePathResponseFrame(&wire.PathResponseFrame{Data: challenge1.Data})
	_, _, shouldSwitch = m.HandlePacketOnTuple(remoteAddr, packetInfo{addr: local1}, now, nil, true)
	require.True(t, shouldSwitch)
	id, ok := m.SwitchToTuple(remoteAddr, local1)
	require.True(t, ok)
	require.Equal(t, pathID(0), id)
	require.Equal(t, []protocol.ConnectionID{connIDs[1]}, retiredConnIDs)
	_, ok = m.SwitchToTuple(remoteAddr, local1)
	require.False(t, ok)
}

// If the PATH_CHALLENGE wasn't sent in a datagram of at least 1200 bytes, the PATH_RESPONSE only validates
// the peer's address. A second PATH_CHALLENGE validates the path MTU (section 8.2.1 of RFC 9000).
func TestTupleManagerChallengeNotExpanded(t *testing.T) {
	connIDs := []protocol.ConnectionID{
		protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
		protocol.ParseConnectionID([]byte{2, 3, 4, 5, 6, 7, 8, 9}),
	}
	var retiredConnIDs []protocol.ConnectionID
	m := newTupleManager(
		func(id pathID) (protocol.ConnectionID, bool) { return connIDs[id], true },
		func(id pathID) { retiredConnIDs = append(retiredConnIDs, connIDs[id]) },
		func() time.Duration { return time.Second },
		utils.DefaultLogger,
	)
	now := monotime.Now()
	remoteAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}
	info := packetInfo{addr: netip.MustParseAddr("10.0.0.1")}
	connID, frames, _ := m.HandlePacketOnTuple(remoteAddr, info, now, nil, true)
	require.Equal(t, connIDs[0], connID)
	require.Len(t, frames, 1)
	challenge := frames[0].Frame.(*wire.PathChallengeFrame)
	m.ChallengeNotExpanded(challenge.Data)
	require.False(t, m.AddrValidated(remoteAddr, info.addr))
	_, _, _, _, ok := m.PopDueChallenge(now)
	require.False(t, ok)

	m.HandlePathResponseFrame(&wire.PathResponseFrame{Data: challenge.Data})
	require.True(t, m.AddrValidated(remoteAddr, info.addr))
	require.False(t, m.AddrValidated(remoteAddr, netip.MustParseAddr("10.0.0.2")))
	_, _, shouldSwitch := m.HandlePacketOnTuple(remoteAddr, info, now, nil, true)
	require.False(t, shouldSwitch)
	// the second PATH_CHALLENGE uses the same connection ID, and is only returned once
	connID, addr, sendInfo, f, ok := m.PopDueChallenge(now)
	require.True(t, ok)
	require.Equal(t, connIDs[0], connID)
	require.Equal(t, remoteAddr, addr)
	require.Equal(t, info, sendInfo)
	mtuChallenge := f.Frame.(*wire.PathChallengeFrame)
	require.NotEqual(t, challenge.Data, mtuChallenge.Data)
	_, _, _, _, ok = m.PopDueChallenge(now)
	require.False(t, ok)
	// a repeated response to the first PATH_CHALLENGE doesn't validate the 4-tuple
	m.HandlePathResponseFrame(&wire.PathResponseFrame{Data: challenge.Data})
	_, _, shouldSwitch = m.HandlePacketOnTuple(remoteAddr, info, now, nil, true)
	require.False(t, shouldSwitch)
	// losing the first PATH_CHALLENGE doesn't matter anymore
	frames[0].Handler.OnLost(challenge)
	require.Empty(t, retiredConnIDs)

	m.HandlePathResponseFrame(&wire.PathResponseFrame{Data: mtuChallenge.Data})
	_, _, shouldSwitch = m.HandlePacketOnTuple(remoteAddr, info, now, nil, true)
	require.True(t, shouldSwitch)
}

// After switching to another 4-tuple, the previously active 4-tuple is validated (section 9.3.3 of RFC 9000).
// Its address was validated before.
func TestTupleManagerPreviousTuple(t *testing.T) {
	connIDs := []protocol.ConnectionID{
		protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
		protocol.ParseConnectionID([]byte{2, 3, 4, 5, 6, 7, 8, 9}),
		protocol.ParseConnectionID([]byte{3, 4, 5, 6, 7, 8, 9, 0}),
	}
	var retiredConnIDs []protocol.ConnectionID
	m := newTupleManager(
		func(id pathID) (protocol.ConnectionID, bool) {
			if int(id) >= len(connIDs) {
				return protocol.ConnectionID{}, false
			}
			return connIDs[id], true
		},
		func(id pathID) {
			// no connection ID was used for this 4-tuple
			if int(id) >= len(connIDs) {
				return
			}
			retiredConnIDs = append(retiredConnIDs, connIDs[id])
		},
		func() time.Duration { return time.Second },
		utils.DefaultLogger,
	)
	now := monotime.Now()
	newAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}
	prevAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 2000}
	prevInfo := packetInfo{addr: netip.MustParseAddr("10.0.0.1"), ifIndex: 42}
	_, frames, _ := m.HandlePacketOnTuple(newAddr, packetInfo{}, now, nil, true)
	require.Len(t, frames, 1)
	m.HandlePathResponseFrame(&wire.PathResponseFrame{Data: frames[0].Frame.(*wire.PathChallengeFrame).Data})
	_, _, shouldSwitch := m.HandlePacketOnTuple(newAddr, packetInfo{}, now, nil, true)
	require.True(t, shouldSwitch)
	id, ok := m.SwitchToTuple(newAddr, netip.Addr{})
	require.True(t, ok)
	require.Equal(t, pathID(0), id)

	prevID := m.AddPreviousTuple(prevAddr, prevInfo, now)
	require.Equal(t, pathID(1), prevID)
	require.True(t, m.AddrValidated(prevAddr, prevInfo.addr))
	connID, addr, info, f, ok := m.PopDueChallenge(now)
	require.True(t, ok)
	require.Equal(t, connIDs[1], connID)
	require.Equal(t, prevAddr, addr)
	require.Equal(t, prevInfo, info)
	challenge := f.Frame.(*wire.PathChallengeFrame)
	_, _, _, _, ok = m.PopDueChallenge(now)
	require.False(t, ok)
	// a non-probing packet received on the previous 4-tuple only switches back after the validation succeeded
	_, frames, shouldSwitch = m.HandlePacketOnTuple(prevAddr, prevInfo, now, nil, true)
	require.Empty(t, frames)
	require.False(t, shouldSwitch)
	m.HandlePathResponseFrame(&wire.PathResponseFrame{Data: challenge.Data})
	_, _, shouldSwitch = m.HandlePacketOnTuple(prevAddr, prevInfo, now, nil, true)
	require.True(t, shouldSwitch)
	id, ok = m.SwitchToTuple(prevAddr, prevInfo.addr)
	require.True(t, ok)
	require.Equal(t, prevID, id)
	require.Empty(t, retiredConnIDs)

	// if the validation fails, the connection ID is retired
	prevID = m.AddPreviousTuple(newAddr, packetInfo{}, now)
	_, _, _, f, ok = m.PopDueChallenge(now)
	require.True(t, ok)
	f.Handler.OnLost(f.Frame)
	require.Equal(t, []protocol.ConnectionID{connIDs[prevID]}, retiredConnIDs)
	require.False(t, m.AddrValidated(newAddr, netip.Addr{}))

	// if no connection ID is available, the previous 4-tuple is not validated
	m.AddPreviousTuple(newAddr, packetInfo{}, now)
	_, _, _, _, ok = m.PopDueChallenge(now)
	require.False(t, ok)
	require.False(t, m.AddrValidated(newAddr, netip.Addr{}))
}

// A PATH_CHALLENGE received on a known 4-tuple is answered (section 8.2.2 of RFC 9000),
// even if the maximum number of 4-tuples is being validated. No other 4-tuple is evicted.
func TestTupleManagerChallengeOnKnownTuple(t *testing.T) {
	var connIDs []protocol.ConnectionID
	for i := range maxTuplesPerPath {
		connIDs = append(connIDs, protocol.ParseConnectionID([]byte{byte(i), 1, 2, 3, 4, 5, 6, 7}))
	}
	var retiredConnIDs []protocol.ConnectionID
	m := newTupleManager(
		func(id pathID) (protocol.ConnectionID, bool) { return connIDs[id], true },
		func(id pathID) { retiredConnIDs = append(retiredConnIDs, connIDs[id]) },
		func() time.Duration { return time.Hour }, // no PATH_CHALLENGE is sent again in this test
		utils.DefaultLogger,
	)
	now := monotime.Now()
	remoteAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}
	// the 4-tuples only differ in the local address
	var infos []packetInfo
	for i := range maxTuplesPerPath {
		info := packetInfo{addr: netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})}
		infos = append(infos, info)
		connID, frames, _ := m.HandlePacketOnTuple(remoteAddr, info, now, nil, false)
		require.Equal(t, connIDs[i], connID)
		require.Len(t, frames, 1)
	}
	connID, frames, _ := m.HandlePacketOnTuple(
		remoteAddr,
		infos[1],
		now,
		&wire.PathChallengeFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}},
		false,
	)
	require.Equal(t, connIDs[1], connID)
	require.Len(t, frames, 1)
	require.Equal(t, &wire.PathResponseFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}, frames[0].Frame)

	// The first 4-tuple didn't receive a packet for pathTimeout.
	// Answering a PATH_CHALLENGE on another known 4-tuple doesn't evict it.
	now = now.Add(pathTimeout)
	connID, frames, _ = m.HandlePacketOnTuple(
		remoteAddr,
		infos[2],
		now,
		&wire.PathChallengeFrame{Data: [8]byte{8, 7, 6, 5, 4, 3, 2, 1}},
		false,
	)
	require.Equal(t, connIDs[2], connID)
	require.Len(t, frames, 1)
	require.Equal(t, &wire.PathResponseFrame{Data: [8]byte{8, 7, 6, 5, 4, 3, 2, 1}}, frames[0].Frame)
	require.Empty(t, retiredConnIDs)
	// the first 4-tuple is still known
	connID, frames, _ = m.HandlePacketOnTuple(remoteAddr, infos[0], now, nil, false)
	require.Zero(t, connID)
	require.Empty(t, frames)
}

// The packet containing the PATH_CHALLENGE is acknowledged, but the PATH_RESPONSE is lost.
// Packets received from the 4-tuple trigger another PATH_CHALLENGE after a PTO of the path,
// with exponential backoff, up to maxPathChallenges.
func TestTupleManagerRetryPathChallenge(t *testing.T) {
	const pto = 100 * time.Millisecond
	connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	m := newTupleManager(
		func(id pathID) (protocol.ConnectionID, bool) { return connID, true },
		func(id pathID) { t.Fatalf("unexpected retirement of connection ID %d", id) },
		func() time.Duration { return pto },
		utils.DefaultLogger,
	)
	remoteAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}
	info := packetInfo{addr: netip.MustParseAddr("10.0.0.1")}
	start := monotime.Now()

	_, frames, _ := m.HandlePacketOnTuple(remoteAddr, info, start, nil, true)
	require.Len(t, frames, 1)
	frames[0].Handler.OnAcked(frames[0].Frame)
	challenges := [][8]byte{frames[0].Frame.(*wire.PathChallengeFrame).Data}

	_, frames, shouldSwitch := m.HandlePacketOnTuple(remoteAddr, info, start.Add(pto-time.Nanosecond), nil, true)
	require.Empty(t, frames)
	require.False(t, shouldSwitch)

	sendTime := start
	for i := 1; i < maxPathChallenges; i++ {
		backoff := pto << (i - 1)
		_, frames, _ = m.HandlePacketOnTuple(remoteAddr, info, sendTime.Add(backoff-time.Nanosecond), nil, true)
		require.Empty(t, frames)
		sendTime = sendTime.Add(backoff)
		c, frames, _ := m.HandlePacketOnTuple(remoteAddr, info, sendTime, nil, true)
		require.Equal(t, connID, c)
		require.Len(t, frames, 1)
		data := frames[0].Frame.(*wire.PathChallengeFrame).Data
		require.NotContains(t, challenges, data)
		challenges = append(challenges, data)
	}
	// no more PATH_CHALLENGEs are sent
	_, frames, _ = m.HandlePacketOnTuple(remoteAddr, info, sendTime.Add(time.Hour), nil, true)
	require.Empty(t, frames)

	// a response to any of the PATH_CHALLENGEs validates the 4-tuple
	m.HandlePathResponseFrame(&wire.PathResponseFrame{Data: challenges[1]})
	_, frames, shouldSwitch = m.HandlePacketOnTuple(remoteAddr, info, sendTime.Add(time.Hour), nil, true)
	require.Empty(t, frames)
	require.True(t, shouldSwitch)
}
