package quic

import (
	"crypto/rand"
	"testing"

	"github.com/AeonDave/mp-quic-go/internal/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/internal/wire"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestConnIDManagerInitialConnID(t *testing.T) {
	m := newConnIDManager(protocol.ParseConnectionID([]byte{1, 2, 3, 4}), nil, nil, nil)
	require.Equal(t, protocol.ParseConnectionID([]byte{1, 2, 3, 4}), m.Get())
	require.Equal(t, protocol.ParseConnectionID([]byte{1, 2, 3, 4}), m.Get())
	m.ChangeInitialConnID(protocol.ParseConnectionID([]byte{5, 6, 7, 8}))
	require.Equal(t, protocol.ParseConnectionID([]byte{5, 6, 7, 8}), m.Get())
}

func TestConnIDManagerAddConnIDs(t *testing.T) {
	m := newConnIDManager(
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		func(protocol.StatelessResetToken) {},
		func(protocol.StatelessResetToken) {},
		func(wire.Frame) {},
	)
	f1 := &wire.NewConnectionIDFrame{
		SequenceNumber:      1,
		ConnectionID:        protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
		StatelessResetToken: protocol.StatelessResetToken{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe},
	}
	f2 := &wire.NewConnectionIDFrame{
		SequenceNumber:      2,
		ConnectionID:        protocol.ParseConnectionID([]byte{0xba, 0xad, 0xf0, 0x0d}),
		StatelessResetToken: protocol.StatelessResetToken{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe},
	}
	require.NoError(t, m.Add(f2))
	require.NoError(t, m.Add(f1)) // receiving reordered frames is fine
	require.NoError(t, m.Add(f2)) // receiving a duplicate is fine

	require.Equal(t, protocol.ParseConnectionID([]byte{1, 2, 3, 4}), m.Get())
	m.updateConnectionID()
	require.Equal(t, protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}), m.Get())
	m.updateConnectionID()
	require.Equal(t, protocol.ParseConnectionID([]byte{0xba, 0xad, 0xf0, 0x0d}), m.Get())

	require.NoError(t, m.Add(f2)) // receiving a duplicate for the current connection ID is fine as well
	require.Equal(t, protocol.ParseConnectionID([]byte{0xba, 0xad, 0xf0, 0x0d}), m.Get())

	// receiving mismatching connection IDs is not fine
	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{
		SequenceNumber:      3,
		ConnectionID:        protocol.ParseConnectionID([]byte{1, 2, 3, 4}), // mismatching connection ID
		StatelessResetToken: protocol.StatelessResetToken{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe},
	}))
	err := m.Add(&wire.NewConnectionIDFrame{
		SequenceNumber:      3,
		ConnectionID:        protocol.ParseConnectionID([]byte{2, 3, 4, 5}), // mismatching connection ID
		StatelessResetToken: protocol.StatelessResetToken{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe},
	})
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
	require.ErrorContains(t, err, "received conflicting connection IDs for sequence number 3")
	// receiving mismatching stateless reset tokens is not fine either
	err = m.Add(&wire.NewConnectionIDFrame{
		SequenceNumber:      3,
		ConnectionID:        protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		StatelessResetToken: protocol.StatelessResetToken{1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0},
	})
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
	require.ErrorContains(t, err, "received conflicting stateless reset tokens for sequence number 3")
}

func TestConnIDManagerLimit(t *testing.T) {
	m := newConnIDManager(
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		func(protocol.StatelessResetToken) {},
		func(protocol.StatelessResetToken) {},
		func(f wire.Frame) {},
	)
	for i := uint8(1); i < protocol.MaxActiveConnectionIDs; i++ {
		require.NoError(t, m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber:      uint64(i),
			ConnectionID:        protocol.ParseConnectionID([]byte{i, i, i, i}),
			StatelessResetToken: protocol.StatelessResetToken{i, i, i, i, i, i, i, i, i, i, i, i, i, i, i, i},
		}))
	}
	require.ErrorIs(t,
		m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber:      uint64(9999),
			ConnectionID:        protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
			StatelessResetToken: protocol.StatelessResetToken{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		}),
		&qerr.TransportError{ErrorCode: qerr.ConnectionIDLimitError},
	)
}

// Connection IDs used for probing paths are active connection IDs,
// and count towards the active_connection_id_limit.
func TestConnIDManagerLimitWithPathProbing(t *testing.T) {
	newFrame := func(seq uint64) *wire.NewConnectionIDFrame {
		b := byte(seq)
		return &wire.NewConnectionIDFrame{
			SequenceNumber:      seq,
			ConnectionID:        protocol.ParseConnectionID([]byte{b, b, b, b}),
			StatelessResetToken: protocol.StatelessResetToken{b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b},
		}
	}
	// newManager returns a connIDManager that uses connection ID 1, uses connection ID 2 for probing path 1,
	// and has connection ID 3 in the queue. Connection ID 0 is retired.
	newManager := func(t *testing.T) *connIDManager {
		t.Helper()
		m := newConnIDManager(
			protocol.ParseConnectionID([]byte{0, 0, 0, 0}),
			func(protocol.StatelessResetToken) {},
			func(protocol.StatelessResetToken) {},
			func(wire.Frame) {},
		)
		for seq := uint64(1); seq < protocol.MaxActiveConnectionIDs; seq++ {
			require.NoError(t, m.Add(newFrame(seq)))
		}
		m.SetHandshakeComplete()
		require.Equal(t, newFrame(1).ConnectionID, m.Get())
		connID, ok := m.GetConnIDForPath(1)
		require.True(t, ok)
		require.Equal(t, newFrame(2).ConnectionID, connID)
		return m
	}

	t.Run("exceeding the limit", func(t *testing.T) {
		m := newManager(t)
		require.NoError(t, m.Add(newFrame(4)))
		require.ErrorIs(t, m.Add(newFrame(5)), &qerr.TransportError{ErrorCode: qerr.ConnectionIDLimitError})
	})

	t.Run("retiring the connection ID of a path", func(t *testing.T) {
		m := newManager(t)
		require.NoError(t, m.Add(newFrame(4)))
		m.RetireConnIDForPath(1)
		require.NoError(t, m.Add(newFrame(5)))
		require.ErrorIs(t, m.Add(newFrame(6)), &qerr.TransportError{ErrorCode: qerr.ConnectionIDLimitError})
	})

	t.Run("retiring the connection ID of a path using Retire Prior To", func(t *testing.T) {
		m := newManager(t)
		require.NoError(t, m.Add(newFrame(4)))
		// retires connection IDs 1 and 2
		f := newFrame(5)
		f.RetirePriorTo = 3
		require.NoError(t, m.Add(f))
		require.Equal(t, newFrame(3).ConnectionID, m.Get())
		require.NoError(t, m.Add(newFrame(6)))
		require.ErrorIs(t, m.Add(newFrame(7)), &qerr.TransportError{ErrorCode: qerr.ConnectionIDLimitError})
	})
}

func TestConnIDManagerRetiringConnectionIDs(t *testing.T) {
	var frameQueue []wire.Frame
	m := newConnIDManager(
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		func(protocol.StatelessResetToken) {},
		func(protocol.StatelessResetToken) {},
		func(f wire.Frame) { frameQueue = append(frameQueue, f) },
	)
	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{
		SequenceNumber: 10,
		ConnectionID:   protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
	}))
	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{
		SequenceNumber: 13,
		ConnectionID:   protocol.ParseConnectionID([]byte{2, 3, 4, 5}),
	}))
	require.Empty(t, frameQueue)
	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{
		RetirePriorTo:  14,
		SequenceNumber: 17,
		ConnectionID:   protocol.ParseConnectionID([]byte{3, 4, 5, 6}),
	}))
	require.Equal(t, []wire.Frame{
		&wire.RetireConnectionIDFrame{SequenceNumber: 10},
		&wire.RetireConnectionIDFrame{SequenceNumber: 13},
		&wire.RetireConnectionIDFrame{SequenceNumber: 0},
	}, frameQueue)
	require.Equal(t, protocol.ParseConnectionID([]byte{3, 4, 5, 6}), m.Get())
	frameQueue = nil

	// a reordered connection ID is immediately retired
	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{
		SequenceNumber: 12,
		ConnectionID:   protocol.ParseConnectionID([]byte{5, 6, 7, 8}),
	}))
	require.Equal(t, []wire.Frame{&wire.RetireConnectionIDFrame{SequenceNumber: 12}}, frameQueue)
	require.Equal(t, protocol.ParseConnectionID([]byte{3, 4, 5, 6}), m.Get())
}

func TestConnIDManagerHandshakeCompletion(t *testing.T) {
	var frameQueue []wire.Frame
	var addedTokens, removedTokens []protocol.StatelessResetToken
	m := newConnIDManager(
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		func(token protocol.StatelessResetToken) { addedTokens = append(addedTokens, token) },
		func(token protocol.StatelessResetToken) { removedTokens = append(removedTokens, token) },
		func(f wire.Frame) { frameQueue = append(frameQueue, f) },
	)
	m.SetStatelessResetToken(protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1})
	require.Equal(t, []protocol.StatelessResetToken{{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}}, addedTokens)
	require.Empty(t, removedTokens)

	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{
		SequenceNumber:      1,
		ConnectionID:        protocol.ParseConnectionID([]byte{4, 3, 2, 1}),
		StatelessResetToken: protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
	}))
	require.Equal(t, protocol.ParseConnectionID([]byte{1, 2, 3, 4}), m.Get())
	m.SetHandshakeComplete()
	require.Equal(t, protocol.ParseConnectionID([]byte{4, 3, 2, 1}), m.Get())
	require.Equal(t, []wire.Frame{&wire.RetireConnectionIDFrame{SequenceNumber: 0}}, frameQueue)
	require.Equal(t, []protocol.StatelessResetToken{{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}}, removedTokens)
}

func TestConnIDManagerConnIDRotation(t *testing.T) {
	toToken := func(connID protocol.ConnectionID) protocol.StatelessResetToken {
		var token protocol.StatelessResetToken
		copy(token[:], connID.Bytes())
		copy(token[connID.Len():], connID.Bytes())
		return token
	}

	var frameQueue []wire.Frame
	var addedTokens, removedTokens []protocol.StatelessResetToken
	m := newConnIDManager(
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		func(token protocol.StatelessResetToken) { addedTokens = append(addedTokens, token) },
		func(token protocol.StatelessResetToken) { removedTokens = append(removedTokens, token) },
		func(f wire.Frame) { frameQueue = append(frameQueue, f) },
	)
	// the first connection ID is used as soon as the handshake is complete
	m.SetHandshakeComplete()
	firstConnID := protocol.ParseConnectionID([]byte{4, 3, 2, 1})
	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{
		SequenceNumber:      1,
		ConnectionID:        firstConnID,
		StatelessResetToken: toToken(protocol.ParseConnectionID([]byte{4, 3, 2, 1})),
	}))
	require.Equal(t, firstConnID, m.Get())
	frameQueue = nil
	require.True(t, m.IsActiveStatelessResetToken(toToken(firstConnID)))
	require.Equal(t, addedTokens, []protocol.StatelessResetToken{toToken(firstConnID)})
	addedTokens = addedTokens[:0]

	// Note that we're missing the connection ID with sequence number 2.
	// It will be received later.
	var queuedConnIDs []protocol.ConnectionID
	for i := range protocol.MaxActiveConnectionIDs - 1 {
		b := make([]byte, 4)
		rand.Read(b)
		connID := protocol.ParseConnectionID(b)
		queuedConnIDs = append(queuedConnIDs, connID)
		require.NoError(t, m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber:      uint64(3 + i),
			ConnectionID:        connID,
			StatelessResetToken: toToken(connID),
		}))
		require.False(t, m.IsActiveStatelessResetToken(toToken(connID)))
	}

	var counter int
	for {
		require.Empty(t, frameQueue)
		m.SentPacket()
		counter++
		if connID := m.Get(); connID != firstConnID {
			require.Equal(t, queuedConnIDs[0], m.Get())
			require.Equal(t, []wire.Frame{&wire.RetireConnectionIDFrame{SequenceNumber: 1}}, frameQueue)
			require.Equal(t, removedTokens, []protocol.StatelessResetToken{toToken(firstConnID)})
			require.Equal(t, addedTokens, []protocol.StatelessResetToken{toToken(connID)})
			addedTokens = addedTokens[:0]
			removedTokens = removedTokens[:0]
			require.True(t, m.IsActiveStatelessResetToken(toToken(connID)))
			require.False(t, m.IsActiveStatelessResetToken(toToken(firstConnID)))
			break
		}
		require.True(t, m.IsActiveStatelessResetToken(toToken(firstConnID)))
		require.Empty(t, addedTokens)
	}
	require.GreaterOrEqual(t, counter, protocol.PacketsPerConnectionID/2)
	require.LessOrEqual(t, counter, protocol.PacketsPerConnectionID*3/2)
	frameQueue = nil

	// now receive connection ID 2
	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{
		SequenceNumber: 2,
		ConnectionID:   protocol.ParseConnectionID([]byte{2, 3, 4, 5}),
	}))
	require.Equal(t, []wire.Frame{&wire.RetireConnectionIDFrame{SequenceNumber: 2}}, frameQueue)
}

func TestConnIDManagerPathMigration(t *testing.T) {
	var frameQueue []wire.Frame
	var addedTokens, removedTokens []protocol.StatelessResetToken
	m := newConnIDManager(
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		func(token protocol.StatelessResetToken) { addedTokens = append(addedTokens, token) },
		func(token protocol.StatelessResetToken) { removedTokens = append(removedTokens, token) },
		func(f wire.Frame) { frameQueue = append(frameQueue, f) },
	)

	// no connection ID available yet
	_, ok := m.GetConnIDForPath(1)
	require.False(t, ok)

	// add two connection IDs
	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{
		SequenceNumber:      1,
		ConnectionID:        protocol.ParseConnectionID([]byte{4, 3, 2, 1}),
		StatelessResetToken: protocol.StatelessResetToken{4, 3, 2, 1, 4, 3, 2, 1},
	}))
	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{
		SequenceNumber:      2,
		ConnectionID:        protocol.ParseConnectionID([]byte{5, 4, 3, 2}),
		StatelessResetToken: protocol.StatelessResetToken{5, 4, 3, 2, 5, 4, 3, 2},
	}))
	connID, ok := m.GetConnIDForPath(1)
	require.True(t, ok)
	require.Equal(t, protocol.ParseConnectionID([]byte{4, 3, 2, 1}), connID)
	require.Equal(t, []protocol.StatelessResetToken{{4, 3, 2, 1, 4, 3, 2, 1}}, addedTokens)
	require.Empty(t, removedTokens)

	addedTokens = addedTokens[:0]
	require.False(t, m.IsActiveStatelessResetToken(protocol.StatelessResetToken{5, 4, 3, 2, 5, 4, 3, 2}))
	connID, ok = m.GetConnIDForPath(2)
	require.True(t, ok)
	require.Equal(t, protocol.ParseConnectionID([]byte{5, 4, 3, 2}), connID)
	require.Equal(t, []protocol.StatelessResetToken{{5, 4, 3, 2, 5, 4, 3, 2}}, addedTokens)
	require.Empty(t, removedTokens)
	require.True(t, m.IsActiveStatelessResetToken(protocol.StatelessResetToken{5, 4, 3, 2, 5, 4, 3, 2}))

	addedTokens = addedTokens[:0]
	// asking for the connection for path 1 again returns the same connection ID
	connID, ok = m.GetConnIDForPath(1)
	require.True(t, ok)
	require.Equal(t, protocol.ParseConnectionID([]byte{4, 3, 2, 1}), connID)
	require.Empty(t, addedTokens)

	// if the connection ID is retired, the path will use another connection ID
	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{
		SequenceNumber:      3,
		RetirePriorTo:       2,
		ConnectionID:        protocol.ParseConnectionID([]byte{6, 5, 4, 3}),
		StatelessResetToken: protocol.StatelessResetToken{6, 5, 4, 3, 6, 5, 4, 3},
	}))
	require.Len(t, frameQueue, 2)
	require.Equal(t, []protocol.StatelessResetToken{{4, 3, 2, 1, 4, 3, 2, 1}}, removedTokens)
	frameQueue = nil
	removedTokens = removedTokens[:0]

	require.Equal(t, protocol.ParseConnectionID([]byte{6, 5, 4, 3}), m.Get())
	require.Equal(t, []protocol.StatelessResetToken{{6, 5, 4, 3, 6, 5, 4, 3}}, addedTokens)
	require.Empty(t, removedTokens)
	addedTokens = addedTokens[:0]

	// the connection ID is not used for new paths
	_, ok = m.GetConnIDForPath(3)
	require.False(t, ok)

	// Manually retiring the connection ID does nothing.
	// Path 1 doesn't have a connection ID anymore.
	m.RetireConnIDForPath(1)
	require.Empty(t, frameQueue)
	_, ok = m.GetConnIDForPath(1)
	require.False(t, ok)
	require.Empty(t, removedTokens)

	// only after a new connection ID is added, it will be used for path 1
	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{
		SequenceNumber:      4,
		ConnectionID:        protocol.ParseConnectionID([]byte{7, 6, 5, 4}),
		StatelessResetToken: protocol.StatelessResetToken{16, 15, 14, 13},
	}))
	connID, ok = m.GetConnIDForPath(1)
	require.True(t, ok)
	require.Equal(t, protocol.ParseConnectionID([]byte{7, 6, 5, 4}), connID)
	require.Equal(t, []protocol.StatelessResetToken{{16, 15, 14, 13}}, addedTokens)
	require.Empty(t, removedTokens)
	require.True(t, m.IsActiveStatelessResetToken(protocol.StatelessResetToken{16, 15, 14, 13}))

	// a RETIRE_CONNECTION_ID frame for path 1 is queued when retiring the connection ID
	m.RetireConnIDForPath(1)
	require.Equal(t, []wire.Frame{&wire.RetireConnectionIDFrame{SequenceNumber: 4}}, frameQueue)
	require.Equal(t, []protocol.StatelessResetToken{{16, 15, 14, 13}}, removedTokens)
	removedTokens = removedTokens[:0]
	require.False(t, m.IsActiveStatelessResetToken(protocol.StatelessResetToken{16, 15, 14, 13}))

	frameQueue = nil
	m.Close()
	require.Equal(t, []protocol.StatelessResetToken{
		{6, 5, 4, 3, 6, 5, 4, 3}, // currently active connection ID
		{5, 4, 3, 2, 5, 4, 3, 2}, // path 2
	}, removedTokens)
	m.RetireConnIDForPath(2)
	require.Empty(t, frameQueue)
}

func TestConnIDManagerRetransmittedNewConnectionIDFrames(t *testing.T) {
	var frameQueue []wire.Frame
	var removedTokens []protocol.StatelessResetToken
	m := newConnIDManager(
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		func(protocol.StatelessResetToken) {},
		func(token protocol.StatelessResetToken) { removedTokens = append(removedTokens, token) },
		func(f wire.Frame) { frameQueue = append(frameQueue, f) },
	)
	frames := []*wire.NewConnectionIDFrame{
		{
			SequenceNumber:      1,
			ConnectionID:        protocol.ParseConnectionID([]byte{4, 3, 2, 1}),
			StatelessResetToken: protocol.StatelessResetToken{1},
		},
		{
			SequenceNumber:      2,
			ConnectionID:        protocol.ParseConnectionID([]byte{5, 4, 3, 2}),
			StatelessResetToken: protocol.StatelessResetToken{2},
		},
		{
			SequenceNumber:      3,
			ConnectionID:        protocol.ParseConnectionID([]byte{6, 5, 4, 3}),
			StatelessResetToken: protocol.StatelessResetToken{3},
		},
	}
	for _, f := range frames {
		require.NoError(t, m.Add(f))
	}
	m.SetHandshakeComplete()
	require.Equal(t, protocol.ParseConnectionID([]byte{4, 3, 2, 1}), m.Get())
	require.Equal(t, []wire.Frame{&wire.RetireConnectionIDFrame{SequenceNumber: 0}}, frameQueue)
	// connection ID 2 is now used for probing a path
	connID, ok := m.GetConnIDForPath(1)
	require.True(t, ok)
	require.Equal(t, protocol.ParseConnectionID([]byte{5, 4, 3, 2}), connID)
	frameQueue = nil

	// Retransmissions of the NEW_CONNECTION_ID frames don't retire the connection IDs that are in use.
	for _, f := range frames {
		require.NoError(t, m.Add(f))
	}
	require.Empty(t, frameQueue)
	require.Empty(t, removedTokens)
	require.Equal(t, protocol.ParseConnectionID([]byte{4, 3, 2, 1}), m.Get())
	connID, ok = m.GetConnIDForPath(1)
	require.True(t, ok)
	require.Equal(t, protocol.ParseConnectionID([]byte{5, 4, 3, 2}), connID)
	require.True(t, m.IsActiveStatelessResetToken(protocol.StatelessResetToken{1}))
	require.True(t, m.IsActiveStatelessResetToken(protocol.StatelessResetToken{2}))

	// a retransmission of a NEW_CONNECTION_ID frame for a retired connection ID retires it again
	m.RetireConnIDForPath(1)
	require.Equal(t, []wire.Frame{&wire.RetireConnectionIDFrame{SequenceNumber: 2}}, frameQueue)
	frameQueue = nil
	require.NoError(t, m.Add(frames[1]))
	require.Equal(t, []wire.Frame{&wire.RetireConnectionIDFrame{SequenceNumber: 2}}, frameQueue)
	require.Equal(t, protocol.ParseConnectionID([]byte{4, 3, 2, 1}), m.Get())
	// the retired connection ID is not used for another path
	connID, ok = m.GetConnIDForPath(2)
	require.True(t, ok)
	require.Equal(t, protocol.ParseConnectionID([]byte{6, 5, 4, 3}), connID)
	_, ok = m.GetConnIDForPath(3)
	require.False(t, ok)
}

func TestConnIDManagerZeroLengthConnectionID(t *testing.T) {
	m := newConnIDManager(
		protocol.ConnectionID{},
		func(protocol.StatelessResetToken) {},
		func(protocol.StatelessResetToken) {},
		func(f wire.Frame) {},
	)
	require.Equal(t, protocol.ConnectionID{}, m.Get())
	for range 5 * protocol.PacketsPerConnectionID {
		m.SentPacket()
		require.Equal(t, protocol.ConnectionID{}, m.Get())
	}

	// for path probing, we don't need to change the connection ID
	for id := pathID(1); id < 10; id++ {
		connID, ok := m.GetConnIDForPath(id)
		require.True(t, ok)
		require.Equal(t, protocol.ConnectionID{}, connID)
	}
	// retiring a connection ID for a path is also a no-op
	for id := pathID(1); id < 20; id++ {
		m.RetireConnIDForPath(id)
	}

	require.ErrorIs(t, m.Add(&wire.NewConnectionIDFrame{
		SequenceNumber:      1,
		ConnectionID:        protocol.ConnectionID{},
		StatelessResetToken: protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
	}), &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
}

func TestConnIDManagerClose(t *testing.T) {
	var addedTokens, removedTokens []protocol.StatelessResetToken
	m := newConnIDManager(
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		func(token protocol.StatelessResetToken) { addedTokens = append(addedTokens, token) },
		func(token protocol.StatelessResetToken) { removedTokens = append(removedTokens, token) },
		func(f wire.Frame) {},
	)
	m.SetStatelessResetToken(protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1})
	require.Equal(t, []protocol.StatelessResetToken{{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}}, addedTokens)
	require.Empty(t, removedTokens)
	m.Close()
	require.Equal(t, []protocol.StatelessResetToken{{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}}, removedTokens)

	require.Panics(t, func() { m.Get() })
	require.Panics(t, func() { m.SetStatelessResetToken(protocol.StatelessResetToken{}) })
}

func BenchmarkConnIDManagerReordered(b *testing.B) {
	benchmarkConnIDManager(b, true)
}

func BenchmarkConnIDManagerInOrder(b *testing.B) {
	benchmarkConnIDManager(b, false)
}

func benchmarkConnIDManager(b *testing.B, reordered bool) {
	m := newConnIDManager(
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		func(protocol.StatelessResetToken) {},
		func(protocol.StatelessResetToken) {},
		func(f wire.Frame) {},
	)
	connIDs := make([]protocol.ConnectionID, 0, protocol.MaxActiveConnectionIDs)
	statelessResetTokens := make([]protocol.StatelessResetToken, 0, protocol.MaxActiveConnectionIDs)
	for range protocol.MaxActiveConnectionIDs {
		b := make([]byte, 8)
		rand.Read(b)
		connIDs = append(connIDs, protocol.ParseConnectionID(b))
		var statelessResetToken protocol.StatelessResetToken
		rand.Read(statelessResetToken[:])
		statelessResetTokens = append(statelessResetTokens, statelessResetToken)
	}

	// 1 -> 3
	// 2 -> 1
	// 3 -> 2
	// 4 -> 4
	offsets := []int{2, -1, -1, 0}

	b.ResetTimer()
	for i := range b.N {
		seq := i
		if reordered {
			seq += offsets[i%len(offsets)]
		}
		m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber:      uint64(seq),
			ConnectionID:        connIDs[i%len(connIDs)],
			StatelessResetToken: statelessResetTokens[i%len(statelessResetTokens)],
		})
		if i > protocol.MaxActiveConnectionIDs-2 {
			m.updateConnectionID()
		}
	}
}

// connIDManagerTracker records the frames queued and the stateless reset tokens added and removed
// by the connIDManagers of a connection.
type connIDManagerTracker struct {
	frames                     []wire.Frame
	addedTokens, removedTokens []protocol.StatelessResetToken
}

func (tr *connIDManagerTracker) newConnIDManager(initialDestConnID protocol.ConnectionID) *connIDManager {
	return newConnIDManager(
		initialDestConnID,
		func(token protocol.StatelessResetToken) { tr.addedTokens = append(tr.addedTokens, token) },
		func(token protocol.StatelessResetToken) { tr.removedTokens = append(tr.removedTokens, token) },
		func(f wire.Frame) { tr.frames = append(tr.frames, f) },
	)
}

func (tr *connIDManagerTracker) reset() {
	tr.frames = nil
	tr.addedTokens = nil
	tr.removedTokens = nil
}

func newTestPathNewConnectionIDFrame(id protocol.PathID, seq uint64) *wire.PathNewConnectionIDFrame {
	b := byte(seq)
	p := byte(id)
	return &wire.PathNewConnectionIDFrame{
		PathID:              id,
		SequenceNumber:      seq,
		ConnectionID:        protocol.ParseConnectionID([]byte{p, b, p, b}),
		StatelessResetToken: protocol.StatelessResetToken{p, b, p, b, p, b, p, b, p, b, p, b, p, b, p, b},
	}
}

func TestConnIDManagerMultipathAddAndGet(t *testing.T) {
	var tr connIDManagerTracker
	initialConnID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
	m := newPathConnIDManagers(tr.newConnIDManager(initialConnID))
	m.EnableMultipath()

	// no connection ID available for path 1 yet
	_, ok := m.Get(1)
	require.False(t, ok)
	connID, ok := m.Get(0)
	require.True(t, ok)
	require.Equal(t, initialConnID, connID)

	// the same sequence numbers are used for different paths
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(1, 1))) // reordered
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(1, 0)))
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(2, 0)))
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(0, 1)))
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(1, 0))) // duplicate
	// connection IDs that are not in use don't have active stateless reset tokens
	require.Empty(t, tr.addedTokens)
	require.Empty(t, tr.frames)

	// the first connection ID of a path is used when the path is used
	connID, ok = m.Get(1)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(1, 0).ConnectionID, connID)
	require.Equal(t, []protocol.StatelessResetToken{newTestPathNewConnectionIDFrame(1, 0).StatelessResetToken}, tr.addedTokens)
	connID, ok = m.Get(1)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(1, 0).ConnectionID, connID)
	connID, ok = m.Get(2)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(2, 0).ConnectionID, connID)
	require.Len(t, tr.addedTokens, 2)
	connID, ok = m.Get(0)
	require.True(t, ok)
	require.Equal(t, initialConnID, connID)
	_, ok = m.Get(3)
	require.False(t, ok)
	require.Empty(t, tr.frames)

	// a retransmission of the frame for the connection ID in use doesn't retire it
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(1, 0)))
	require.Empty(t, tr.frames)

	// receiving mismatching connection IDs is not fine
	f := newTestPathNewConnectionIDFrame(1, 1)
	f.ConnectionID = protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})
	err := m.Add(f)
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
	require.ErrorContains(t, err, "received conflicting connection IDs for sequence number 1")

	// after completion of the handshake, path 0 switches to the next connection ID
	m.path0.SetHandshakeComplete()
	connID, ok = m.Get(0)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(0, 1).ConnectionID, connID)
	require.Equal(t, []wire.Frame{&wire.PathRetireConnectionIDFrame{PathID: 0, SequenceNumber: 0}}, tr.frames)
}

// HasConnID and NextSequenceNumber are used to decide if a path can be opened,
// and for the PATH_CIDS_BLOCKED frame (section 4.7 of draft-ietf-quic-multipath-21).
func TestConnIDManagerMultipathAvailableConnIDs(t *testing.T) {
	var tr connIDManagerTracker
	m := newPathConnIDManagers(tr.newConnIDManager(protocol.ParseConnectionID([]byte{1, 2, 3, 4})))
	m.EnableMultipath()

	require.True(t, m.HasConnID(0))
	require.Equal(t, uint64(1), m.NextSequenceNumber(0))
	require.False(t, m.HasConnID(1))
	require.Zero(t, m.NextSequenceNumber(1))

	// reordered frames
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(1, 2)))
	require.True(t, m.HasConnID(1))
	require.Equal(t, uint64(3), m.NextSequenceNumber(1))
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(1, 1)))
	require.Equal(t, uint64(3), m.NextSequenceNumber(1))
	_, ok := m.Get(1)
	require.True(t, ok)
	require.True(t, m.HasConnID(1))

	// the sequence numbers of reordered or retired connection IDs count
	f := newTestPathNewConnectionIDFrame(2, 4)
	f.RetirePriorTo = 4
	require.NoError(t, m.Add(f))
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(2, 3)))
	require.True(t, m.HasConnID(2))
	require.Equal(t, uint64(5), m.NextSequenceNumber(2))

	// abandoned paths can't be used
	m.AbandonPath(1)
	require.False(t, m.HasConnID(1))
	_, ok = m.Get(1)
	require.False(t, ok)
}

func TestConnIDManagerMultipathRetirePriorTo(t *testing.T) {
	var tr connIDManagerTracker
	m := newPathConnIDManagers(tr.newConnIDManager(protocol.ParseConnectionID([]byte{1, 2, 3, 4})))
	m.EnableMultipath()
	for seq := range uint64(3) {
		require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(1, seq)))
	}
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(2, 0)))
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(2, 1)))
	_, ok := m.Get(1)
	require.True(t, ok)
	_, ok = m.Get(2)
	require.True(t, ok)
	tr.reset()

	// Retire Prior To only applies to connection IDs of the same path
	f := newTestPathNewConnectionIDFrame(1, 3)
	f.RetirePriorTo = 2
	require.NoError(t, m.Add(f))
	require.Equal(t, []wire.Frame{
		&wire.PathRetireConnectionIDFrame{PathID: 1, SequenceNumber: 1},
		&wire.PathRetireConnectionIDFrame{PathID: 1, SequenceNumber: 0},
	}, tr.frames)
	require.Equal(t, []protocol.StatelessResetToken{newTestPathNewConnectionIDFrame(1, 0).StatelessResetToken}, tr.removedTokens)
	require.Equal(t, []protocol.StatelessResetToken{newTestPathNewConnectionIDFrame(1, 2).StatelessResetToken}, tr.addedTokens)
	connID, ok := m.Get(1)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(1, 2).ConnectionID, connID)
	connID, ok = m.Get(2)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(2, 0).ConnectionID, connID)
	tr.reset()

	// a NEW_CONNECTION_ID frame only applies to path 0
	require.NoError(t, m.path0.Add(&wire.NewConnectionIDFrame{
		SequenceNumber:      5,
		RetirePriorTo:       5,
		ConnectionID:        protocol.ParseConnectionID([]byte{5, 5, 5, 5}),
		StatelessResetToken: protocol.StatelessResetToken{5},
	}))
	require.Equal(t, []wire.Frame{&wire.PathRetireConnectionIDFrame{PathID: 0, SequenceNumber: 0}}, tr.frames)
	connID, ok = m.Get(0)
	require.True(t, ok)
	require.Equal(t, protocol.ParseConnectionID([]byte{5, 5, 5, 5}), connID)
	connID, ok = m.Get(1)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(1, 2).ConnectionID, connID)
	connID, ok = m.Get(2)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(2, 0).ConnectionID, connID)
	tr.reset()

	// Retire Prior To for a path that doesn't use a connection ID yet
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(3, 0)))
	f = newTestPathNewConnectionIDFrame(3, 2)
	f.RetirePriorTo = 1
	require.NoError(t, m.Add(f))
	require.Equal(t, []wire.Frame{&wire.PathRetireConnectionIDFrame{PathID: 3, SequenceNumber: 0}}, tr.frames)
	require.Empty(t, tr.addedTokens)
	tr.reset()
	// a reordered frame for a connection ID that is retired is retired immediately
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(3, 0)))
	require.Equal(t, []wire.Frame{&wire.PathRetireConnectionIDFrame{PathID: 3, SequenceNumber: 0}}, tr.frames)
	tr.reset()
	connID, ok = m.Get(3)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(3, 2).ConnectionID, connID)
	require.Empty(t, tr.frames)
	// sequence number 1 is smaller than the Retire Prior To value
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(3, 1)))
	require.Equal(t, []wire.Frame{&wire.PathRetireConnectionIDFrame{PathID: 3, SequenceNumber: 1}}, tr.frames)
}

// A packet sent to another 4-tuple than the one a path uses needs another connection ID of the path
// (section 9.5 of RFC 9000).
func TestConnIDManagerMultipathConnIDForTuple(t *testing.T) {
	var tr connIDManagerTracker
	m := newPathConnIDManagers(tr.newConnIDManager(protocol.ParseConnectionID([]byte{1, 2, 3, 4})))
	m.EnableMultipath()

	// no connection ID available for path 1 yet
	_, ok := m.GetConnIDForTuple(1, 0)
	require.False(t, ok)
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(1, 0)))
	// the only connection ID is used by the path itself
	_, ok = m.GetConnIDForTuple(1, 0)
	require.False(t, ok)
	connID, ok := m.Get(1)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(1, 0).ConnectionID, connID)

	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(1, 1)))
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(1, 2)))
	tr.reset()
	connID, ok = m.GetConnIDForTuple(1, 0)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(1, 1).ConnectionID, connID)
	require.Equal(t, []protocol.StatelessResetToken{newTestPathNewConnectionIDFrame(1, 1).StatelessResetToken}, tr.addedTokens)
	require.True(t, m.IsActiveStatelessResetToken(newTestPathNewConnectionIDFrame(1, 1).StatelessResetToken))
	// the same 4-tuple keeps using its connection ID
	connID, ok = m.GetConnIDForTuple(1, 0)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(1, 1).ConnectionID, connID)
	connID, ok = m.GetConnIDForTuple(1, 1)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(1, 2).ConnectionID, connID)
	_, ok = m.GetConnIDForTuple(1, 2)
	require.False(t, ok)
	// the path keeps using its connection ID
	connID, ok = m.Get(1)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(1, 0).ConnectionID, connID)
	// the connection IDs used for 4-tuples count towards the limit
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(1, 3)))
	require.ErrorIs(t,
		m.Add(newTestPathNewConnectionIDFrame(1, 4)),
		&qerr.TransportError{ErrorCode: qerr.ConnectionIDLimitError},
	)
	require.Empty(t, tr.frames)

	// retiring the connection ID of a 4-tuple
	tr.reset()
	m.RetireConnIDForTuple(1, 0)
	require.Equal(t, []wire.Frame{&wire.PathRetireConnectionIDFrame{PathID: 1, SequenceNumber: 1}}, tr.frames)
	require.Equal(t, []protocol.StatelessResetToken{newTestPathNewConnectionIDFrame(1, 1).StatelessResetToken}, tr.removedTokens)
	require.False(t, m.IsActiveStatelessResetToken(newTestPathNewConnectionIDFrame(1, 1).StatelessResetToken))
	connID, ok = m.GetConnIDForTuple(1, 2)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(1, 3).ConnectionID, connID)

	// abandoned paths can't be used
	tr.reset()
	m.AbandonPath(1)
	_, ok = m.GetConnIDForTuple(1, 2)
	require.False(t, ok)
	m.RetireConnIDForTuple(1, 2)
	require.Empty(t, tr.frames)
	require.False(t, m.IsActiveStatelessResetToken(newTestPathNewConnectionIDFrame(1, 3).StatelessResetToken))
}

// When a path migrates to another 4-tuple, the connection ID used for that 4-tuple becomes the path's
// connection ID, and the connection ID used so far is retired (section 9.5 of RFC 9000).
func TestConnIDManagerMultipathUseConnIDForTuple(t *testing.T) {
	var tr connIDManagerTracker
	m := newPathConnIDManagers(tr.newConnIDManager(protocol.ParseConnectionID([]byte{1, 2, 3, 4})))
	m.EnableMultipath()
	for seq := range uint64(3) {
		require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(1, seq)))
	}
	connID, ok := m.Get(1)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(1, 0).ConnectionID, connID)
	_, ok = m.GetConnIDForTuple(1, 0)
	require.True(t, ok)
	_, ok = m.GetConnIDForTuple(1, 1)
	require.True(t, ok)
	// no connection ID is used for this 4-tuple
	require.False(t, m.UseConnIDForTuple(1, 2, invalidPathID))

	tr.reset()
	require.True(t, m.UseConnIDForTuple(1, 1, invalidPathID))
	connID, ok = m.Get(1)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(1, 2).ConnectionID, connID)
	require.Equal(t, []wire.Frame{&wire.PathRetireConnectionIDFrame{PathID: 1, SequenceNumber: 0}}, tr.frames)
	require.Equal(t, []protocol.StatelessResetToken{newTestPathNewConnectionIDFrame(1, 0).StatelessResetToken}, tr.removedTokens)
	require.Empty(t, tr.addedTokens)
	require.True(t, m.IsActiveStatelessResetToken(newTestPathNewConnectionIDFrame(1, 2).StatelessResetToken))
	require.False(t, m.IsActiveStatelessResetToken(newTestPathNewConnectionIDFrame(1, 0).StatelessResetToken))
	// the connection ID of the other 4-tuple is still in use
	connID, ok = m.GetConnIDForTuple(1, 0)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(1, 1).ConnectionID, connID)
	// a retransmitted PATH_NEW_CONNECTION_ID frame for the new active connection ID is not retired
	tr.reset()
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(1, 2)))
	require.Empty(t, tr.frames)

	// path 0 works the same way
	require.NoError(t, m.AddNewConnectionID(&wire.NewConnectionIDFrame{SequenceNumber: 1, ConnectionID: protocol.ParseConnectionID([]byte{9, 9, 9, 9})}))
	_, ok = m.GetConnIDForTuple(0, 0)
	require.True(t, ok)
	tr.reset()
	require.True(t, m.UseConnIDForTuple(0, 0, invalidPathID))
	require.Equal(t, []wire.Frame{&wire.PathRetireConnectionIDFrame{PathID: 0, SequenceNumber: 0}}, tr.frames)
	connID, ok = m.Get(0)
	require.True(t, ok)
	require.Equal(t, protocol.ParseConnectionID([]byte{9, 9, 9, 9}), connID)

	// abandoned paths can't be used
	m.AbandonPath(1)
	require.False(t, m.UseConnIDForTuple(1, 0, invalidPathID))
}

// When a path migrates to another 4-tuple, the connection ID used so far is used to validate the previously active
// 4-tuple (section 9.3.3 of RFC 9000). It was never used towards another address (section 9.5 of RFC 9000).
// It is retired once the previous 4-tuple isn't validated anymore.
func TestConnIDManagerMultipathUseConnIDForTupleKeepsPrevious(t *testing.T) {
	var tr connIDManagerTracker
	m := newPathConnIDManagers(tr.newConnIDManager(protocol.ParseConnectionID([]byte{1, 2, 3, 4})))
	m.EnableMultipath()
	for seq := range uint64(4) {
		require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(1, seq)))
	}
	connID, ok := m.Get(1)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(1, 0).ConnectionID, connID)
	connID, ok = m.GetConnIDForTuple(1, 0)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(1, 1).ConnectionID, connID)
	// The peer retires the active connection ID. The path uses the connection ID with sequence number 2.
	f := newTestPathNewConnectionIDFrame(1, 4)
	f.RetirePriorTo = 1
	require.NoError(t, m.Add(f))
	connID, ok = m.Get(1)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(1, 2).ConnectionID, connID)

	tr.reset()
	require.True(t, m.UseConnIDForTuple(1, 0, 1))
	connID, ok = m.Get(1)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(1, 1).ConnectionID, connID)
	require.Empty(t, tr.frames)
	require.Empty(t, tr.removedTokens)
	// the previous connection ID is used for the previous 4-tuple
	connID, ok = m.GetConnIDForTuple(1, 1)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(1, 2).ConnectionID, connID)
	require.True(t, m.IsActiveStatelessResetToken(newTestPathNewConnectionIDFrame(1, 2).StatelessResetToken))
	// A retransmitted PATH_NEW_CONNECTION_ID frame for it is ignored. It is neither retired, nor used again.
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(1, 2)))
	require.Empty(t, tr.frames)
	connID, ok = m.GetConnIDForTuple(1, 2)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(1, 3).ConnectionID, connID)

	// the previous 4-tuple isn't validated anymore
	m.RetireConnIDForTuple(1, 1)
	require.Equal(t, []wire.Frame{&wire.PathRetireConnectionIDFrame{PathID: 1, SequenceNumber: 2}}, tr.frames)
	require.Equal(t, []protocol.StatelessResetToken{newTestPathNewConnectionIDFrame(1, 2).StatelessResetToken}, tr.removedTokens)
	require.False(t, m.IsActiveStatelessResetToken(newTestPathNewConnectionIDFrame(1, 2).StatelessResetToken))

	// The connection ID used during the handshake doesn't have a stateless reset token. It is retired.
	require.NoError(t, m.AddNewConnectionID(&wire.NewConnectionIDFrame{SequenceNumber: 1, ConnectionID: protocol.ParseConnectionID([]byte{9, 9, 9, 9})}))
	_, ok = m.GetConnIDForTuple(0, 0)
	require.True(t, ok)
	tr.reset()
	require.True(t, m.UseConnIDForTuple(0, 0, 1))
	require.Equal(t, []wire.Frame{&wire.PathRetireConnectionIDFrame{PathID: 0, SequenceNumber: 0}}, tr.frames)
	_, ok = m.GetConnIDForTuple(0, 1)
	require.False(t, ok)
}

// When a path is closed, its connIDManager is removed. The connIDManager of path 0 is kept.
func TestConnIDManagerMultipathRemovePath(t *testing.T) {
	var tr connIDManagerTracker
	m := newPathConnIDManagers(tr.newConnIDManager(protocol.ParseConnectionID([]byte{1, 2, 3, 4})))
	m.EnableMultipath()
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(1, 0)))
	_, ok := m.Get(1)
	require.True(t, ok)
	tr.reset()
	m.AbandonPath(1)
	require.Equal(t, []protocol.StatelessResetToken{newTestPathNewConnectionIDFrame(1, 0).StatelessResetToken}, tr.removedTokens)
	require.Contains(t, m.paths, protocol.PathID(1))
	m.RemovePath(1)
	require.NotContains(t, m.paths, protocol.PathID(1))
	// a path that was never abandoned is closed when it is removed
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(2, 0)))
	_, ok = m.Get(2)
	require.True(t, ok)
	tr.reset()
	m.RemovePath(2)
	require.Equal(t, []protocol.StatelessResetToken{newTestPathNewConnectionIDFrame(2, 0).StatelessResetToken}, tr.removedTokens)
	require.NotContains(t, m.paths, protocol.PathID(2))
	// removing an unknown path is a no-op
	m.RemovePath(3)

	m.RemovePath(0)
	require.True(t, m.path0.closed)
	_, ok = m.Get(0)
	require.False(t, ok)
	require.NoError(t, m.AddNewConnectionID(&wire.NewConnectionIDFrame{SequenceNumber: 1, ConnectionID: protocol.ParseConnectionID([]byte{9, 9, 9, 9})}))
}

func TestConnIDManagerMultipathLimit(t *testing.T) {
	var tr connIDManagerTracker
	m := newPathConnIDManagers(tr.newConnIDManager(protocol.ParseConnectionID([]byte{1, 2, 3, 4})))
	m.EnableMultipath()
	// The limit applies to every path.
	// Before a path is used, all connection IDs are in the queue.
	for id := range protocol.PathID(3) {
		for seq := range uint64(protocol.MaxActiveConnectionIDs) {
			if id == 0 && seq == 0 {
				continue
			}
			require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(id, seq)))
		}
	}
	for id := range protocol.PathID(3) {
		require.ErrorIs(t,
			m.Add(newTestPathNewConnectionIDFrame(id, protocol.MaxActiveConnectionIDs)),
			&qerr.TransportError{ErrorCode: qerr.ConnectionIDLimitError},
		)
	}

	// once a path is used, its active connection ID counts towards the limit
	_, ok := m.Get(1)
	require.True(t, ok)
	require.ErrorIs(t,
		m.Add(newTestPathNewConnectionIDFrame(1, protocol.MaxActiveConnectionIDs)),
		&qerr.TransportError{ErrorCode: qerr.ConnectionIDLimitError},
	)
	// retiring connection IDs using Retire Prior To makes room for new ones
	f := newTestPathNewConnectionIDFrame(1, protocol.MaxActiveConnectionIDs)
	f.RetirePriorTo = 1
	require.NoError(t, m.Add(f))
}

func TestConnIDManagerMultipathPath0RetireFrames(t *testing.T) {
	var tr connIDManagerTracker
	path0 := tr.newConnIDManager(protocol.ParseConnectionID([]byte{1, 2, 3, 4}))
	m := newPathConnIDManagers(path0)
	for seq := uint64(1); seq < protocol.MaxActiveConnectionIDs; seq++ {
		require.NoError(t, path0.Add(&wire.NewConnectionIDFrame{
			SequenceNumber:      seq,
			ConnectionID:        protocol.ParseConnectionID([]byte{byte(seq), 0, 0, 0}),
			StatelessResetToken: protocol.StatelessResetToken{byte(seq)},
		}))
	}
	path0.SetHandshakeComplete()
	// without the multipath extension, RETIRE_CONNECTION_ID frames are used
	require.Equal(t, protocol.ParseConnectionID([]byte{1, 0, 0, 0}), path0.Get())
	require.Equal(t, []wire.Frame{&wire.RetireConnectionIDFrame{SequenceNumber: 0}}, tr.frames)
	tr.reset()

	m.EnableMultipath()
	_, ok := path0.GetConnIDForPath(1)
	require.True(t, ok)
	path0.RetireConnIDForPath(1)
	require.Equal(t, []wire.Frame{&wire.PathRetireConnectionIDFrame{PathID: 0, SequenceNumber: 2}}, tr.frames)
	tr.reset()
	path0.updateConnectionID()
	require.Equal(t, []wire.Frame{&wire.PathRetireConnectionIDFrame{PathID: 0, SequenceNumber: 1}}, tr.frames)
}

func TestConnIDManagerMultipathAbandonPath(t *testing.T) {
	var tr connIDManagerTracker
	m := newPathConnIDManagers(tr.newConnIDManager(protocol.ParseConnectionID([]byte{1, 2, 3, 4})))
	m.EnableMultipath()
	for seq := range uint64(3) {
		require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(1, seq)))
		require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(2, seq)))
	}
	_, ok := m.Get(1)
	require.True(t, ok)
	_, ok = m.Get(2)
	require.True(t, ok)
	// connection ID 1 of path 1 is used to probe a new 4-tuple
	_, ok = m.paths[1].GetConnIDForPath(1)
	require.True(t, ok)
	tr.reset()

	// abandoning the path retires the connection IDs without sending any frames
	m.AbandonPath(1)
	require.Empty(t, tr.frames)
	require.ElementsMatch(t,
		[]protocol.StatelessResetToken{
			newTestPathNewConnectionIDFrame(1, 0).StatelessResetToken,
			newTestPathNewConnectionIDFrame(1, 1).StatelessResetToken,
		},
		tr.removedTokens,
	)
	for seq := range uint64(3) {
		require.False(t, m.IsActiveStatelessResetToken(newTestPathNewConnectionIDFrame(1, seq).StatelessResetToken))
	}
	require.True(t, m.IsActiveStatelessResetToken(newTestPathNewConnectionIDFrame(2, 0).StatelessResetToken))
	_, ok = m.Get(1)
	require.False(t, ok)
	m.SentPacket(1)
	// frames for the abandoned path are ignored
	tr.reset()
	f := newTestPathNewConnectionIDFrame(1, 5)
	f.RetirePriorTo = 5
	require.NoError(t, m.Add(f))
	_, ok = m.Get(1)
	require.False(t, ok)
	// abandoning the path again does nothing
	m.AbandonPath(1)
	require.Empty(t, tr.frames)
	require.Empty(t, tr.removedTokens)
	require.Empty(t, tr.addedTokens)

	// path 2 is not affected
	connID, ok := m.Get(2)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(2, 0).ConnectionID, connID)

	// an unused path ID can be abandoned as well
	m.AbandonPath(5)
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(5, 0)))
	_, ok = m.Get(5)
	require.False(t, ok)
	require.Empty(t, tr.frames)
	require.Empty(t, tr.addedTokens)
}

func TestConnIDManagerMultipathAbandonPath0(t *testing.T) {
	var tr connIDManagerTracker
	path0 := tr.newConnIDManager(protocol.ParseConnectionID([]byte{1, 2, 3, 4}))
	m := newPathConnIDManagers(path0)
	// a NEW_CONNECTION_ID frame provides a connection ID for path 0
	require.NoError(t, m.AddNewConnectionID(&wire.NewConnectionIDFrame{
		SequenceNumber:      1,
		ConnectionID:        protocol.ParseConnectionID([]byte{1, 1, 1, 1}),
		StatelessResetToken: protocol.StatelessResetToken{1},
	}))
	m.EnableMultipath()
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(1, 0)))
	path0.SetHandshakeComplete()
	connID, ok := m.Get(0)
	require.True(t, ok)
	require.Equal(t, protocol.ParseConnectionID([]byte{1, 1, 1, 1}), connID)
	tr.reset()

	m.AbandonPath(0)
	require.Empty(t, tr.frames)
	require.Equal(t, []protocol.StatelessResetToken{{1}}, tr.removedTokens)
	_, ok = m.Get(0)
	require.False(t, ok)
	tr.reset()

	// NEW_CONNECTION_ID and PATH_NEW_CONNECTION_ID frames for the abandoned path are ignored,
	// even if they retire the connection ID that was in use
	require.NoError(t, m.AddNewConnectionID(&wire.NewConnectionIDFrame{
		SequenceNumber:      2,
		RetirePriorTo:       2,
		ConnectionID:        protocol.ParseConnectionID([]byte{2, 2, 2, 2}),
		StatelessResetToken: protocol.StatelessResetToken{2},
	}))
	f := newTestPathNewConnectionIDFrame(0, 3)
	f.RetirePriorTo = 3
	require.NoError(t, m.Add(f))
	_, ok = m.Get(0)
	require.False(t, ok)
	require.Empty(t, tr.frames)
	require.Empty(t, tr.addedTokens)
	require.Empty(t, tr.removedTokens)

	// path 1 is not affected
	connID, ok = m.Get(1)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(1, 0).ConnectionID, connID)
}

// A sequence number used for different connection IDs or stateless reset tokens is a PROTOCOL_VIOLATION,
// see section 19.15 of RFC 9000.
func TestConnIDManagerMultipathConflictingConnIDs(t *testing.T) {
	var tr connIDManagerTracker
	m := newPathConnIDManagers(tr.newConnIDManager(protocol.ParseConnectionID([]byte{1, 2, 3, 4})))
	m.EnableMultipath()
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(1, 0)))
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(1, 1)))
	// the same sequence number on a different path is not a conflict
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(2, 0)))

	f := newTestPathNewConnectionIDFrame(1, 0)
	f.ConnectionID = protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})
	err := m.Add(f)
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
	require.ErrorContains(t, err, "received conflicting connection IDs for sequence number 0")

	f = newTestPathNewConnectionIDFrame(1, 1)
	f.StatelessResetToken = protocol.StatelessResetToken{0xde, 0xad, 0xbe, 0xef}
	err = m.Add(f)
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
	require.ErrorContains(t, err, "received conflicting stateless reset tokens for sequence number 1")
	require.Empty(t, tr.frames)
}

func TestConnIDManagerMultipathStatelessResetTokens(t *testing.T) {
	var tr connIDManagerTracker
	m := newPathConnIDManagers(tr.newConnIDManager(protocol.ParseConnectionID([]byte{1, 2, 3, 4})))
	m.EnableMultipath()
	path0Token := protocol.StatelessResetToken{0xff}
	m.path0.SetStatelessResetToken(path0Token)
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(1, 0)))
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(1, 1)))
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(2, 0)))
	_, ok := m.Get(1)
	require.True(t, ok)
	path1Token := newTestPathNewConnectionIDFrame(1, 0).StatelessResetToken
	path2Token := newTestPathNewConnectionIDFrame(2, 0).StatelessResetToken

	require.True(t, m.IsActiveStatelessResetToken(path0Token))
	require.True(t, m.IsActiveStatelessResetToken(path1Token))
	// connection IDs that are not in use
	require.False(t, m.IsActiveStatelessResetToken(newTestPathNewConnectionIDFrame(1, 1).StatelessResetToken))
	require.False(t, m.IsActiveStatelessResetToken(path2Token))
	_, ok = m.Get(2)
	require.True(t, ok)
	require.True(t, m.IsActiveStatelessResetToken(path2Token))

	m.AbandonPath(1)
	require.False(t, m.IsActiveStatelessResetToken(path1Token))
	require.True(t, m.IsActiveStatelessResetToken(path0Token))
	require.True(t, m.IsActiveStatelessResetToken(path2Token))

	// closing removes the stateless reset tokens of all paths, without sending any frames
	tr.reset()
	m.Close()
	require.ElementsMatch(t, []protocol.StatelessResetToken{path0Token, path2Token}, tr.removedTokens)
	require.Empty(t, tr.frames)
	require.False(t, m.IsActiveStatelessResetToken(path0Token))
	require.False(t, m.IsActiveStatelessResetToken(path2Token))
	_, ok = m.Get(2)
	require.False(t, ok)
	require.Panics(t, func() { m.path0.Get() })
}

func TestConnIDManagerMultipathPreferredAddress(t *testing.T) {
	var tr connIDManagerTracker
	path0 := tr.newConnIDManager(protocol.ParseConnectionID([]byte{1, 2, 3, 4}))
	m := newPathConnIDManagers(path0)
	preferredAddressConnID := protocol.ParseConnectionID([]byte{0xca, 0xfe})
	preferredAddressToken := protocol.StatelessResetToken{0xca, 0xfe}
	require.NoError(t, path0.AddFromPreferredAddress(preferredAddressConnID, preferredAddressToken))
	m.EnableMultipath()

	// the connection ID from the preferred_address transport parameter has sequence number 1 on path 0
	require.NoError(t, m.Add(&wire.PathNewConnectionIDFrame{
		PathID:              0,
		SequenceNumber:      1,
		ConnectionID:        preferredAddressConnID,
		StatelessResetToken: preferredAddressToken,
	}))
	err := m.Add(&wire.PathNewConnectionIDFrame{
		PathID:              0,
		SequenceNumber:      1,
		ConnectionID:        protocol.ParseConnectionID([]byte{0xde, 0xad}),
		StatelessResetToken: preferredAddressToken,
	})
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
	require.ErrorContains(t, err, "received conflicting connection IDs for sequence number 1")
	// sequence number 1 of path 1 is a different connection ID
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(1, 1)))
	path0.SetHandshakeComplete()
	connID, ok := m.Get(0)
	require.True(t, ok)
	require.Equal(t, preferredAddressConnID, connID)
	require.Equal(t, []wire.Frame{&wire.PathRetireConnectionIDFrame{PathID: 0, SequenceNumber: 0}}, tr.frames)
	require.True(t, m.IsActiveStatelessResetToken(preferredAddressToken))
	connID, ok = m.Get(1)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(1, 1).ConnectionID, connID)
}

func TestConnIDManagerMultipathProbingBeforeUse(t *testing.T) {
	var tr connIDManagerTracker
	m := newPathConnIDManagers(tr.newConnIDManager(protocol.ParseConnectionID([]byte{1, 2, 3, 4})))
	m.EnableMultipath()
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(1, 0)))
	_, ok := m.getOrCreate(1).GetConnIDForPath(1)
	require.False(t, ok) // the only connection ID is used by the path itself
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(1, 1)))
	connID, ok := m.getOrCreate(1).GetConnIDForPath(1)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(1, 1).ConnectionID, connID)
	connID, ok = m.Get(1)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(1, 0).ConnectionID, connID)
	require.ElementsMatch(t,
		[]protocol.StatelessResetToken{
			newTestPathNewConnectionIDFrame(1, 0).StatelessResetToken,
			newTestPathNewConnectionIDFrame(1, 1).StatelessResetToken,
		},
		tr.addedTokens,
	)
	// retransmissions don't retire connection IDs in use
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(1, 0)))
	require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(1, 1)))
	require.Empty(t, tr.frames)
	m.getOrCreate(1).RetireConnIDForPath(1)
	require.Equal(t, []wire.Frame{&wire.PathRetireConnectionIDFrame{PathID: 1, SequenceNumber: 1}}, tr.frames)
}

func TestConnIDManagerMultipathRotation(t *testing.T) {
	var tr connIDManagerTracker
	m := newPathConnIDManagers(tr.newConnIDManager(protocol.ParseConnectionID([]byte{1, 2, 3, 4})))
	m.EnableMultipath()
	for seq := range uint64(protocol.MaxActiveConnectionIDs) {
		require.NoError(t, m.Add(newTestPathNewConnectionIDFrame(1, seq)))
	}
	// Unlike on path 0, the first connection ID is not replaced right away:
	// it was never used during the handshake.
	connID, ok := m.Get(1)
	require.True(t, ok)
	require.Equal(t, newTestPathNewConnectionIDFrame(1, 0).ConnectionID, connID)
	var counter int
	for {
		require.Empty(t, tr.frames)
		m.SentPacket(1)
		counter++
		connID, ok := m.Get(1)
		require.True(t, ok)
		if connID != newTestPathNewConnectionIDFrame(1, 0).ConnectionID {
			require.Equal(t, newTestPathNewConnectionIDFrame(1, 1).ConnectionID, connID)
			require.Equal(t, []wire.Frame{&wire.PathRetireConnectionIDFrame{PathID: 1, SequenceNumber: 0}}, tr.frames)
			break
		}
	}
	require.GreaterOrEqual(t, counter, protocol.PacketsPerConnectionID/2)
	require.LessOrEqual(t, counter, protocol.PacketsPerConnectionID*3/2)
}

// The connIDManagers of all paths use the callbacks of the connection.
func TestConnIDManagerMultipathConnection(t *testing.T) {
	t.Run("client", func(t *testing.T) {
		testConnIDManagerMultipathConnection(t, protocol.PerspectiveClient)
	})
	t.Run("server", func(t *testing.T) {
		testConnIDManagerMultipathConnection(t, protocol.PerspectiveServer)
	})
}

func testConnIDManagerMultipathConnection(t *testing.T, pers protocol.Perspective) {
	mockCtrl := gomock.NewController(t)
	var tc *testConnection
	if pers == protocol.PerspectiveClient {
		tc = newClientTestConnection(t, mockCtrl, nil, false)
	} else {
		tc = newServerTestConnection(t, mockCtrl, nil, false)
	}
	require.Same(t, tc.conn.connIDManager, tc.conn.peerConnIDs.path0)

	f := newTestPathNewConnectionIDFrame(1, 0)
	require.NoError(t, tc.conn.peerConnIDs.Add(f))
	require.NoError(t, tc.conn.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 1)))
	tc.connRunner.EXPECT().AddResetToken(f.StatelessResetToken, tc.conn)
	connID, ok := tc.conn.peerConnIDs.Get(1)
	require.True(t, ok)
	require.Equal(t, f.ConnectionID, connID)

	retire := newTestPathNewConnectionIDFrame(1, 2)
	retire.RetirePriorTo = 2
	tc.connRunner.EXPECT().RemoveResetToken(f.StatelessResetToken)
	tc.connRunner.EXPECT().AddResetToken(retire.StatelessResetToken, tc.conn)
	require.NoError(t, tc.conn.peerConnIDs.Add(retire))
	frames, _, _ := tc.conn.framer.Append(nil, nil, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
	require.ElementsMatch(t,
		[]ackhandler.Frame{
			{Frame: &wire.PathRetireConnectionIDFrame{PathID: 1, SequenceNumber: 1}},
			{Frame: &wire.PathRetireConnectionIDFrame{PathID: 1, SequenceNumber: 0}},
		},
		frames,
	)

	tc.connRunner.EXPECT().RemoveResetToken(retire.StatelessResetToken)
	tc.conn.peerConnIDs.AbandonPath(1)

	// NEW_CONNECTION_ID frames are ignored once path 0 was abandoned
	tc.conn.peerConnIDs.AbandonPath(0)
	_, err := tc.conn.handleFrame(
		&wire.NewConnectionIDFrame{
			SequenceNumber:      1,
			RetirePriorTo:       1,
			ConnectionID:        protocol.ParseConnectionID([]byte{1, 1, 1, 1}),
			StatelessResetToken: protocol.StatelessResetToken{1},
		},
		protocol.Encryption1RTT,
		protocol.ParseConnectionID([]byte{9, 9, 9, 9}),
		monotime.Now(),
	)
	require.NoError(t, err)
	frames, _, _ = tc.conn.framer.Append(nil, nil, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
	require.Empty(t, frames)
}

// Without the multipath extension, NEW_CONNECTION_ID frames are handled by the connIDManager.
func TestConnectionHandleNewConnectionIDFrame(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tc := newClientTestConnection(t, mockCtrl, nil, false)
	tc.conn.connIDManager.SetHandshakeComplete()
	f := &wire.NewConnectionIDFrame{
		SequenceNumber:      1,
		RetirePriorTo:       1,
		ConnectionID:        protocol.ParseConnectionID([]byte{1, 1, 1, 1}),
		StatelessResetToken: protocol.StatelessResetToken{1},
	}
	tc.connRunner.EXPECT().AddResetToken(f.StatelessResetToken, tc.conn)
	_, err := tc.conn.handleFrame(f, protocol.Encryption1RTT, protocol.ParseConnectionID([]byte{9, 9, 9, 9}), monotime.Now())
	require.NoError(t, err)
	require.Equal(t, f.ConnectionID, tc.conn.connIDManager.Get())
	frames, _, _ := tc.conn.framer.Append(nil, nil, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
	require.Equal(t, []ackhandler.Frame{{Frame: &wire.RetireConnectionIDFrame{SequenceNumber: 0}}}, frames)

	// a conflicting connection ID is a PROTOCOL_VIOLATION
	require.NoError(t, tc.conn.connIDManager.Add(&wire.NewConnectionIDFrame{
		SequenceNumber:      3,
		ConnectionID:        protocol.ParseConnectionID([]byte{3, 3, 3, 3}),
		StatelessResetToken: protocol.StatelessResetToken{3},
	}))
	_, err = tc.conn.handleFrame(
		&wire.NewConnectionIDFrame{
			SequenceNumber:      3,
			ConnectionID:        protocol.ParseConnectionID([]byte{4, 4, 4, 4}),
			StatelessResetToken: protocol.StatelessResetToken{3},
		},
		protocol.Encryption1RTT,
		protocol.ParseConnectionID([]byte{9, 9, 9, 9}),
		monotime.Now(),
	)
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
}

// The client uses the connection ID from the preferred_address transport parameter for the preferred address.
func TestConnIDManagerPreferredAddressForPath(t *testing.T) {
	var tr connIDManagerTracker
	m := tr.newConnIDManager(protocol.ParseConnectionID([]byte{1, 2, 3, 4}))
	connID := protocol.ParseConnectionID([]byte{0xca, 0xfe})
	token := protocol.StatelessResetToken{0xca, 0xfe}
	m.AddFromPreferredAddressForPath(5, connID, token)
	require.Equal(t, []protocol.StatelessResetToken{token}, tr.addedTokens)
	require.True(t, m.IsActiveStatelessResetToken(token))
	require.Equal(t, uint64(2), m.nextSeq)

	// the connection ID isn't used for other paths, nor for the current path
	m.SetHandshakeComplete()
	require.Equal(t, protocol.ParseConnectionID([]byte{1, 2, 3, 4}), m.Get())
	_, ok := m.GetConnIDForPath(6)
	require.False(t, ok)
	c, ok := m.GetConnIDForPath(5)
	require.True(t, ok)
	require.Equal(t, connID, c)

	// a retransmission of the connection ID is ignored
	require.NoError(t, m.Add(&wire.NewConnectionIDFrame{SequenceNumber: 1, ConnectionID: connID, StatelessResetToken: token}))
	require.Empty(t, tr.frames)

	// switching to the path retires the connection ID used so far
	require.True(t, m.UseConnIDForPath(5, invalidPathID))
	require.Equal(t, connID, m.Get())
	require.Equal(t, []wire.Frame{&wire.RetireConnectionIDFrame{SequenceNumber: 0}}, tr.frames)
}

func TestResetTokenRunners(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	runner1 := NewMockConnRunner(mockCtrl)
	runner2 := NewMockConnRunner(mockCtrl)
	handler1 := NewMockPacketHandler(mockCtrl)
	handler2 := NewMockPacketHandler(mockCtrl)
	r := newResetTokenRunners(runner1, handler1)

	token1 := protocol.StatelessResetToken{1}
	token2 := protocol.StatelessResetToken{2}
	runner1.EXPECT().AddResetToken(token1, handler1)
	r.AddResetToken(token1)
	// the tokens added so far are added to a new runner
	runner2.EXPECT().AddResetToken(token1, handler2)
	r.AddRunner(runner2, handler2)
	// adding the same runner again has no effect
	r.AddRunner(runner2, handler2)
	r.AddRunner(runner1, handler2)

	runner1.EXPECT().AddResetToken(token2, handler1)
	runner2.EXPECT().AddResetToken(token2, handler2)
	r.AddResetToken(token2)
	runner1.EXPECT().RemoveResetToken(token1)
	runner2.EXPECT().RemoveResetToken(token1)
	r.RemoveResetToken(token1)

	// removed tokens are not added to a new runner
	runner3 := NewMockConnRunner(mockCtrl)
	runner3.EXPECT().AddResetToken(token2, handler1)
	r.AddRunner(runner3, handler1)
}
