package quic

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

func TestConnIDGeneratorIssueAndRetire(t *testing.T) {
	t.Run("with initial client destination connection ID", func(t *testing.T) {
		testConnIDGeneratorIssueAndRetire(t, true)
	})
	t.Run("without initial client destination connection ID", func(t *testing.T) {
		testConnIDGeneratorIssueAndRetire(t, false)
	})
}

func testConnIDGeneratorIssueAndRetire(t *testing.T, hasInitialClientDestConnID bool) {
	var (
		added   []protocol.ConnectionID
		removed []protocol.ConnectionID
	)
	var queuedFrames []wire.Frame
	sr := newStatelessResetter(&StatelessResetKey{1, 2, 3, 4})
	var initialClientDestConnID *protocol.ConnectionID
	if hasInitialClientDestConnID {
		connID := protocol.ParseConnectionID([]byte{2, 2, 2, 2})
		initialClientDestConnID = &connID
	}
	g := newConnIDGenerator(
		&packetHandlerMap{},
		protocol.ParseConnectionID([]byte{1, 1, 1, 1}),
		initialClientDestConnID,
		sr,
		connRunnerCallbacks{
			AddConnectionID:    func(c protocol.ConnectionID) { added = append(added, c) },
			RemoveConnectionID: func(c protocol.ConnectionID) { removed = append(removed, c) },
			ReplaceWithClosed:  func([]protocol.ConnectionID, []byte, time.Duration) {},
		},
		func(f wire.Frame) { queuedFrames = append(queuedFrames, f) },
		&protocol.DefaultConnectionIDGenerator{ConnLen: 5},
	)

	require.Empty(t, added)
	require.NoError(t, g.SetMaxActiveConnIDs(4))
	require.Len(t, added, 3)
	require.Len(t, queuedFrames, 3)
	require.Empty(t, removed)
	connIDs := make(map[uint64]protocol.ConnectionID)
	// connection IDs 1, 2 and 3 were issued
	for i, f := range queuedFrames {
		ncid := f.(*wire.NewConnectionIDFrame)
		require.EqualValues(t, i+1, ncid.SequenceNumber)
		require.Equal(t, ncid.ConnectionID, added[i])
		require.Equal(t, ncid.StatelessResetToken, sr.GetStatelessResetToken(ncid.ConnectionID))
		connIDs[ncid.SequenceNumber] = ncid.ConnectionID
	}

	// completing the handshake retires the initial client destination connection ID
	added = added[:0]
	queuedFrames = queuedFrames[:0]
	now := monotime.Now()
	g.SetHandshakeComplete(now)
	require.Empty(t, added)
	require.Empty(t, queuedFrames)
	require.Empty(t, removed)
	g.RemoveRetiredConnIDs(now)
	if hasInitialClientDestConnID {
		require.Equal(t, []protocol.ConnectionID{*initialClientDestConnID}, removed)
		removed = removed[:0]
	} else {
		require.Empty(t, removed)
	}

	// it's invalid to retire a connection ID that hasn't been issued yet
	err := g.Retire(4, protocol.ParseConnectionID([]byte{3, 3, 3, 3}), monotime.Now())
	require.ErrorIs(t, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation}, err)
	require.ErrorContains(t, err, "retired connection ID 4 (highest issued: 3)")
	// it's invalid to retire a connection ID in a packet that uses that connection ID
	err = g.Retire(3, connIDs[3], monotime.Now())
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
	require.ErrorContains(t, err, "was used as the Destination Connection ID on this packet")

	// retiring a connection ID makes us issue a new one
	require.NoError(t, g.Retire(2, protocol.ParseConnectionID([]byte{3, 3, 3, 3}), monotime.Now()))
	g.RemoveRetiredConnIDs(monotime.Now())
	require.Equal(t, []protocol.ConnectionID{connIDs[2]}, removed)
	require.Len(t, queuedFrames, 1)
	require.EqualValues(t, 4, queuedFrames[0].(*wire.NewConnectionIDFrame).SequenceNumber)
	queuedFrames = queuedFrames[:0]
	removed = removed[:0]

	// duplicate retirements don't do anything
	require.NoError(t, g.Retire(2, protocol.ParseConnectionID([]byte{3, 3, 3, 3}), monotime.Now()))
	g.RemoveRetiredConnIDs(monotime.Now())
	require.Empty(t, queuedFrames)
	require.Empty(t, removed)

	// retiring the initial connection ID doesn't make us issue a new one
	require.NoError(t, g.Retire(0, protocol.ParseConnectionID([]byte{3, 3, 3, 3}), monotime.Now()))
	g.RemoveRetiredConnIDs(monotime.Now())
	require.Equal(t, []protocol.ConnectionID{protocol.ParseConnectionID([]byte{1, 1, 1, 1})}, removed)
	require.Empty(t, queuedFrames)
}

func TestConnIDGeneratorRetiring(t *testing.T) {
	initialConnID := protocol.ParseConnectionID([]byte{2, 2, 2, 2})
	var added, removed []protocol.ConnectionID
	g := newConnIDGenerator(
		&packetHandlerMap{},
		protocol.ParseConnectionID([]byte{1, 1, 1, 1}),
		&initialConnID,
		newStatelessResetter(&StatelessResetKey{1, 2, 3, 4}),
		connRunnerCallbacks{
			AddConnectionID:    func(c protocol.ConnectionID) { added = append(added, c) },
			RemoveConnectionID: func(c protocol.ConnectionID) { removed = append(removed, c) },
			ReplaceWithClosed:  func([]protocol.ConnectionID, []byte, time.Duration) {},
		},
		func(f wire.Frame) {},
		&protocol.DefaultConnectionIDGenerator{ConnLen: 5},
	)
	require.NoError(t, g.SetMaxActiveConnIDs(6))
	require.Empty(t, removed)
	require.Len(t, added, 5)

	now := monotime.Now()

	retirements := map[protocol.ConnectionID]monotime.Time{}
	t1 := now.Add(time.Duration(rand.IntN(1000)) * time.Millisecond)
	retirements[initialConnID] = t1
	g.SetHandshakeComplete(t1)
	for i := range 5 {
		t2 := now.Add(time.Duration(rand.IntN(1000)) * time.Millisecond)
		require.NoError(t, g.Retire(uint64(i+1), protocol.ParseConnectionID([]byte{9, 9, 9, 9}), t2))
		retirements[added[i]] = t2

		if rand.IntN(2) == 0 {
			now = now.Add(time.Duration(rand.IntN(500)) * time.Millisecond)
			g.RemoveRetiredConnIDs(now)
			for _, r := range removed {
				require.Contains(t, retirements, r)
				require.LessOrEqual(t, retirements[r], now)
				delete(retirements, r)
			}
			removed = removed[:0]
			for _, r := range retirements {
				require.Greater(t, r, now)
			}
		}
	}
}

func TestConnIDGeneratorRemoveAll(t *testing.T) {
	t.Run("with initial client destination connection ID", func(t *testing.T) {
		testConnIDGeneratorRemoveAll(t, true)
	})
	t.Run("without initial client destination connection ID", func(t *testing.T) {
		testConnIDGeneratorRemoveAll(t, false)
	})
}

func testConnIDGeneratorRemoveAll(t *testing.T, hasInitialClientDestConnID bool) {
	var initialClientDestConnID *protocol.ConnectionID
	if hasInitialClientDestConnID {
		connID := protocol.ParseConnectionID([]byte{2, 2, 2, 2})
		initialClientDestConnID = &connID
	}
	var (
		added   []protocol.ConnectionID
		removed []protocol.ConnectionID
	)
	g := newConnIDGenerator(
		&packetHandlerMap{},
		protocol.ParseConnectionID([]byte{1, 1, 1, 1}),
		initialClientDestConnID,
		newStatelessResetter(&StatelessResetKey{1, 2, 3, 4}),
		connRunnerCallbacks{
			AddConnectionID:    func(c protocol.ConnectionID) { added = append(added, c) },
			RemoveConnectionID: func(c protocol.ConnectionID) { removed = append(removed, c) },
			ReplaceWithClosed:  func([]protocol.ConnectionID, []byte, time.Duration) {},
		},
		func(f wire.Frame) {},
		&protocol.DefaultConnectionIDGenerator{ConnLen: 5},
	)

	require.NoError(t, g.SetMaxActiveConnIDs(1000))
	require.Len(t, added, protocol.MaxIssuedConnectionIDs-1)

	g.RemoveAll()
	if hasInitialClientDestConnID {
		require.Len(t, removed, protocol.MaxIssuedConnectionIDs+1)
		require.Contains(t, removed, *initialClientDestConnID)
	} else {
		require.Len(t, removed, protocol.MaxIssuedConnectionIDs)
	}
	for _, id := range added {
		require.Contains(t, removed, id)
	}
	require.Contains(t, removed, protocol.ParseConnectionID([]byte{1, 1, 1, 1}))
}

func TestConnIDGeneratorReplaceWithClosed(t *testing.T) {
	t.Run("with initial client destination connection ID", func(t *testing.T) {
		testConnIDGeneratorReplaceWithClosed(t, true)
	})
	t.Run("without initial client destination connection ID", func(t *testing.T) {
		testConnIDGeneratorReplaceWithClosed(t, false)
	})
}

func testConnIDGeneratorReplaceWithClosed(t *testing.T, hasInitialClientDestConnID bool) {
	var initialClientDestConnID *protocol.ConnectionID
	if hasInitialClientDestConnID {
		connID := protocol.ParseConnectionID([]byte{2, 2, 2, 2})
		initialClientDestConnID = &connID
	}
	var (
		added        []protocol.ConnectionID
		replaced     []protocol.ConnectionID
		replacedWith []byte
	)
	g := newConnIDGenerator(
		&packetHandlerMap{},
		protocol.ParseConnectionID([]byte{1, 1, 1, 1}),
		initialClientDestConnID,
		newStatelessResetter(&StatelessResetKey{1, 2, 3, 4}),
		connRunnerCallbacks{
			AddConnectionID:    func(c protocol.ConnectionID) { added = append(added, c) },
			RemoveConnectionID: func(c protocol.ConnectionID) { t.Fatal("didn't expect conn ID removals") },
			ReplaceWithClosed: func(connIDs []protocol.ConnectionID, b []byte, _ time.Duration) {
				replaced = connIDs
				replacedWith = b
			},
		},
		func(f wire.Frame) {},
		&protocol.DefaultConnectionIDGenerator{ConnLen: 5},
	)

	require.NoError(t, g.SetMaxActiveConnIDs(1000))
	require.Len(t, added, protocol.MaxIssuedConnectionIDs-1)
	// Retire two of these connection ID.
	// This makes us issue two more connection IDs.
	require.NoError(t, g.Retire(3, protocol.ParseConnectionID([]byte{1, 1, 1, 1}), monotime.Now()))
	require.NoError(t, g.Retire(4, protocol.ParseConnectionID([]byte{1, 1, 1, 1}), monotime.Now()))
	require.Len(t, added, protocol.MaxIssuedConnectionIDs+1)

	g.ReplaceWithClosed([]byte("foobar"), time.Second)
	expected := append([]protocol.ConnectionID{protocol.ParseConnectionID([]byte{1, 1, 1, 1})}, added...)
	if hasInitialClientDestConnID {
		expected = append(expected, *initialClientDestConnID)
	}
	require.ElementsMatch(t, expected, replaced)
	require.Equal(t, []byte("foobar"), replacedWith)
}

func TestConnIDGeneratorAddConnRunner(t *testing.T) {
	initialConnID := protocol.ParseConnectionID([]byte{1, 1, 1, 1})
	clientDestConnID := protocol.ParseConnectionID([]byte{2, 2, 2, 2})

	type connIDTracker struct {
		added, removed, replaced []protocol.ConnectionID
	}

	var tracker1, tracker2, tracker3 connIDTracker
	runner1 := connRunnerCallbacks{
		AddConnectionID:    func(c protocol.ConnectionID) { tracker1.added = append(tracker1.added, c) },
		RemoveConnectionID: func(c protocol.ConnectionID) { tracker1.removed = append(tracker1.removed, c) },
		ReplaceWithClosed: func(connIDs []protocol.ConnectionID, _ []byte, _ time.Duration) {
			tracker1.replaced = append(tracker1.replaced, connIDs...)
		},
	}
	runner2 := connRunnerCallbacks{
		AddConnectionID:    func(c protocol.ConnectionID) { tracker2.added = append(tracker2.added, c) },
		RemoveConnectionID: func(c protocol.ConnectionID) { tracker2.removed = append(tracker2.removed, c) },
		ReplaceWithClosed: func(connIDs []protocol.ConnectionID, _ []byte, _ time.Duration) {
			tracker2.replaced = append(tracker2.replaced, connIDs...)
		},
	}
	runner3 := connRunnerCallbacks{
		AddConnectionID:    func(c protocol.ConnectionID) { tracker3.added = append(tracker3.added, c) },
		RemoveConnectionID: func(c protocol.ConnectionID) { tracker3.removed = append(tracker3.removed, c) },
		ReplaceWithClosed: func(connIDs []protocol.ConnectionID, _ []byte, _ time.Duration) {
			tracker3.replaced = append(tracker3.replaced, connIDs...)
		},
	}

	sr := newStatelessResetter(&StatelessResetKey{1, 2, 3, 4})
	var queuedFrames []wire.Frame

	tr := &packetHandlerMap{}
	g := newConnIDGenerator(
		tr,
		initialConnID,
		&clientDestConnID,
		sr,
		runner1,
		func(f wire.Frame) { queuedFrames = append(queuedFrames, f) },
		&protocol.DefaultConnectionIDGenerator{ConnLen: 5},
	)
	require.NoError(t, g.SetMaxActiveConnIDs(3))
	require.Len(t, tracker1.added, 2)

	// add the second runner - it should get all existing connection IDs
	g.AddConnRunner(&packetHandlerMap{}, runner2)
	require.Len(t, tracker1.added, 2) // unchanged
	require.ElementsMatch(t,
		[]protocol.ConnectionID{initialConnID, clientDestConnID, tracker1.added[0], tracker1.added[1]},
		tracker2.added,
	)

	// adding the same transport again doesn't do anything
	trCopy := tr
	g.AddConnRunner(trCopy, runner3)
	require.Empty(t, tracker3.added)

	var connIDToRetire protocol.ConnectionID
	var seqToRetire uint64
	ncid := queuedFrames[0].(*wire.NewConnectionIDFrame)
	connIDToRetire = ncid.ConnectionID
	seqToRetire = ncid.SequenceNumber

	require.NoError(t, g.Retire(seqToRetire, protocol.ParseConnectionID([]byte{3, 3, 3, 3}), monotime.Now()))
	g.RemoveRetiredConnIDs(monotime.Now())
	require.Equal(t, []protocol.ConnectionID{connIDToRetire}, tracker1.removed)
	require.Equal(t, []protocol.ConnectionID{connIDToRetire}, tracker2.removed)

	tracker1.removed = nil
	tracker2.removed = nil
	g.SetHandshakeComplete(monotime.Now())
	g.RemoveRetiredConnIDs(monotime.Now())
	require.Equal(t, []protocol.ConnectionID{clientDestConnID}, tracker1.removed)
	require.Equal(t, []protocol.ConnectionID{clientDestConnID}, tracker2.removed)

	g.ReplaceWithClosed([]byte("connection closed"), time.Second)
	require.NotEmpty(t, tracker1.replaced)
	require.Equal(t, tracker1.replaced, tracker2.replaced)

	tracker1.removed = nil
	tracker2.removed = nil
	g.RemoveAll()
	require.NotEmpty(t, tracker1.removed)
	require.Equal(t, tracker1.removed, tracker2.removed)
}

// connIDGeneratorTracker records the connection IDs added to and removed from the connection runner,
// and the frames queued by the connIDGenerator.
type connIDGeneratorTracker struct {
	added, removed []protocol.ConnectionID
	frames         []wire.Frame
}

func (tr *connIDGeneratorTracker) callbacks() connRunnerCallbacks {
	return connRunnerCallbacks{
		AddConnectionID:    func(c protocol.ConnectionID) { tr.added = append(tr.added, c) },
		RemoveConnectionID: func(c protocol.ConnectionID) { tr.removed = append(tr.removed, c) },
		ReplaceWithClosed:  func([]protocol.ConnectionID, []byte, time.Duration) {},
	}
}

func (tr *connIDGeneratorTracker) queueControlFrame(f wire.Frame) { tr.frames = append(tr.frames, f) }

// popPathNewConnectionIDFrames returns the queued PATH_NEW_CONNECTION_ID frames,
// and checks that their connection IDs were added to the connection runner.
func (tr *connIDGeneratorTracker) popPathNewConnectionIDFrames(t *testing.T) []*wire.PathNewConnectionIDFrame {
	t.Helper()
	frames := make([]*wire.PathNewConnectionIDFrame, 0, len(tr.frames))
	require.Len(t, tr.added, len(tr.frames))
	for i, f := range tr.frames {
		require.IsType(t, &wire.PathNewConnectionIDFrame{}, f)
		frame := f.(*wire.PathNewConnectionIDFrame)
		require.Equal(t, tr.added[i], frame.ConnectionID)
		require.Zero(t, frame.RetirePriorTo)
		frames = append(frames, frame)
	}
	tr.frames = tr.frames[:0]
	tr.added = tr.added[:0]
	return frames
}

func newMultipathTestConnIDGenerator(tr *connIDGeneratorTracker, initialClientDestConnID *protocol.ConnectionID) *connIDGenerator {
	return newConnIDGenerator(
		&packetHandlerMap{},
		protocol.ParseConnectionID([]byte{1, 1, 1, 1}),
		initialClientDestConnID,
		newStatelessResetter(&StatelessResetKey{1, 2, 3, 4}),
		tr.callbacks(),
		tr.queueControlFrame,
		&protocol.DefaultConnectionIDGenerator{ConnLen: 5},
	)
}

func TestConnIDGeneratorMultipathUnusedPaths(t *testing.T) {
	var tr connIDGeneratorTracker
	sr := newStatelessResetter(&StatelessResetKey{1, 2, 3, 4})
	g := newMultipathTestConnIDGenerator(&tr, nil)
	require.NoError(t, g.SetMaxActiveConnIDs(4))
	require.Len(t, tr.frames, 3)
	for _, f := range tr.frames {
		require.IsType(t, &wire.NewConnectionIDFrame{}, f)
	}
	tr.frames = tr.frames[:0]
	tr.added = tr.added[:0]

	// before the multipath extension is enabled, no connection IDs are issued for other paths
	require.NoError(t, g.SetPeerMaxPathID(3))
	require.NoError(t, g.IssueForUnusedPaths(3))
	require.Empty(t, tr.frames)

	expectPaths := func(t *testing.T, pathIDs ...protocol.PathID) {
		t.Helper()
		frames := tr.popPathNewConnectionIDFrames(t)
		require.Len(t, frames, len(pathIDs))
		for i, f := range frames {
			require.Equal(t, pathIDs[i], f.PathID)
			require.Zero(t, f.SequenceNumber)
			require.Equal(t, sr.GetStatelessResetToken(f.ConnectionID), f.StatelessResetToken)
			id, ok := g.PathForConnID(f.ConnectionID)
			require.True(t, ok)
			require.Equal(t, pathIDs[i], id)
		}
	}

	// one connection ID for every path ID up to the smaller one of the two maximum path IDs
	require.NoError(t, g.EnableMultipath(3, 2))
	expectPaths(t, 1, 2)
	// a smaller (e.g. reordered) or unchanged maximum path ID doesn't change anything
	require.NoError(t, g.SetPeerMaxPathID(1))
	require.NoError(t, g.SetPeerMaxPathID(2))
	expectPaths(t)
	// the peer increases its maximum path ID, but our maximum path ID is smaller
	require.NoError(t, g.SetPeerMaxPathID(5))
	expectPaths(t, 3)
	// we increase our maximum path ID
	require.NoError(t, g.IssueForUnusedPaths(4))
	expectPaths(t, 4)
	require.NoError(t, g.IssueForUnusedPaths(2))
	expectPaths(t)
	// connection IDs are never issued for path IDs larger than the peer's maximum path ID
	require.NoError(t, g.IssueForUnusedPaths(10))
	expectPaths(t, 5)
	require.NoError(t, g.SetPeerMaxPathID(7))
	expectPaths(t, 6, 7)

	require.EqualValues(t, 4, g.NextSequenceNumber(0))
	for id := protocol.PathID(1); id <= 7; id++ {
		require.EqualValues(t, 1, g.NextSequenceNumber(id))
	}
	require.Zero(t, g.NextSequenceNumber(8))
}

func TestConnIDGeneratorMultipathMaxPathID(t *testing.T) {
	var tr connIDGeneratorTracker
	g := newMultipathTestConnIDGenerator(&tr, nil)
	require.NoError(t, g.SetMaxActiveConnIDs(2))
	tr.frames = tr.frames[:0]
	tr.added = tr.added[:0]
	require.NoError(t, g.EnableMultipath(protocol.MaxPathID, 1))
	frames := tr.popPathNewConnectionIDFrames(t)
	require.Len(t, frames, 1)
	require.Equal(t, protocol.PathID(1), frames[0].PathID)
	// pretend that connection IDs were issued for all path IDs up to 2^32-3
	g.nextUnusedPathID = protocol.MaxPathID - 1
	require.NoError(t, g.SetPeerMaxPathID(1<<62-1))
	frames = tr.popPathNewConnectionIDFrames(t)
	require.Len(t, frames, 2)
	require.Equal(t, protocol.MaxPathID-1, frames[0].PathID)
	require.Equal(t, protocol.MaxPathID, frames[1].PathID)
	// no connection IDs are issued for path IDs larger than 2^32-1
	require.NoError(t, g.IssueForUnusedPaths(1<<62-1))
	require.Empty(t, tr.frames)
}

func TestConnIDGeneratorMultipathZeroLengthConnIDs(t *testing.T) {
	var tr connIDGeneratorTracker
	g := newConnIDGenerator(
		&packetHandlerMap{},
		protocol.ConnectionID{},
		nil,
		newStatelessResetter(&StatelessResetKey{1, 2, 3, 4}),
		tr.callbacks(),
		tr.queueControlFrame,
		&protocol.DefaultConnectionIDGenerator{ConnLen: 0},
	)
	require.NoError(t, g.SetMaxActiveConnIDs(4))
	require.NoError(t, g.EnableMultipath(3, 3))
	require.NoError(t, g.TopUpPath(0))
	require.NoError(t, g.TopUpPath(1))
	require.Empty(t, tr.frames)
	require.Empty(t, tr.added)
}

func TestConnIDGeneratorMultipathPath0(t *testing.T) {
	var tr connIDGeneratorTracker
	g := newMultipathTestConnIDGenerator(&tr, nil)
	require.NoError(t, g.SetMaxActiveConnIDs(3))
	require.Len(t, tr.frames, 2)
	connIDs := []protocol.ConnectionID{protocol.ParseConnectionID([]byte{1, 1, 1, 1})}
	for i, f := range tr.frames {
		require.IsType(t, &wire.NewConnectionIDFrame{}, f)
		require.EqualValues(t, i+1, f.(*wire.NewConnectionIDFrame).SequenceNumber)
		connIDs = append(connIDs, f.(*wire.NewConnectionIDFrame).ConnectionID)
	}
	tr.frames = tr.frames[:0]
	tr.added = tr.added[:0]

	require.NoError(t, g.EnableMultipath(0, 0))
	require.Empty(t, tr.frames)

	// connection IDs for path 0 are now issued in PATH_NEW_CONNECTION_ID frames
	require.NoError(t, g.Retire(1, protocol.ParseConnectionID([]byte{9, 9, 9, 9}), monotime.Now()))
	require.NoError(t, g.RetireForPath(0, 2, protocol.ParseConnectionID([]byte{9, 9, 9, 9}), monotime.Now()))
	frames := tr.popPathNewConnectionIDFrames(t)
	require.Len(t, frames, 2)
	for i, f := range frames {
		require.Zero(t, f.PathID)
		require.EqualValues(t, 3+i, f.SequenceNumber)
	}
	require.EqualValues(t, 5, g.NextSequenceNumber(0))

	// unlike without the multipath extension, the initial connection ID is replaced as well
	require.NoError(t, g.Retire(0, protocol.ParseConnectionID([]byte{9, 9, 9, 9}), monotime.Now()))
	frames = tr.popPathNewConnectionIDFrames(t)
	require.Len(t, frames, 1)
	require.Zero(t, frames[0].PathID)
	require.EqualValues(t, 5, frames[0].SequenceNumber)
	require.EqualValues(t, 6, g.NextSequenceNumber(0))

	err := g.RetireForPath(0, 6, protocol.ParseConnectionID([]byte{9, 9, 9, 9}), monotime.Now())
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
	require.ErrorContains(t, err, "retired connection ID 6 (highest issued: 5)")

	now := monotime.Now()
	g.RemoveRetiredConnIDs(now)
	require.ElementsMatch(t, connIDs, tr.removed)
	for _, connID := range connIDs {
		_, ok := g.PathForConnID(connID)
		require.False(t, ok)
	}
}

// With the multipath extension, the peer always has an unused connection ID for path 0,
// even if its active_connection_id_limit is 2.
func TestConnIDGeneratorMultipathReplaceInitialConnID(t *testing.T) {
	t.Run("retired after enabling multipath", func(t *testing.T) {
		testConnIDGeneratorMultipathReplaceInitialConnID(t, false)
	})
	t.Run("retired before enabling multipath", func(t *testing.T) {
		testConnIDGeneratorMultipathReplaceInitialConnID(t, true)
	})
}

func testConnIDGeneratorMultipathReplaceInitialConnID(t *testing.T, retireBeforeEnabling bool) {
	var tr connIDGeneratorTracker
	g := newMultipathTestConnIDGenerator(&tr, nil)
	require.NoError(t, g.SetMaxActiveConnIDs(2))
	require.Len(t, tr.frames, 1)
	tr.frames = tr.frames[:0]
	tr.added = tr.added[:0]
	initialConnID := protocol.ParseConnectionID([]byte{1, 1, 1, 1})
	otherConnID := protocol.ParseConnectionID([]byte{9, 9, 9, 9})

	if retireBeforeEnabling {
		// without the multipath extension, the initial connection ID is not replaced
		require.NoError(t, g.Retire(0, otherConnID, monotime.Now()))
		require.Empty(t, tr.frames)
		require.Len(t, g.path0.active, 1)
	}
	require.NoError(t, g.EnableMultipath(1, 1))
	if retireBeforeEnabling {
		// enabling the multipath extension replaces it
		frames := tr.popPathNewConnectionIDFrames(t)
		require.Len(t, frames, 2)
		require.Equal(t, protocol.PathID(0), frames[0].PathID)
		require.EqualValues(t, 2, frames[0].SequenceNumber)
		require.Equal(t, protocol.PathID(1), frames[1].PathID)
		require.Zero(t, frames[1].SequenceNumber)
	} else {
		frames := tr.popPathNewConnectionIDFrames(t)
		require.Len(t, frames, 1)
		require.Equal(t, protocol.PathID(1), frames[0].PathID)
		require.NoError(t, g.RetireForPath(0, 0, otherConnID, monotime.Now()))
		frames = tr.popPathNewConnectionIDFrames(t)
		require.Len(t, frames, 1)
		require.Zero(t, frames[0].PathID)
		require.EqualValues(t, 2, frames[0].SequenceNumber)
	}
	require.Len(t, g.path0.active, 2)
	require.NotContains(t, g.path0.active, uint64(0))

	// path 1 behaves the same way
	require.NoError(t, g.TopUpPath(1))
	require.Len(t, tr.popPathNewConnectionIDFrames(t), 1)
	require.NoError(t, g.RetireForPath(1, 0, otherConnID, monotime.Now()))
	require.Len(t, tr.popPathNewConnectionIDFrames(t), 1)
	require.Len(t, g.paths[1].active, 2)

	g.RemoveRetiredConnIDs(monotime.Now())
	require.Len(t, tr.removed, 2)
	require.Contains(t, tr.removed, initialConnID)
}

func TestConnIDGeneratorMultipathTopUpPath(t *testing.T) {
	t.Run("active_connection_id_limit", func(t *testing.T) {
		testConnIDGeneratorMultipathTopUpPath(t, 4, 4)
	})
	t.Run("more than we issue", func(t *testing.T) {
		testConnIDGeneratorMultipathTopUpPath(t, 100, protocol.MaxIssuedConnectionIDs)
	})
}

func testConnIDGeneratorMultipathTopUpPath(t *testing.T, limit uint64, expected int) {
	var tr connIDGeneratorTracker
	g := newMultipathTestConnIDGenerator(&tr, nil)
	require.NoError(t, g.SetMaxActiveConnIDs(limit))
	tr.frames = tr.frames[:0]
	tr.added = tr.added[:0]
	require.NoError(t, g.EnableMultipath(2, 2))
	require.Len(t, tr.popPathNewConnectionIDFrames(t), 2)

	require.NoError(t, g.TopUpPath(1))
	frames := tr.popPathNewConnectionIDFrames(t)
	require.Len(t, frames, expected-1)
	for i, f := range frames {
		require.Equal(t, protocol.PathID(1), f.PathID)
		require.EqualValues(t, i+1, f.SequenceNumber)
		id, ok := g.PathForConnID(f.ConnectionID)
		require.True(t, ok)
		require.Equal(t, protocol.PathID(1), id)
	}
	require.EqualValues(t, expected, g.NextSequenceNumber(1))
	require.EqualValues(t, 1, g.NextSequenceNumber(2))

	// the path already has enough connection IDs
	require.NoError(t, g.TopUpPath(1))
	require.NoError(t, g.TopUpPath(0))
	require.Empty(t, tr.frames)

	// path IDs that no connection IDs were issued for yet are not topped up
	require.NoError(t, g.TopUpPath(3))
	require.NoError(t, g.TopUpPath(1000))
	require.Empty(t, tr.frames)
	require.Zero(t, g.NextSequenceNumber(3))
}

func TestConnIDGeneratorMultipathRetireForPath(t *testing.T) {
	var tr connIDGeneratorTracker
	g := newMultipathTestConnIDGenerator(&tr, nil)
	require.NoError(t, g.SetMaxActiveConnIDs(3))
	tr.frames = tr.frames[:0]
	tr.added = tr.added[:0]
	require.NoError(t, g.EnableMultipath(2, 2))
	require.NoError(t, g.TopUpPath(1))
	require.NoError(t, g.TopUpPath(2))
	// connection IDs by path ID and sequence number
	connIDs := make(map[protocol.PathID]map[uint64]protocol.ConnectionID)
	for _, f := range tr.popPathNewConnectionIDFrames(t) {
		if _, ok := connIDs[f.PathID]; !ok {
			connIDs[f.PathID] = make(map[uint64]protocol.ConnectionID)
		}
		connIDs[f.PathID][f.SequenceNumber] = f.ConnectionID
	}
	require.Len(t, connIDs, 2)
	require.Len(t, connIDs[1], 3)
	require.Len(t, connIDs[2], 3)

	otherConnID := protocol.ParseConnectionID([]byte{9, 9, 9, 9})
	// it's invalid to retire a connection ID that hasn't been issued yet
	err := g.RetireForPath(1, 3, otherConnID, monotime.Now())
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
	require.ErrorContains(t, err, "retired connection ID 3 for path 1 (highest issued: 2)")
	err = g.RetireForPath(3, 0, otherConnID, monotime.Now())
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
	require.ErrorContains(t, err, "retired connection ID 0 for path 3 (none issued)")
	// it's invalid to retire a connection ID in a packet that uses that connection ID
	err = g.RetireForPath(1, 1, connIDs[1][1], monotime.Now())
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
	require.ErrorContains(t, err, "was used as the Destination Connection ID on this packet")
	require.Empty(t, tr.frames)

	// Retiring a connection ID of path 1 makes us issue a new connection ID for path 1.
	// The frame can be sent on a different path.
	now := monotime.Now()
	expiry := now.Add(time.Second)
	require.NoError(t, g.RetireForPath(1, 0, connIDs[2][0], expiry))
	frames := tr.popPathNewConnectionIDFrames(t)
	require.Len(t, frames, 1)
	require.Equal(t, protocol.PathID(1), frames[0].PathID)
	require.EqualValues(t, 3, frames[0].SequenceNumber)
	require.EqualValues(t, 4, g.NextSequenceNumber(1))
	require.EqualValues(t, 3, g.NextSequenceNumber(2))

	// the connection ID is removed at expiry
	g.RemoveRetiredConnIDs(now)
	require.Empty(t, tr.removed)
	id, ok := g.PathForConnID(connIDs[1][0])
	require.True(t, ok)
	require.Equal(t, protocol.PathID(1), id)
	g.RemoveRetiredConnIDs(expiry)
	require.Equal(t, []protocol.ConnectionID{connIDs[1][0]}, tr.removed)
	_, ok = g.PathForConnID(connIDs[1][0])
	require.False(t, ok)
	// the connection ID with the same sequence number on path 2 is still active
	id, ok = g.PathForConnID(connIDs[2][0])
	require.True(t, ok)
	require.Equal(t, protocol.PathID(2), id)
	tr.removed = tr.removed[:0]

	// duplicate retirements don't do anything
	require.NoError(t, g.RetireForPath(1, 0, otherConnID, expiry))
	g.RemoveRetiredConnIDs(expiry)
	require.Empty(t, tr.frames)
	require.Empty(t, tr.removed)

	// unlike for path 0, the first connection ID of a path is replaced
	require.NoError(t, g.RetireForPath(2, 0, otherConnID, expiry))
	frames = tr.popPathNewConnectionIDFrames(t)
	require.Len(t, frames, 1)
	require.Equal(t, protocol.PathID(2), frames[0].PathID)
	require.EqualValues(t, 3, frames[0].SequenceNumber)
}

func TestConnIDGeneratorMultipathAbandonPath(t *testing.T) {
	var tr connIDGeneratorTracker
	g := newMultipathTestConnIDGenerator(&tr, nil)
	require.NoError(t, g.SetMaxActiveConnIDs(4))
	tr.frames = tr.frames[:0]
	tr.added = tr.added[:0]
	require.NoError(t, g.EnableMultipath(3, 3))
	require.NoError(t, g.TopUpPath(2))
	var path2ConnIDs, otherConnIDs []protocol.ConnectionID
	for _, f := range tr.popPathNewConnectionIDFrames(t) {
		if f.PathID == 2 {
			path2ConnIDs = append(path2ConnIDs, f.ConnectionID)
		} else {
			otherConnIDs = append(otherConnIDs, f.ConnectionID)
		}
	}
	require.Len(t, path2ConnIDs, 4)
	require.Len(t, otherConnIDs, 2)

	now := monotime.Now()
	g.AbandonPath(2)
	require.Empty(t, tr.frames)
	// The connection IDs stay valid until the path is removed,
	// so that packets that are still in flight on the path don't trigger stateless resets.
	g.RemoveRetiredConnIDs(now.Add(time.Hour))
	require.Empty(t, tr.removed)
	for _, connID := range path2ConnIDs {
		id, ok := g.PathForConnID(connID)
		require.True(t, ok)
		require.Equal(t, protocol.PathID(2), id)
	}

	// no new connection IDs are issued for the abandoned path
	require.NoError(t, g.TopUpPath(2))
	require.NoError(t, g.RetireForPath(2, 1, protocol.ParseConnectionID([]byte{9, 9, 9, 9}), now))
	require.Empty(t, tr.frames)
	err := g.RetireForPath(2, 4, protocol.ParseConnectionID([]byte{9, 9, 9, 9}), now)
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
	require.EqualValues(t, 4, g.NextSequenceNumber(2))
	// the connection ID retired by the peer is removed at expiry
	g.RemoveRetiredConnIDs(now)
	require.Equal(t, []protocol.ConnectionID{path2ConnIDs[1]}, tr.removed)
	tr.removed = tr.removed[:0]

	// when the path is removed, all its connection IDs are removed right away
	g.RemovePath(2)
	require.Empty(t, tr.frames)
	require.ElementsMatch(t, []protocol.ConnectionID{path2ConnIDs[0], path2ConnIDs[2], path2ConnIDs[3]}, tr.removed)
	tr.removed = tr.removed[:0]
	for _, connID := range path2ConnIDs {
		_, ok := g.PathForConnID(connID)
		require.False(t, ok)
	}
	for _, connID := range otherConnIDs {
		_, ok := g.PathForConnID(connID)
		require.True(t, ok)
	}
	require.NotContains(t, g.paths, protocol.PathID(2))
	require.NoError(t, g.TopUpPath(2))
	require.Empty(t, tr.frames)

	// An unused path ID can be abandoned as well.
	// Connection IDs are never issued for it, also after it was removed.
	g.AbandonPath(5)
	g.RemovePath(5)
	require.Empty(t, tr.removed)
	require.NoError(t, g.SetPeerMaxPathID(6))
	require.NoError(t, g.IssueForUnusedPaths(6))
	var pathIDs []protocol.PathID
	for _, f := range tr.popPathNewConnectionIDFrames(t) {
		pathIDs = append(pathIDs, f.PathID)
	}
	require.Equal(t, []protocol.PathID{4, 6}, pathIDs)
	require.NoError(t, g.TopUpPath(5))
	require.Empty(t, tr.frames)
	require.Zero(t, g.NextSequenceNumber(5))
	err = g.RetireForPath(5, 0, protocol.ParseConnectionID([]byte{9, 9, 9, 9}), now)
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
	require.ErrorContains(t, err, "retired connection ID 0 for path 5 (none issued)")
}

// The peer can abandon path IDs that no connection ID was issued for, and every closed path ID allows it to use
// another one. The state kept for these path IDs must not grow with their number.
func TestConnIDGeneratorMultipathAbandonManyUnusedPaths(t *testing.T) {
	var tr connIDGeneratorTracker
	g := newMultipathTestConnIDGenerator(&tr, nil)
	require.NoError(t, g.SetMaxActiveConnIDs(4))
	tr.frames = tr.frames[:0]
	tr.added = tr.added[:0]
	// The peer's maximum path ID is 0, so no connection IDs are issued for other paths.
	require.NoError(t, g.EnableMultipath(3, 0))
	tr.frames = tr.frames[:0]

	const num = 10000
	localMaxPathID := protocol.PathID(3)
	for id := protocol.PathID(1); id <= num; id++ {
		g.AbandonPath(id)
		g.RemovePath(id)
		localMaxPathID++
		require.NoError(t, g.IssueForUnusedPaths(localMaxPathID))
	}
	require.Empty(t, tr.frames)
	require.Empty(t, tr.added)
	require.Zero(t, len(g.paths))
	// consecutive path IDs are stored as a single range (see TestPathIDSetCompact)
	require.Equal(t, num, g.abandonedUnused.Len())

	// Connection IDs are only issued for the path IDs that were not abandoned.
	require.NoError(t, g.SetPeerMaxPathID(localMaxPathID))
	var pathIDs []protocol.PathID
	for _, f := range tr.popPathNewConnectionIDFrames(t) {
		pathIDs = append(pathIDs, f.PathID)
	}
	require.Equal(t, []protocol.PathID{num + 1, num + 2, num + 3}, pathIDs)
	require.Len(t, g.paths, 3)

	// Abandoning a path ID that was already removed doesn't allocate any state.
	g.AbandonPath(1)
	g.RemovePath(1)
	require.Len(t, g.paths, 3)
	require.Equal(t, num, g.abandonedUnused.Len())
}

func TestConnIDGeneratorMultipathAbandonPath0(t *testing.T) {
	var tr connIDGeneratorTracker
	g := newMultipathTestConnIDGenerator(&tr, nil)
	require.NoError(t, g.SetMaxActiveConnIDs(3))
	path0ConnIDs := append([]protocol.ConnectionID{protocol.ParseConnectionID([]byte{1, 1, 1, 1})}, tr.added...)
	tr.frames = tr.frames[:0]
	tr.added = tr.added[:0]
	require.NoError(t, g.EnableMultipath(1, 1))
	require.Len(t, tr.popPathNewConnectionIDFrames(t), 1)

	now := monotime.Now()
	g.AbandonPath(0)
	require.NoError(t, g.Retire(1, protocol.ParseConnectionID([]byte{9, 9, 9, 9}), now))
	require.NoError(t, g.TopUpPath(0))
	require.Empty(t, tr.frames)
	g.RemoveRetiredConnIDs(now)
	require.Equal(t, []protocol.ConnectionID{path0ConnIDs[1]}, tr.removed)
	g.RemovePath(0)
	require.ElementsMatch(t, path0ConnIDs, tr.removed)
	// retransmitted RETIRE_CONNECTION_ID frames are ignored
	require.NoError(t, g.Retire(2, protocol.ParseConnectionID([]byte{9, 9, 9, 9}), now))
	require.NoError(t, g.TopUpPath(0))
	require.Empty(t, tr.frames)
}

func TestConnIDGeneratorPathForConnID(t *testing.T) {
	var tr connIDGeneratorTracker
	initialClientDestConnID := protocol.ParseConnectionID([]byte{2, 2, 2, 2})
	g := newMultipathTestConnIDGenerator(&tr, &initialClientDestConnID)
	for _, connID := range []protocol.ConnectionID{protocol.ParseConnectionID([]byte{1, 1, 1, 1}), initialClientDestConnID} {
		id, ok := g.PathForConnID(connID)
		require.True(t, ok)
		require.Zero(t, id)
	}
	_, ok := g.PathForConnID(protocol.ParseConnectionID([]byte{3, 3, 3, 3}))
	require.False(t, ok)

	// connection IDs issued without the multipath extension belong to path 0
	require.NoError(t, g.SetMaxActiveConnIDs(2))
	require.Len(t, tr.added, 1)
	id, ok := g.PathForConnID(tr.added[0])
	require.True(t, ok)
	require.Zero(t, id)

	// the initial client destination connection ID is removed after completion of the handshake
	now := monotime.Now()
	g.SetHandshakeComplete(now.Add(time.Second))
	g.RemoveRetiredConnIDs(now)
	_, ok = g.PathForConnID(initialClientDestConnID)
	require.True(t, ok)
	g.RemoveRetiredConnIDs(now.Add(time.Second))
	_, ok = g.PathForConnID(initialClientDestConnID)
	require.False(t, ok)
}

func TestConnIDGeneratorMultipathConnRunners(t *testing.T) {
	t.Run("with initial client destination connection ID", func(t *testing.T) {
		testConnIDGeneratorMultipathConnRunners(t, true)
	})
	t.Run("without initial client destination connection ID", func(t *testing.T) {
		testConnIDGeneratorMultipathConnRunners(t, false)
	})
}

func testConnIDGeneratorMultipathConnRunners(t *testing.T, hasInitialClientDestConnID bool) {
	var initialClientDestConnID *protocol.ConnectionID
	if hasInitialClientDestConnID {
		connID := protocol.ParseConnectionID([]byte{2, 2, 2, 2})
		initialClientDestConnID = &connID
	}
	var tr1 connIDGeneratorTracker
	var replaced1 []protocol.ConnectionID
	callbacks1 := tr1.callbacks()
	callbacks1.ReplaceWithClosed = func(connIDs []protocol.ConnectionID, _ []byte, _ time.Duration) {
		replaced1 = append(replaced1, connIDs...)
	}
	g := newConnIDGenerator(
		&packetHandlerMap{},
		protocol.ParseConnectionID([]byte{1, 1, 1, 1}),
		initialClientDestConnID,
		newStatelessResetter(&StatelessResetKey{1, 2, 3, 4}),
		callbacks1,
		tr1.queueControlFrame,
		&protocol.DefaultConnectionIDGenerator{ConnLen: 5},
	)
	require.NoError(t, g.SetMaxActiveConnIDs(3))
	require.NoError(t, g.EnableMultipath(3, 3))
	require.NoError(t, g.TopUpPath(1))
	require.NoError(t, g.TopUpPath(2))
	// retire a connection ID of path 1, and abandon path 3
	var path1ConnID protocol.ConnectionID
	for _, f := range tr1.frames {
		if f, ok := f.(*wire.PathNewConnectionIDFrame); ok && f.PathID == 1 && f.SequenceNumber == 0 {
			path1ConnID = f.ConnectionID
		}
	}
	require.NotZero(t, path1ConnID.Len())
	expiry := monotime.Now().Add(time.Hour)
	require.NoError(t, g.RetireForPath(1, 0, protocol.ParseConnectionID([]byte{9, 9, 9, 9}), expiry))
	g.AbandonPath(3)
	var path3ConnIDs []protocol.ConnectionID
	for _, f := range tr1.frames {
		if f, ok := f.(*wire.PathNewConnectionIDFrame); ok && f.PathID == 3 {
			path3ConnIDs = append(path3ConnIDs, f.ConnectionID)
		}
	}
	require.NotEmpty(t, path3ConnIDs)

	// all connection IDs that were added and not removed
	registered := append([]protocol.ConnectionID{protocol.ParseConnectionID([]byte{1, 1, 1, 1})}, tr1.added...)
	if hasInitialClientDestConnID {
		registered = append(registered, *initialClientDestConnID)
	}
	require.Empty(t, tr1.removed)
	require.Len(t, g.pathOf, len(registered))
	for _, connID := range registered {
		_, ok := g.PathForConnID(connID)
		require.True(t, ok)
	}

	// The new runner learns all active connection IDs of all paths, including those of abandoned paths
	// (packets might still arrive on these paths), but not those that the peer retired.
	var tr2 connIDGeneratorTracker
	g.AddConnRunner(&packetHandlerMap{}, tr2.callbacks())
	var expectedActive []protocol.ConnectionID
	for _, connID := range registered {
		if connID != path1ConnID {
			expectedActive = append(expectedActive, connID)
		}
	}
	require.Len(t, expectedActive, len(registered)-1)
	require.ElementsMatch(t, expectedActive, tr2.added)

	// When the abandoned path is removed, its connection IDs are removed from all runners.
	g.RemovePath(3)
	require.ElementsMatch(t, path3ConnIDs, tr1.removed)
	require.ElementsMatch(t, path3ConnIDs, tr2.removed)
	tr1.removed = tr1.removed[:0]
	tr2.removed = tr2.removed[:0]
	registered = slices.DeleteFunc(registered, func(connID protocol.ConnectionID) bool { return slices.Contains(path3ConnIDs, connID) })

	g.ReplaceWithClosed([]byte("foobar"), time.Second)
	require.ElementsMatch(t, registered, replaced1)

	g.RemoveAll()
	require.ElementsMatch(t, registered, tr1.removed)
	require.ElementsMatch(t, registered, tr2.removed)
	for _, connID := range registered {
		_, ok := g.PathForConnID(connID)
		require.False(t, ok)
	}
}

// The connIDGenerator is used with random operations. After every operation, we check that:
//   - connection IDs are never issued for path IDs larger than the local or the peer's maximum path ID,
//   - connection IDs for new path IDs are issued in ascending order, without holes, skipping abandoned path IDs,
//   - every path ID up to the smaller one of the maximum path IDs has a connection ID, unless it was abandoned,
//   - sequence numbers increase by 1 for every path, and no connection IDs are issued for abandoned paths,
//   - the peer never has more active connection IDs for a path than allowed,
//   - a retired connection ID is replaced, unless it is the initial connection ID or the path was abandoned,
//   - PathForConnID knows exactly the connection IDs that are registered with the connection runner.
func TestConnIDGeneratorMultipathRandomized(t *testing.T) {
	for seed := range uint64(25) {
		t.Run(fmt.Sprintf("seed %d", seed), func(t *testing.T) {
			testConnIDGeneratorMultipathRandomized(t, seed)
		})
	}
}

func testConnIDGeneratorMultipathRandomized(t *testing.T, seed uint64) {
	const limit = 4
	r := rand.New(rand.NewPCG(seed, 42))
	var tr connIDGeneratorTracker
	g := newMultipathTestConnIDGenerator(&tr, nil)

	initialConnID := protocol.ParseConnectionID([]byte{1, 1, 1, 1})
	registered := map[protocol.ConnectionID]struct{}{initialConnID: {}}
	// the model
	active := map[protocol.PathID]map[uint64]protocol.ConnectionID{0: {0: initialConnID}}
	pathOf := map[protocol.ConnectionID]protocol.PathID{initialConnID: 0}
	retiring := make(map[protocol.ConnectionID]monotime.Time)
	nextSeq := map[protocol.PathID]uint64{0: 1}
	abandoned := make(map[protocol.PathID]bool)
	removed := make(map[protocol.PathID]bool) // the connection never passes frames for removed paths
	nextNewPathID := protocol.PathID(1)
	var localMax, peerMax protocol.PathID

	// processIssued checks the issued connection IDs and returns the number of frames per path
	processIssued := func(t *testing.T) map[protocol.PathID]int {
		t.Helper()
		require.Len(t, tr.added, len(tr.frames))
		issued := make(map[protocol.PathID]int)
		for i, f := range tr.frames {
			var id protocol.PathID
			var seq uint64
			var connID protocol.ConnectionID
			switch f := f.(type) {
			case *wire.NewConnectionIDFrame:
				seq, connID = f.SequenceNumber, f.ConnectionID
			case *wire.PathNewConnectionIDFrame:
				id, seq, connID = f.PathID, f.SequenceNumber, f.ConnectionID
			default:
				t.Fatalf("unexpected frame: %#v", f)
			}
			require.Equal(t, tr.added[i], connID)
			require.NotContains(t, registered, connID)
			registered[connID] = struct{}{}
			if id != 0 {
				require.LessOrEqual(t, id, peerMax)
				require.LessOrEqual(t, id, localMax)
			}
			require.False(t, abandoned[id])
			require.Equal(t, nextSeq[id], seq)
			nextSeq[id]++
			if id != 0 && seq == 0 {
				for abandoned[nextNewPathID] {
					nextNewPathID++
				}
				require.Equal(t, nextNewPathID, id)
				nextNewPathID++
			}
			if _, ok := active[id]; !ok {
				active[id] = make(map[uint64]protocol.ConnectionID)
			}
			active[id][seq] = connID
			pathOf[connID] = id
			require.LessOrEqual(t, len(active[id]), min(limit, protocol.MaxIssuedConnectionIDs))
			issued[id]++
		}
		tr.frames = tr.frames[:0]
		tr.added = tr.added[:0]
		return issued
	}

	checkState := func(t *testing.T) {
		t.Helper()
		for _, connID := range tr.removed {
			require.Contains(t, registered, connID)
			delete(registered, connID)
		}
		tr.removed = tr.removed[:0]
		require.Len(t, registered, len(pathOf))
		require.Len(t, g.pathOf, len(pathOf))
		for connID, id := range pathOf {
			require.Contains(t, registered, connID)
			pathID, ok := g.PathForConnID(connID)
			require.True(t, ok)
			require.Equal(t, id, pathID)
		}
		for id := protocol.PathID(1); id <= min(localMax, peerMax); id++ {
			require.True(t, abandoned[id] || nextSeq[id] > 0, "no connection ID for path %d", id)
		}
		for id, seq := range nextSeq {
			if !removed[id] {
				require.Equal(t, seq, g.NextSequenceNumber(id))
			}
		}
	}

	now := monotime.Now()
	require.NoError(t, g.SetMaxActiveConnIDs(limit))
	localMax = protocol.PathID(r.IntN(4))
	peerMax = protocol.PathID(r.IntN(4))
	require.NoError(t, g.EnableMultipath(localMax, peerMax))
	processIssued(t)
	checkState(t)

	for range 300 {
		switch r.IntN(8) {
		case 0:
			v := protocol.PathID(r.IntN(12))
			require.NoError(t, g.SetPeerMaxPathID(v))
			peerMax = max(peerMax, v)
			processIssued(t)
		case 1:
			v := protocol.PathID(r.IntN(12))
			require.NoError(t, g.IssueForUnusedPaths(v))
			localMax = max(localMax, v)
			processIssued(t)
		case 2:
			id := protocol.PathID(r.IntN(14))
			require.NoError(t, g.TopUpPath(id))
			issued := processIssued(t)
			if nextSeq[id] > 0 && !abandoned[id] {
				require.Len(t, active[id], min(limit, protocol.MaxIssuedConnectionIDs))
			} else {
				require.Zero(t, issued[id])
			}
		case 3, 4:
			id := protocol.PathID(r.IntN(14))
			if removed[id] {
				break
			}
			seq := r.Uint64N(nextSeq[id] + 2)
			connID, isActive := active[id][seq]
			sentWith := protocol.ParseConnectionID([]byte{9, 9, 9, 9})
			if isActive && r.IntN(4) == 0 {
				sentWith = connID
			}
			expiry := now.Add(time.Duration(r.IntN(1000)) * time.Millisecond)
			err := g.RetireForPath(id, seq, sentWith, expiry)
			if seq >= nextSeq[id] || (isActive && connID == sentWith) {
				require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
				require.Empty(t, tr.frames)
				break
			}
			require.NoError(t, err)
			if isActive {
				delete(active[id], seq)
				retiring[connID] = expiry
			}
			issued := processIssued(t)
			if !isActive {
				require.Empty(t, issued)
				break
			}
			if abandoned[id] {
				require.Empty(t, issued)
			} else {
				require.Equal(t, map[protocol.PathID]int{id: 1}, issued)
			}
		case 5:
			// the connection IDs of an abandoned path stay valid until it is removed
			id := protocol.PathID(r.IntN(14))
			g.AbandonPath(id)
			require.Empty(t, tr.frames)
			abandoned[id] = true
		case 7:
			// only abandoned paths are removed
			id := protocol.PathID(r.IntN(14))
			if !abandoned[id] || removed[id] {
				break
			}
			g.RemovePath(id)
			require.Empty(t, tr.frames)
			removed[id] = true
			var expected []protocol.ConnectionID
			for _, connID := range active[id] {
				expected = append(expected, connID)
				delete(pathOf, connID)
			}
			delete(active, id)
			require.ElementsMatch(t, expected, tr.removed)
		case 6:
			now = now.Add(time.Duration(r.IntN(500)) * time.Millisecond)
			g.RemoveRetiredConnIDs(now)
			var expected []protocol.ConnectionID
			for connID, expiry := range retiring {
				if !expiry.After(now) {
					expected = append(expected, connID)
					delete(retiring, connID)
					delete(pathOf, connID)
				}
			}
			require.ElementsMatch(t, expected, tr.removed)
		}
		checkState(t)
	}
}

type failingConnIDGenerator struct {
	ConnectionIDGenerator
	fail bool
}

func (g *failingConnIDGenerator) GenerateConnectionID() (protocol.ConnectionID, error) {
	if g.fail {
		return protocol.ConnectionID{}, errors.New("no connection ID")
	}
	return g.ConnectionIDGenerator.GenerateConnectionID()
}

func TestConnIDGeneratorMultipathGenerationFailure(t *testing.T) {
	var tr connIDGeneratorTracker
	connIDGen := &failingConnIDGenerator{ConnectionIDGenerator: &protocol.DefaultConnectionIDGenerator{ConnLen: 5}}
	g := newConnIDGenerator(
		&packetHandlerMap{},
		protocol.ParseConnectionID([]byte{1, 1, 1, 1}),
		nil,
		newStatelessResetter(&StatelessResetKey{1, 2, 3, 4}),
		tr.callbacks(),
		tr.queueControlFrame,
		connIDGen,
	)
	require.NoError(t, g.SetMaxActiveConnIDs(2))
	tr.frames = tr.frames[:0]
	tr.added = tr.added[:0]

	connIDGen.fail = true
	require.EqualError(t, g.EnableMultipath(3, 3), "no connection ID")
	require.EqualError(t, g.SetPeerMaxPathID(4), "no connection ID")
	require.EqualError(t, g.IssueForUnusedPaths(4), "no connection ID")
	require.Empty(t, tr.frames)
	require.Zero(t, g.NextSequenceNumber(1))
	require.NoError(t, g.TopUpPath(1)) // no connection ID was issued for path 1 yet

	// the next attempt issues connection IDs for all path IDs, starting with the lowest one
	connIDGen.fail = false
	require.NoError(t, g.IssueForUnusedPaths(4))
	var pathIDs []protocol.PathID
	for _, f := range tr.popPathNewConnectionIDFrames(t) {
		require.Zero(t, f.SequenceNumber)
		pathIDs = append(pathIDs, f.PathID)
	}
	require.Equal(t, []protocol.PathID{1, 2, 3, 4}, pathIDs)

	connIDGen.fail = true
	require.EqualError(t, g.TopUpPath(1), "no connection ID")
	err := g.RetireForPath(1, 0, protocol.ParseConnectionID([]byte{9, 9, 9, 9}), monotime.Now())
	require.EqualError(t, err, "no connection ID")
	require.Empty(t, tr.frames)
}

// With the multipath extension, a packet received after the connection was closed is answered with the
// CONNECTION_CLOSE packet of the path that it was received on. Packets received on other paths, e.g. abandoned paths,
// are not answered.
func TestConnIDGeneratorMultipathReplaceWithClosedPaths(t *testing.T) {
	initialClientDestConnID := protocol.ParseConnectionID([]byte{2, 2, 2, 2})
	var tr connIDGeneratorTracker
	type replaceCall struct {
		connIDs []protocol.ConnectionID
		packet  []byte
	}
	var calls []replaceCall
	callbacks := tr.callbacks()
	callbacks.ReplaceWithClosed = func(connIDs []protocol.ConnectionID, packet []byte, expiry time.Duration) {
		require.Equal(t, time.Second, expiry)
		calls = append(calls, replaceCall{connIDs: connIDs, packet: packet})
	}
	g := newConnIDGenerator(
		&packetHandlerMap{},
		protocol.ParseConnectionID([]byte{1, 1, 1, 1}),
		&initialClientDestConnID,
		newStatelessResetter(&StatelessResetKey{1, 2, 3, 4}),
		callbacks,
		tr.queueControlFrame,
		&protocol.DefaultConnectionIDGenerator{ConnLen: 5},
	)
	require.NoError(t, g.SetMaxActiveConnIDs(3))
	require.NoError(t, g.EnableMultipath(3, 3))
	require.NoError(t, g.TopUpPath(1))
	require.NoError(t, g.TopUpPath(2))
	// the peer retires a connection ID of path 1, it might still be used for a while
	var retiredConnID protocol.ConnectionID
	for _, f := range tr.frames {
		if f, ok := f.(*wire.PathNewConnectionIDFrame); ok && f.PathID == 1 && f.SequenceNumber == 0 {
			retiredConnID = f.ConnectionID
		}
	}
	require.NoError(t, g.RetireForPath(1, 0, protocol.ParseConnectionID([]byte{9, 9, 9, 9}), monotime.Now().Add(time.Hour)))
	g.AbandonPath(2)

	connIDsOf := func(ids ...protocol.PathID) []protocol.ConnectionID {
		var connIDs []protocol.ConnectionID
		for connID, id := range g.pathOf {
			if slices.Contains(ids, id) {
				connIDs = append(connIDs, connID)
			}
		}
		return connIDs
	}
	path0ConnIDs := connIDsOf(0)
	require.Contains(t, path0ConnIDs, initialClientDestConnID)
	path1ConnIDs := connIDsOf(1)
	require.Contains(t, path1ConnIDs, retiredConnID)
	otherConnIDs := connIDsOf(2, 3)
	require.NotEmpty(t, otherConnIDs)

	g.ReplaceWithClosedPaths(map[protocol.PathID][]byte{
		0: []byte("close on path 0"),
		1: []byte("close on path 1"),
	}, time.Second)
	require.Len(t, calls, 3)
	require.ElementsMatch(t, path0ConnIDs, calls[0].connIDs)
	require.Equal(t, []byte("close on path 0"), calls[0].packet)
	require.ElementsMatch(t, path1ConnIDs, calls[1].connIDs)
	require.Equal(t, []byte("close on path 1"), calls[1].packet)
	// the connection IDs of the abandoned path, and of the unused path
	require.ElementsMatch(t, otherConnIDs, calls[2].connIDs)
	require.Nil(t, calls[2].packet)
}

// The connection ID sent in the preferred_address transport parameter has sequence number 1,
// and counts towards the peer's active_connection_id_limit (section 18.2 of RFC 9000).
// With the multipath extension, it belongs to path 0 (section 2.2 of draft-ietf-quic-multipath-21).
func TestConnIDGeneratorPreferredAddress(t *testing.T) {
	for _, multipath := range []bool{false, true} {
		name := "without multipath"
		if multipath {
			name = "with multipath"
		}
		t.Run(name, func(t *testing.T) {
			var added, removed []protocol.ConnectionID
			var queuedFrames []wire.Frame
			sr := newStatelessResetter(&StatelessResetKey{1, 2, 3, 4})
			g := newConnIDGenerator(
				&packetHandlerMap{},
				protocol.ParseConnectionID([]byte{1, 1, 1, 1}),
				nil,
				sr,
				connRunnerCallbacks{
					AddConnectionID:    func(c protocol.ConnectionID) { added = append(added, c) },
					RemoveConnectionID: func(c protocol.ConnectionID) { removed = append(removed, c) },
					ReplaceWithClosed:  func([]protocol.ConnectionID, []byte, time.Duration) {},
				},
				func(f wire.Frame) { queuedFrames = append(queuedFrames, f) },
				&protocol.DefaultConnectionIDGenerator{ConnLen: 5},
			)
			connID, token, err := g.IssuePreferredAddressConnID()
			require.NoError(t, err)
			require.Equal(t, 5, connID.Len())
			require.Equal(t, sr.GetStatelessResetToken(connID), token)
			require.Equal(t, []protocol.ConnectionID{connID}, added)
			require.Empty(t, queuedFrames)
			id, ok := g.PathForConnID(connID)
			require.True(t, ok)
			require.Zero(t, id)

			if multipath {
				g.EnableMultipath(0, 0)
			}
			// connection IDs 2 and 3 are issued
			require.NoError(t, g.SetMaxActiveConnIDs(4))
			require.Len(t, queuedFrames, 2)
			var seqs []uint64
			for _, f := range queuedFrames {
				if multipath {
					require.Zero(t, f.(*wire.PathNewConnectionIDFrame).PathID)
					seqs = append(seqs, f.(*wire.PathNewConnectionIDFrame).SequenceNumber)
				} else {
					seqs = append(seqs, f.(*wire.NewConnectionIDFrame).SequenceNumber)
				}
			}
			require.Equal(t, []uint64{2, 3}, seqs)
			queuedFrames = nil

			// retiring the connection ID issues a new one
			require.NoError(t, g.Retire(1, protocol.ParseConnectionID([]byte{1, 1, 1, 1}), monotime.Now()))
			require.Len(t, queuedFrames, 1)
			g.RemoveRetiredConnIDs(monotime.Now().Add(time.Hour))
			require.Equal(t, []protocol.ConnectionID{connID}, removed)

			require.Panics(t, func() { g.IssuePreferredAddressConnID() })
		})
	}
}

// sequenceConnIDGenerator returns the connection IDs in order.
type sequenceConnIDGenerator struct {
	connIDs []protocol.ConnectionID
}

func (g *sequenceConnIDGenerator) GenerateConnectionID() (protocol.ConnectionID, error) {
	if len(g.connIDs) == 0 {
		return protocol.ConnectionID{}, errors.New("no connection ID")
	}
	c := g.connIDs[0]
	g.connIDs = g.connIDs[1:]
	return c, nil
}

func (g *sequenceConnIDGenerator) ConnectionIDLen() int { return 4 }

// A connection ID is never issued twice on a connection (section 5.1 of RFC 9000),
// and not used by two connections of a Transport (section 10.3.2 of RFC 9000).
func TestConnIDGeneratorUniqueConnIDs(t *testing.T) {
	initialConnID := protocol.ParseConnectionID([]byte{1, 1, 1, 1})
	initialClientDestConnID := protocol.ParseConnectionID([]byte{2, 2, 2, 2})
	otherConnID := protocol.ParseConnectionID([]byte{3, 3, 3, 3}) // used by another connection of the Transport
	connID4 := protocol.ParseConnectionID([]byte{4, 4, 4, 4})
	connID5 := protocol.ParseConnectionID([]byte{5, 5, 5, 5})

	tr := &packetHandlerMap{handlers: map[protocol.ConnectionID]packetHandler{otherConnID: &mockPacketHandler{}}}
	gen := &sequenceConnIDGenerator{
		connIDs: []protocol.ConnectionID{initialConnID, initialClientDestConnID, otherConnID, connID4, connID4, connID5},
	}
	var added []protocol.ConnectionID
	g := newConnIDGenerator(
		tr,
		initialConnID,
		&initialClientDestConnID,
		newStatelessResetter(&StatelessResetKey{1, 2, 3, 4}),
		connRunnerCallbacks{
			AddConnectionID:    func(c protocol.ConnectionID) { added = append(added, c) },
			RemoveConnectionID: func(protocol.ConnectionID) {},
			ReplaceWithClosed:  func([]protocol.ConnectionID, []byte, time.Duration) {},
		},
		func(wire.Frame) {},
		gen,
	)
	require.NoError(t, g.SetMaxActiveConnIDs(3))
	require.Equal(t, []protocol.ConnectionID{connID4, connID5}, added)
	require.Empty(t, gen.connIDs)

	// The retired connection ID is kept until it is removed, so it is not issued again.
	// If the generator only returns connection IDs that are in use, issuing a new one fails.
	for range maxConnIDGenerationAttempts {
		gen.connIDs = append(gen.connIDs, connID4)
	}
	require.ErrorContains(t,
		g.Retire(1, initialConnID, monotime.Now().Add(time.Second)),
		"failed to generate an unused connection ID",
	)
}

// A connection ID is never issued twice on a connection (section 5.1 of RFC 9000), also after it was retired and
// removed. With the built-in generator, this holds for any number of connection IDs.
func TestConnIDGeneratorNeverReissuesConnIDs(t *testing.T) {
	const connLen = 4
	initialConnID := protocol.ParseConnectionID([]byte{1, 1, 1, 1})
	initialClientDestConnID := protocol.ParseConnectionID([]byte{2, 2, 2, 2})
	issued := make(map[protocol.ConnectionID]struct{})
	var numIssued int
	var lastSeq uint64
	g := newConnIDGenerator(
		&packetHandlerMap{},
		initialConnID,
		&initialClientDestConnID,
		newStatelessResetter(&StatelessResetKey{1, 2, 3, 4}),
		connRunnerCallbacks{
			AddConnectionID: func(c protocol.ConnectionID) {
				issued[c] = struct{}{}
				numIssued++
			},
			RemoveConnectionID: func(protocol.ConnectionID) {},
			ReplaceWithClosed:  func([]protocol.ConnectionID, []byte, time.Duration) {},
		},
		func(f wire.Frame) { lastSeq = f.(*wire.NewConnectionIDFrame).SequenceNumber },
		&protocol.DefaultConnectionIDGenerator{ConnLen: connLen},
	)
	require.IsType(t, &connIDPermutation{}, g.generator)
	require.NoError(t, g.SetMaxActiveConnIDs(2))
	require.Equal(t, uint64(1), lastSeq)

	now := monotime.Now()
	const n = 1<<16 + 1000
	for i := uint64(1); i <= n; i++ {
		require.NoError(t, g.Retire(i, initialConnID, now))
		// the retired connection IDs are removed right away
		g.RemoveRetiredConnIDs(now)
		require.Equal(t, i+1, lastSeq)
	}
	require.Equal(t, n+1, numIssued)
	require.Len(t, issued, numIssued)
	require.NotContains(t, issued, initialConnID)
	require.NotContains(t, issued, initialClientDestConnID)
	for connID := range issued {
		require.Equal(t, connLen, connID.Len())
	}
}

// The connection IDs used before the connection was created are never issued again.
func TestConnIDGeneratorDoesntIssueInitialConnIDs(t *testing.T) {
	initialConnID := protocol.ParseConnectionID([]byte{1, 1, 1, 1})
	initialClientDestConnID := protocol.ParseConnectionID([]byte{2, 2, 2, 2})
	connID3 := protocol.ParseConnectionID([]byte{3, 3, 3, 3})
	gen := &sequenceConnIDGenerator{connIDs: []protocol.ConnectionID{connID3}}
	var added []protocol.ConnectionID
	g := newConnIDGenerator(
		&packetHandlerMap{},
		initialConnID,
		&initialClientDestConnID,
		newStatelessResetter(&StatelessResetKey{1, 2, 3, 4}),
		connRunnerCallbacks{
			AddConnectionID:    func(c protocol.ConnectionID) { added = append(added, c) },
			RemoveConnectionID: func(protocol.ConnectionID) {},
			ReplaceWithClosed:  func([]protocol.ConnectionID, []byte, time.Duration) {},
		},
		func(wire.Frame) {},
		gen,
	)
	require.NoError(t, g.SetMaxActiveConnIDs(2))
	require.Equal(t, []protocol.ConnectionID{connID3}, added)

	// the initial connection IDs are retired and removed
	now := monotime.Now()
	g.SetHandshakeComplete(now)
	require.NoError(t, g.Retire(0, connID3, now))
	g.RemoveRetiredConnIDs(now)
	_, ok := g.PathForConnID(initialConnID)
	require.False(t, ok)
	_, ok = g.PathForConnID(initialClientDestConnID)
	require.False(t, ok)

	connID4 := protocol.ParseConnectionID([]byte{4, 4, 4, 4})
	gen.connIDs = []protocol.ConnectionID{initialConnID, initialClientDestConnID, connID4}
	require.NoError(t, g.Retire(1, initialConnID, now))
	require.Equal(t, []protocol.ConnectionID{connID3, connID4}, added)
	require.Empty(t, gen.connIDs)
}

// An endpoint that uses zero-length connection IDs treats every RETIRE_CONNECTION_ID frame as a
// PROTOCOL_VIOLATION (section 19.16 of RFC 9000).
func TestConnIDGeneratorZeroLengthRetire(t *testing.T) {
	g := newConnIDGenerator(
		&packetHandlerMap{},
		protocol.ConnectionID{},
		nil,
		newStatelessResetter(&StatelessResetKey{1, 2, 3, 4}),
		connRunnerCallbacks{
			AddConnectionID:    func(protocol.ConnectionID) {},
			RemoveConnectionID: func(protocol.ConnectionID) {},
			ReplaceWithClosed:  func([]protocol.ConnectionID, []byte, time.Duration) {},
		},
		func(wire.Frame) { t.Fatal("didn't expect any frames") },
		&protocol.DefaultConnectionIDGenerator{ConnLen: 0},
	)
	require.NoError(t, g.SetMaxActiveConnIDs(4))
	for _, seq := range []uint64{0, 1, 2} {
		err := g.Retire(seq, protocol.ConnectionID{}, monotime.Now().Add(time.Second))
		var transportErr *qerr.TransportError
		require.ErrorAs(t, err, &transportErr)
		require.Equal(t, qerr.ProtocolViolation, transportErr.ErrorCode)
	}
}
