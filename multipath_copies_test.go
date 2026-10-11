package quic

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/wire"
	"github.com/AeonDave/mp-quic-go/qlog"
	"github.com/AeonDave/mp-quic-go/testutils/events"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// countingFrameHandler counts how often the frames it handles are acknowledged and lost.
type countingFrameHandler struct {
	acked, lost int
}

func (h *countingFrameHandler) OnAcked(wire.Frame) { h.acked++ }
func (h *countingFrameHandler) OnLost(wire.Frame)  { h.lost++ }

// newMPCopiesTestConn returns a client connection using IETF Multipath QUIC with an active path 1.
// The multipath controller sends data on the path with the highest path ID.
func newMPCopiesTestConn(t *testing.T) *mpPathTestConn {
	t.Helper()
	tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
	c := tc.conn
	c.multipathController = &selectingTestController{selectPath: func(paths []PathInfo) PathID { return paths[len(paths)-1].ID }}
	require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
	pathConn := newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{})
	tc.openTestPath(t, tc.newTestPath(pathConn))
	return tc
}

// sendTestPacket registers a packet sent on a path.
func (tc *mpPathTestConn) sendTestPacket(pathID protocol.PathID, frames []ackhandler.Frame, streamFrames []ackhandler.StreamFrame) shortHeaderPacket {
	p := tc.packPacket(pathID, frames, 1000, false)
	p.StreamFrames = streamFrames
	tc.conn.registerPackedShortHeaderPacket(p, protocol.ECNNon, monotime.Now())
	return p
}

// The reinjection policy selects the path that lost frames are retransmitted on.
// With IETF Multipath QUIC, the lost frames are tracked by path ID and packet number.
func TestMultipathReinjectionOnOtherPath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPCopiesTestConn(t)
		c := tc.conn
		policy := NewMultipathReinjectionPolicy()
		policy.Enable()
		policy.SetReinjectionDelay(0)
		c.multipathReinjectionManager = NewMultipathReinjectionManager(policy)
		c.setupMultipathObservers()

		// data is sent on path 1
		paths, _ := tc.sendTestDataPackets(t, 3)
		requireOnlyPath(t, paths, 1)

		// The first packet sent on path 1 is lost. Its frame is queued for retransmission.
		var pns []protocol.PacketNumber
		for i := range 4 {
			f := &wire.MaxDataFrame{MaximumData: protocol.ByteCount(1000 + i)}
			pns = append(pns, tc.sendTestPacket(1, []ackhandler.Frame{{Frame: f, Handler: c.retransmissionQueue.AckHandler(protocol.Encryption1RTT)}}, nil).PacketNumber)
		}
		require.NoError(t, handleTestFrame(t, c, &wire.AckFrame{PathID: 1, HasPathID: true, AckRanges: ackRangesFor(pns[1:])}, protocol.Encryption1RTT))
		require.True(t, c.retransmissionQueue.HasData(protocol.Encryption1RTT))
		pending, _ := c.multipathReinjectionManager.GetStatistics()
		require.Equal(t, 1, pending)

		// The retransmission is sent on path 0, although the controller selects path 1.
		var retransmitted []wire.Frame
		tc.appendPacket = func(buf *packetBuffer, maxSize protocol.ByteCount, pathID protocol.PathID) (shortHeaderPacket, error) {
			if len(retransmitted) > 0 {
				return shortHeaderPacket{}, errNothingToPack
			}
			f := c.retransmissionQueue.GetFrame(protocol.Encryption1RTT, maxSize, protocol.Version1)
			require.NotNil(t, f)
			retransmitted = append(retransmitted, f)
			require.Equal(t, protocol.PathID(0), pathID)
			buf.Data = append(buf.Data, make([]byte, 100)...)
			return tc.packPacket(pathID, []ackhandler.Frame{{Frame: f}}, 100, false), nil
		}
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Equal(t, []wire.Frame{&wire.MaxDataFrame{MaximumData: 1000}}, retransmitted)
		_, reinjected := c.multipathReinjectionManager.GetStatistics()
		require.Equal(t, 1, reinjected)
	})
}

// reinjectionTargetController selects the path that lost frames are reinjected on.
type reinjectionTargetController struct {
	selectingTestController
	target     PathID
	candidates [][]PathID // the IDs of the candidate paths passed to SelectReinjectionTarget
}

var _ MultipathReinjectionTargetSelector = &reinjectionTargetController{}

func (c *reinjectionTargetController) SelectReinjectionTarget(ctx ReinjectionTargetContext) (PathID, bool) {
	ids := make([]PathID, 0, len(ctx.Candidates))
	for _, p := range ctx.Candidates {
		ids = append(ids, p.ID)
	}
	c.candidates = append(c.candidates, ids)
	return c.target, true
}

// A controller implementing MultipathReinjectionTargetSelector selects the path that lost frames are reinjected on.
// The candidates are the paths that data is sent on, except for the path that the frames were lost on.
func TestMultipathReinjectionTargetSelector(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
		c := tc.conn
		ctrl := &reinjectionTargetController{target: 2}
		ctrl.selectPath = func(paths []PathInfo) PathID { return paths[0].ID }
		c.multipathController = ctrl
		for id := protocol.PathID(1); id <= 2; id++ {
			require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(id, 0)))
			require.Equal(t, id, tc.openTestPath(t, tc.newTestPath(newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{}))))
		}
		policy := NewMultipathReinjectionPolicy()
		policy.Enable()
		policy.SetReinjectionDelay(0)
		c.multipathReinjectionManager = NewMultipathReinjectionManager(policy)
		c.setupMultipathObservers()

		handler := &countingFrameHandler{}
		frames := []ackhandler.Frame{{Frame: &wire.MaxDataFrame{MaximumData: 1000}, Handler: handler}}
		c.multipathReinjectionManager.OnPacketLost(0, 1, protocol.Encryption1RTT, frames)
		c.handlePendingReinjections(monotime.Now())
		require.Equal(t, [][]PathID{{1, 2}}, ctrl.candidates)
		// Without the controller, path 1 would have been selected: all paths have the same RTT.
		require.Equal(t, []protocol.PathID{2}, c.reinjectionPathQueue)
		// the frames were already handed to OnLost by the loss detection
		require.Zero(t, handler.lost)
	})
}

// The reinjection policy limits the number of lost packets queued for reinjection on a path.
func TestMultipathReinjectionQueueLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPCopiesTestConn(t)
		c := tc.conn
		policy := NewMultipathReinjectionPolicy()
		policy.Enable()
		policy.SetReinjectionDelay(0)
		policy.SetMaxReinjectionQueuePerPath(1)
		c.multipathReinjectionManager = NewMultipathReinjectionManager(policy)
		c.setupMultipathObservers()

		handler := &countingFrameHandler{}
		frames := []ackhandler.Frame{{Frame: &wire.MaxDataFrame{MaximumData: 1000}, Handler: handler}}
		c.multipathReinjectionManager.OnPacketLost(0, 1, protocol.Encryption1RTT, frames)
		c.multipathReinjectionManager.OnPacketLost(0, 2, protocol.Encryption1RTT, frames)
		c.handlePendingReinjections(monotime.Now())
		// The frames were lost on path 0, and are reinjected on path 1.
		// Only one lost packet is queued for path 1.
		require.Equal(t, []protocol.PathID{1}, c.reinjectionPathQueue)
		pending, reinjected := c.multipathReinjectionManager.GetStatistics()
		require.Equal(t, 1, pending)
		require.Equal(t, 1, reinjected)

		// once the next packet carrying retransmissions was sent on path 1, the next lost packet is queued
		c.retransmissionQueue.addAppData(&wire.MaxDataFrame{MaximumData: 1000})
		require.Equal(t, c.mp.paths[1], c.reinjectionTargetPath([]*mpPath{c.mp.paths[0], c.mp.paths[1]}))
		c.handlePendingReinjections(monotime.Now())
		require.Equal(t, []protocol.PathID{1}, c.reinjectionPathQueue)
		pending, reinjected = c.multipathReinjectionManager.GetStatistics()
		require.Zero(t, pending)
		require.Equal(t, 2, reinjected)
		require.Zero(t, handler.lost)
	})
}

// When the probe timeout of a path expires, copies of the frames of the packets outstanding on the path are sent on
// another path, if the policy says so (section 5.7 of draft-ietf-quic-multipath-21).
// The copies are not retransmitted.
func TestMultipathReinjectOnPTO(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPCopiesTestConn(t)
		c := tc.conn
		policy := NewMultipathReinjectionPolicy()
		policy.Enable()
		policy.SetReinjectOnPTO(true)
		policy.SetMaxReinjections(1)
		c.multipathReinjectionManager = NewMultipathReinjectionManager(policy)
		c.setupMultipathObservers()

		handler := &countingFrameHandler{}
		var sent []*wire.StreamFrame
		for i := range 2 {
			f := &wire.StreamFrame{StreamID: 4, Offset: protocol.ByteCount(100 * i), Data: bytes.Repeat([]byte{byte(i)}, 100)}
			sent = append(sent, f)
			tc.sendTestPacket(1, nil, []ackhandler.StreamFrame{{Frame: f, Handler: handler}})
		}
		// a packet that doesn't contain any frames that are reinjected
		tc.sendTestPacket(1, []ackhandler.Frame{{Frame: &wire.PingFrame{}}}, nil)

		timeout := c.sentPacketHandler.GetLossDetectionTimeout()
		time.Sleep(monotime.Until(timeout))
		require.NoError(t, c.sentPacketHandler.OnLossDetectionTimeout(monotime.Now()))
		require.Equal(t, ackhandler.SendPTOAppData, c.sentPacketHandler.SendModeForPath(1, monotime.Now()))

		var probePaths []protocol.PathID
		tc.packer.EXPECT().PackPTOProbePacket(protocol.Encryption1RTT, gomock.Any(), gomock.Any(), gomock.Any(), protocol.Version1, gomock.Any()).DoAndReturn(
			func(_ protocol.EncryptionLevel, maxSize protocol.ByteCount, _ bool, _ monotime.Time, _ protocol.Version, pathID protocol.PathID) (*coalescedPacket, error) {
				probePaths = append(probePaths, pathID)
				p := tc.packPacket(pathID, []ackhandler.Frame{{Frame: &wire.PingFrame{}}}, 100, false)
				return &coalescedPacket{buffer: getTestPacketBuffer(100), shortHdrPacket: &p}, nil
			},
		).Times(2)
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Equal(t, []protocol.PathID{1, 1}, probePaths)
		require.Len(t, tc.pathPackets, 1)
		copies := tc.pathPackets[0]
		require.Equal(t, protocol.PathID(0), copies.pathID)
		require.Empty(t, copies.frames)
		require.Len(t, copies.streamFrames, 2)
		for i, f := range copies.streamFrames {
			require.Nil(t, f.Handler)
			require.NotSame(t, sent[i], f.Frame)
			require.Equal(t, sent[i].Offset, f.Frame.Offset)
			require.Equal(t, sent[i].Data, f.Frame.Data)
			require.True(t, f.Frame.DataLenPresent)
		}
		_, reinjected := c.multipathReinjectionManager.GetStatistics()
		require.Equal(t, 2, reinjected)

		// The next PTO: the packets were already reinjected once, and the copies sent on path 0 are not copied again.
		timeout = c.sentPacketHandler.GetLossDetectionTimeout()
		time.Sleep(monotime.Until(timeout))
		require.NoError(t, c.sentPacketHandler.OnLossDetectionTimeout(monotime.Now()))
		tc.packer.EXPECT().PackPTOProbePacket(protocol.Encryption1RTT, gomock.Any(), gomock.Any(), gomock.Any(), protocol.Version1, gomock.Any()).DoAndReturn(
			func(_ protocol.EncryptionLevel, maxSize protocol.ByteCount, _ bool, _ monotime.Time, _ protocol.Version, pathID protocol.PathID) (*coalescedPacket, error) {
				p := tc.packPacket(pathID, []ackhandler.Frame{{Frame: &wire.PingFrame{}}}, 100, false)
				return &coalescedPacket{buffer: getTestPacketBuffer(100), shortHdrPacket: &p}, nil
			},
		).Times(2)
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Len(t, tc.pathPackets, 1)

		// The frames of the packets were sent in the PTO probe packets. These packets are not outstanding anymore,
		// so their reinjection counts are removed the next time the outstanding packets are reinjected.
		require.Len(t, c.multipathReinjectionManager.reinjectedPackets, 2)
		c.maybeReinjectOnPTO(c.mp.paths[1], monotime.Now())
		require.Empty(t, c.multipathReinjectionManager.reinjectedPackets)
		require.Len(t, tc.pathPackets, 1)
	})
}

// When the PTO of a path expires, copies of the frames of its outstanding packets are sent on another path.
// If the path then potentially failed, the packets are declared lost and reported lost.
// No reinjection state is kept for them.
func TestMultipathReinjectOnPTOPathFailed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPCopiesTestConn(t)
		c := tc.conn
		policy := NewMultipathReinjectionPolicy()
		policy.Enable()
		policy.SetReinjectOnPTO(true)
		policy.SetMaxReinjections(1)
		c.multipathReinjectionManager = NewMultipathReinjectionManager(policy)
		c.setupMultipathObservers()

		handler := &countingFrameHandler{}
		for i := range 20 {
			f := &wire.StreamFrame{StreamID: 4, Offset: protocol.ByteCount(100 * i), Data: bytes.Repeat([]byte{byte(i)}, 100)}
			tc.sendTestPacket(1, nil, []ackhandler.StreamFrame{{Frame: f, Handler: handler}})
		}
		tc.expirePTO(t)
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Len(t, tc.copiedFrames(0), 20)
		require.False(t, c.mp.failures.potentiallyFailed(1))
		// the frames of the oldest packets were sent in the PTO probe packets
		require.Equal(t, 2, handler.lost)
		// the copies are acknowledged: path 0 works
		var pns []protocol.PacketNumber
		for _, p := range tc.pathPackets {
			pns = append(pns, p.pn)
		}
		require.NoError(t, handleTestFrame(t, c, &wire.AckFrame{PathID: 0, HasPathID: true, AckRanges: ackRangesFor(pns)}, protocol.Encryption1RTT))

		// path 1 potentially failed: its outstanding packets are declared lost
		time.Sleep(time.Second)
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		require.True(t, c.mp.failures.potentiallyFailed(1))
		require.False(t, c.mp.failures.potentiallyFailed(0))
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Equal(t, 20, handler.lost)
		require.Empty(t, c.multipathReinjectionManager.reinjectedPackets)
		// the packets were reinjected on PTO already, so they are not reinjected again
		pending, _ := c.multipathReinjectionManager.GetStatistics()
		require.Zero(t, pending)
	})
}

// expirePTO lets the probe timeout of the path with the earliest PTO expire,
// and makes the packer return PTO probe packets containing a PING frame.
func (tc *mpPathTestConn) expirePTO(t *testing.T) {
	t.Helper()
	sph := tc.conn.sentPacketHandler
	time.Sleep(monotime.Until(sph.GetLossDetectionTimeout()))
	require.NoError(t, sph.OnLossDetectionTimeout(monotime.Now()))
	tc.packer.EXPECT().PackPTOProbePacket(protocol.Encryption1RTT, gomock.Any(), gomock.Any(), gomock.Any(), protocol.Version1, gomock.Any()).DoAndReturn(
		func(_ protocol.EncryptionLevel, maxSize protocol.ByteCount, _ bool, _ monotime.Time, _ protocol.Version, pathID protocol.PathID) (*coalescedPacket, error) {
			p := tc.packPacket(pathID, []ackhandler.Frame{{Frame: &wire.PingFrame{}}}, 100, false)
			return &coalescedPacket{buffer: getTestPacketBuffer(100), shortHdrPacket: &p}, nil
		},
	).AnyTimes()
}

// copiedFrames returns the frames sent on a path in packets carrying copies.
func (tc *mpPathTestConn) copiedFrames(pathID protocol.PathID) []wire.Frame {
	var frames []wire.Frame
	for _, p := range tc.pathPackets {
		if p.pathID != pathID {
			continue
		}
		for _, f := range p.frames {
			frames = append(frames, f.Frame)
		}
		for _, f := range p.streamFrames {
			frames = append(frames, f.Frame)
		}
	}
	return frames
}

// A sender doesn't send STREAM frames for a stream after it reset the stream (section 3.3 of RFC 9000).
// This also applies to copies sent on another path when the probe timeout of a path expires.
// After a RESET_STREAM_AT frame, the data below the reliable size is still copied.
func TestMultipathReinjectOnPTOAfterStreamReset(t *testing.T) {
	t.Run("RESET_STREAM", func(t *testing.T) {
		testMultipathReinjectOnPTOAfterStreamReset(t, false)
	})
	t.Run("RESET_STREAM_AT", func(t *testing.T) {
		testMultipathReinjectOnPTOAfterStreamReset(t, true)
	})
}

func testMultipathReinjectOnPTOAfterStreamReset(t *testing.T, resetStreamAt bool) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPCopiesTestConn(t)
		c := tc.conn
		policy := NewMultipathReinjectionPolicy()
		policy.Enable()
		policy.SetReinjectOnPTO(true)
		c.multipathReinjectionManager = NewMultipathReinjectionManager(policy)
		c.setupMultipathObservers()

		const streamID protocol.StreamID = 4
		mockSender := NewMockStreamSender(tc.mockCtrl)
		mockSender.EXPECT().onHasStreamData(streamID, gomock.Any()).AnyTimes()
		// Path 1 potentially fails when its PTO expires: the frames sent on it are declared lost.
		mockSender.EXPECT().onHasStreamRetransmission(streamID, gomock.Any()).AnyTimes()
		str := newSendStream(context.Background(), streamID, mockSender, newTestStreamFlowControllerWithSendWindow(streamID, protocol.MaxByteCount), resetStreamAt)
		// lorem | ipsum (reliable size) dolor | sit
		popFrame := func() ackhandler.StreamFrame {
			f, _, _ := str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
			require.NotNil(t, f.Frame)
			return f
		}
		_, err := str.Write([]byte("lorem"))
		require.NoError(t, err)
		tc.sendTestPacket(1, nil, []ackhandler.StreamFrame{popFrame()})
		_, err = str.Write([]byte("ipsum"))
		require.NoError(t, err)
		str.SetReliableBoundary()
		_, err = str.Write([]byte("dolor"))
		require.NoError(t, err)
		tc.sendTestPacket(1, nil, []ackhandler.StreamFrame{popFrame()})
		_, err = str.Write([]byte("sit"))
		require.NoError(t, err)
		tc.sendTestPacket(1, nil, []ackhandler.StreamFrame{popFrame()})
		// a STREAM frame of another stream
		other := &wire.StreamFrame{StreamID: 8, Data: []byte("foobar")}
		tc.sendTestPacket(1, nil, []ackhandler.StreamFrame{{Frame: other, Handler: &countingFrameHandler{}}})

		// the stream is reset, and the RESET_STREAM (or RESET_STREAM_AT) frame is sent
		mockSender.EXPECT().onHasStreamControlFrame(streamID, gomock.Any())
		str.CancelWrite(42)
		cf, ok, _ := str.getControlFrame(monotime.Now())
		require.True(t, ok)
		var reliableSize protocol.ByteCount
		if resetStreamAt {
			reliableSize = 10
		}
		require.Equal(t, &wire.ResetStreamFrame{StreamID: streamID, FinalSize: 18, ErrorCode: 42, ReliableSize: reliableSize}, cf.Frame)

		tc.expirePTO(t)
		require.NoError(t, c.triggerSending(monotime.Now()))
		expected := []wire.Frame{&wire.StreamFrame{StreamID: 8, Data: []byte("foobar"), DataLenPresent: true}}
		if resetStreamAt {
			expected = []wire.Frame{
				&wire.StreamFrame{StreamID: streamID, Data: []byte("lorem"), DataLenPresent: true},
				&wire.StreamFrame{StreamID: streamID, Offset: 5, Data: []byte("ipsum"), DataLenPresent: true},
				expected[0],
			}
		}
		require.Equal(t, expected, tc.copiedFrames(0))
	})
}

// STREAM_DATA_BLOCKED frames are only copied for streams that were not reset, and that still exist
// (section 3.3 of RFC 9000).
func TestMultipathReinjectOnPTOStreamDataBlocked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPCopiesTestConn(t)
		c := tc.conn
		policy := NewMultipathReinjectionPolicy()
		policy.Enable()
		policy.SetReinjectOnPTO(true)
		c.multipathReinjectionManager = NewMultipathReinjectionManager(policy)
		c.setupMultipathObservers()

		c.streamsMap.HandleMaxStreamsFrame(&wire.MaxStreamsFrame{Type: protocol.StreamTypeUni, MaxStreamNum: 10})
		str1, err := c.streamsMap.OpenUniStream()
		require.NoError(t, err)
		str2, err := c.streamsMap.OpenUniStream()
		require.NoError(t, err)
		handler := c.retransmissionQueue.AckHandler(protocol.Encryption1RTT)
		tc.sendTestPacket(1, []ackhandler.Frame{
			{Frame: &wire.StreamDataBlockedFrame{StreamID: str1.StreamID(), MaximumStreamData: 100}, Handler: handler},
			{Frame: &wire.StreamDataBlockedFrame{StreamID: str2.StreamID(), MaximumStreamData: 200}, Handler: handler},
			// a stream that was never opened
			{Frame: &wire.StreamDataBlockedFrame{StreamID: 42, MaximumStreamData: 300}, Handler: handler},
		}, nil)
		str1.CancelWrite(1337)

		tc.expirePTO(t)
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Equal(t,
			[]wire.Frame{&wire.StreamDataBlockedFrame{StreamID: str2.StreamID(), MaximumStreamData: 200}},
			tc.copiedFrames(0),
		)
	})
}

// With frame-level duplication, copies of the frames of a packet are sent on another path.
// The copies don't have handlers: if the packet carrying them is lost, they are not retransmitted.
func TestMultipathDuplicationLostCopy(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPCopiesTestConn(t)
		c := tc.conn
		policy := NewMultipathDuplicationPolicy()
		policy.Enable()
		policy.AddStreamForDuplication(4)
		c.multipathDuplicationPolicy = policy
		reinjection := NewMultipathReinjectionPolicy()
		reinjection.Enable()
		c.multipathReinjectionManager = NewMultipathReinjectionManager(reinjection)
		c.setupMultipathObservers()

		handler := &countingFrameHandler{}
		original := &wire.StreamFrame{StreamID: 4, Data: []byte("foobar"), Fin: true}
		other := &wire.StreamFrame{StreamID: 8, Data: []byte("not duplicated")}
		var sentPacket shortHeaderPacket
		tc.appendPacket = func(buf *packetBuffer, maxSize protocol.ByteCount, pathID protocol.PathID) (shortHeaderPacket, error) {
			if sentPacket.Length > 0 {
				return shortHeaderPacket{}, errNothingToPack
			}
			buf.Data = append(buf.Data, make([]byte, 100)...)
			sentPacket = tc.packPacket(pathID, []ackhandler.Frame{{Frame: &wire.MaxDataFrame{MaximumData: 1000}}}, 100, false)
			sentPacket.StreamFrames = []ackhandler.StreamFrame{{Frame: original, Handler: handler}, {Frame: other, Handler: handler}}
			return sentPacket, nil
		}
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Equal(t, protocol.PathID(1), protocol.PathID(sentPacket.PathID))
		// the copy is sent on path 0
		require.Len(t, tc.pathPackets, 1)
		dup := tc.pathPackets[0]
		require.Equal(t, protocol.PathID(0), dup.pathID)
		require.Empty(t, dup.frames)
		require.Len(t, dup.streamFrames, 1)
		require.Nil(t, dup.streamFrames[0].Handler)
		require.NotSame(t, original, dup.streamFrames[0].Frame)
		require.Equal(t, &wire.StreamFrame{StreamID: 4, Data: []byte("foobar"), Fin: true, DataLenPresent: true}, dup.streamFrames[0].Frame)

		// the packet carrying the copy is lost
		var pns []protocol.PacketNumber
		for range 3 {
			pns = append(pns, tc.sendTestPacket(0, []ackhandler.Frame{{Frame: &wire.PingFrame{}}}, nil).PacketNumber)
		}
		require.NoError(t, handleTestFrame(t, c, &wire.AckFrame{PathID: 0, HasPathID: true, AckRanges: ackRangesFor(pns)}, protocol.Encryption1RTT))
		_, inFlight, ok := c.sentPacketHandler.PathCongestionState(0)
		require.True(t, ok)
		require.Zero(t, inFlight)
		require.Zero(t, handler.lost)
		require.False(t, c.retransmissionQueue.HasData(protocol.Encryption1RTT))
		pending, _ := c.multipathReinjectionManager.GetStatistics()
		require.Zero(t, pending)

		// the original packet is acknowledged
		require.NoError(t, handleTestFrame(t, c, &wire.AckFrame{PathID: 1, HasPathID: true, AckRanges: ackRangesFor([]protocol.PacketNumber{sentPacket.PacketNumber})}, protocol.Encryption1RTT))
		require.Equal(t, 2, handler.acked)
	})
}

// The STREAM frames of a stream that was reset after they were packed are not duplicated,
// like they are not retransmitted (section 3.3 of RFC 9000).
func TestMultipathDuplicationAfterStreamReset(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPCopiesTestConn(t)
		c := tc.conn
		policy := NewMultipathDuplicationPolicy()
		policy.Enable()
		policy.AddStreamForDuplication(4)
		policy.AddStreamForDuplication(8)
		c.multipathDuplicationPolicy = policy

		mockSender := NewMockStreamSender(tc.mockCtrl)
		mockSender.EXPECT().onHasStreamData(protocol.StreamID(4), gomock.Any())
		str := newSendStream(context.Background(), 4, mockSender, newTestStreamFlowControllerWithSendWindow(4, protocol.MaxByteCount), false)
		_, err := str.Write([]byte("foobar"))
		require.NoError(t, err)
		f, _, _ := str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
		require.NotNil(t, f.Frame)
		other := &wire.StreamFrame{StreamID: 8, Data: []byte("raboof")}

		var sentPacket shortHeaderPacket
		tc.appendPacket = func(buf *packetBuffer, maxSize protocol.ByteCount, pathID protocol.PathID) (shortHeaderPacket, error) {
			if sentPacket.Length > 0 {
				return shortHeaderPacket{}, errNothingToPack
			}
			// the application resets stream 4 while the packet is sent
			mockSender.EXPECT().onHasStreamControlFrame(protocol.StreamID(4), gomock.Any())
			str.CancelWrite(42)
			buf.Data = append(buf.Data, make([]byte, 100)...)
			sentPacket = tc.packPacket(pathID, nil, 100, false)
			sentPacket.StreamFrames = []ackhandler.StreamFrame{f, {Frame: other, Handler: &countingFrameHandler{}}}
			return sentPacket, nil
		}
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Equal(t, protocol.PathID(1), protocol.PathID(sentPacket.PathID))
		require.Equal(t,
			[]wire.Frame{&wire.StreamFrame{StreamID: 8, Data: []byte("raboof"), DataLenPresent: true}},
			tc.copiedFrames(0),
		)
	})
}

// duplicateEventRecorder is a multipath controller that records the paths of the packets carrying duplicated frames.
type duplicateEventRecorder struct {
	selectingTestController

	pathsMx sync.Mutex
	paths   []PathID
}

func (r *duplicateEventRecorder) OnPacketSent(ev PathEvent) {
	if !ev.IsDuplicate {
		return
	}
	r.pathsMx.Lock()
	defer r.pathsMx.Unlock()
	r.paths = append(r.paths, ev.PathID)
}

func (r *duplicateEventRecorder) OnPacketAcked(PathEvent) {}
func (r *duplicateEventRecorder) OnPacketLost(PathEvent)  {}

// streamDataByPath returns the ranges of the data of stream 0 sent or received, by path.
func streamDataByPath(r *events.Recorder, sent bool) map[protocol.PathID][][2]int64 {
	ranges := make(map[protocol.PathID][][2]int64)
	add := func(hdr qlog.PacketHeader, frames []qlog.Frame) {
		if hdr.PacketType != qlog.PacketType1RTT {
			return
		}
		for _, f := range frames {
			if sf, ok := f.Frame.(*qlog.StreamFrame); ok && sf.StreamID == 0 {
				ranges[hdr.PathID] = append(ranges[hdr.PathID], [2]int64{sf.Offset, sf.Length})
			}
		}
	}
	if sent {
		for _, ev := range r.Events(qlog.PacketSent{}) {
			add(ev.(qlog.PacketSent).Header, ev.(qlog.PacketSent).Frames)
		}
	} else {
		for _, ev := range r.Events(qlog.PacketReceived{}) {
			add(ev.(qlog.PacketReceived).Header, ev.(qlog.PacketReceived).Frames)
		}
	}
	return ranges
}

// With frame-level duplication, the data of a stream is sent on both paths.
// The server receives it twice, but the application receives it once.
func TestMultipathDuplicationEndToEnd(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		policy := NewMultipathDuplicationPolicy()
		policy.Enable()
		policy.SetDuplicateAllStreams(true)
		policy.SetDuplicatePathCount(2)
		ctrl := &duplicateEventRecorder{selectingTestController: selectingTestController{selectPath: func([]PathInfo) PathID { return 42 }}}
		p := newMultipathPathTestPair(t, multipathPathTestOpts{
			clientConf: func(c *Config) {
				useTestController(ctrl)(c)
				c.MultipathDuplicationPolicy = policy
			},
		})
		p.openPath(t)
		p.transfer(t, randomData(50<<10))
		p.close(t)

		ctrl.pathsMx.Lock()
		require.Contains(t, ctrl.paths, PathID(0))
		require.Contains(t, ctrl.paths, PathID(1))
		ctrl.pathsMx.Unlock()
		// The client sent the same data on both paths, and the server received it on both paths.
		for _, ranges := range []map[protocol.PathID][][2]int64{
			streamDataByPath(p.clientEvents, true),
			streamDataByPath(p.serverEvents, false),
		} {
			var duplicated int
			for _, r := range ranges[0] {
				if slices.Contains(ranges[1], r) {
					duplicated++
				}
			}
			require.NotZero(t, duplicated)
		}
	})
}
