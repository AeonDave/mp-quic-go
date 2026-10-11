package ackhandler

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/congestion"
	"github.com/AeonDave/mp-quic-go/internal/mocks"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/internal/utils"
	"github.com/AeonDave/mp-quic-go/internal/wire"
	"github.com/AeonDave/mp-quic-go/qlog"
	"github.com/AeonDave/mp-quic-go/qlogwriter"
	"github.com/AeonDave/mp-quic-go/testutils/events"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// These tests cover IETF Multipath QUIC (draft-ietf-quic-multipath):
// every path has its own packet number space and is recovered independently.

type pathPacketNumber struct {
	PathID       protocol.PathID
	PacketNumber protocol.PacketNumber
}

// pathPacketTracker counts how often the frame sent in a packet was acknowledged and declared lost.
type pathPacketTracker struct {
	acked, lost map[pathPacketNumber]int
}

func newPathPacketTracker() *pathPacketTracker {
	return &pathPacketTracker{
		acked: make(map[pathPacketNumber]int),
		lost:  make(map[pathPacketNumber]int),
	}
}

func (t *pathPacketTracker) NewPingFrame(pathID protocol.PathID, pn protocol.PacketNumber) Frame {
	p := pathPacketNumber{PathID: pathID, PacketNumber: pn}
	return Frame{
		Frame: &wire.PingFrame{},
		Handler: &customFrameHandler{
			onAcked: func(wire.Frame) { t.acked[p]++ },
			onLost:  func(wire.Frame) { t.lost[p]++ },
		},
	}
}

// Lost returns the packet numbers of the lost packets of a path, in ascending order.
func (t *pathPacketTracker) Lost(pathID protocol.PathID) []protocol.PacketNumber {
	var pns []protocol.PacketNumber
	for p := range t.lost {
		if p.PathID == pathID {
			pns = append(pns, p.PacketNumber)
		}
	}
	slices.Sort(pns)
	return pns
}

// Acked returns the packet numbers of the acknowledged packets of a path, in ascending order.
func (t *pathPacketTracker) Acked(pathID protocol.PathID) []protocol.PacketNumber {
	var pns []protocol.PacketNumber
	for p := range t.acked {
		if p.PathID == pathID {
			pns = append(pns, p.PacketNumber)
		}
	}
	slices.Sort(pns)
	return pns
}

func newMultipathSentPacketHandler(
	pers protocol.Perspective,
	enableECN bool,
	ignorePacketsBelow func(protocol.PathID, protocol.PacketNumber),
) *sentPacketHandler {
	sph := NewSentPacketHandler(
		0,
		1200,
		utils.NewRTTStats(),
		&utils.ConnectionStats{},
		true,
		enableECN,
		nil,
		pers,
		nil,
		utils.DefaultLogger,
	).(*sentPacketHandler)
	sph.EnableMultipath(ignorePacketsBelow)
	return sph
}

// confirmHandshake drops the Initial and Handshake packet number spaces.
func confirmHandshake(sph *sentPacketHandler, now monotime.Time) {
	sph.DropPackets(protocol.EncryptionInitial, now)
	sph.DropPackets(protocol.EncryptionHandshake, now)
}

func sendPathPacket(sph *sentPacketHandler, tracker *pathPacketTracker, pathID protocol.PathID, t monotime.Time, size protocol.ByteCount) protocol.PacketNumber {
	pn := sph.PopPacketNumber(pathID, protocol.Encryption1RTT)
	ecn := protocol.ECNNon
	if sph.enableECN {
		ecn = sph.ECNModeForPath(pathID)
	}
	sph.SentPacket(t, pn, protocol.InvalidPacketNumber, nil, []Frame{tracker.NewPingFrame(pathID, pn)}, protocol.Encryption1RTT, ecn, size, false, false, pathID)
	return pn
}

func pathAck(pathID protocol.PathID, pns ...protocol.PacketNumber) *wire.AckFrame {
	return &wire.AckFrame{PathID: pathID, HasPathID: true, AckRanges: ackRanges(slices.Clone(pns)...)}
}

// requireAlarm checks the timer that the alarm is set for, and the path it belongs to.
func requireAlarm(t *testing.T, sph *sentPacketHandler, pathID protocol.PathID, alarm alarmTimer) {
	t.Helper()
	require.Equal(t, alarm, sph.alarm)
	require.Equal(t, pathID, sph.alarmPathID)
}

// pathState is the part of a path's state that an ACK for another path must not modify.
type pathState struct {
	LargestAcked, LargestSent             protocol.PacketNumber
	HistoryLen, NumOutstanding            int
	LossTime                              monotime.Time
	BytesInFlight, CongestionWindow       protocol.ByteCount
	InSlowStart, InRecovery               bool
	SmoothedRTT, LatestRTT, MeanDeviation time.Duration
	HasRTTMeasurement                     bool
	PTOCount                              uint32
	NumProbesToSend                       int
	ECN                                   ecnTracker
	LostPackets                           []lostPacket
}

func getPathState(r *pathRecovery) pathState {
	s := pathState{
		LargestAcked:      r.space.largestAcked,
		LargestSent:       r.space.largestSent,
		HistoryLen:        r.space.history.Len(),
		NumOutstanding:    r.space.history.NumOutstanding(),
		LossTime:          r.space.lossTime,
		BytesInFlight:     r.bytesInFlight,
		CongestionWindow:  r.congestion.GetCongestionWindow(),
		InSlowStart:       r.congestion.InSlowStart(),
		InRecovery:        r.congestion.InRecovery(),
		SmoothedRTT:       r.rttStats.SmoothedRTT(),
		LatestRTT:         r.rttStats.LatestRTT(),
		MeanDeviation:     r.rttStats.MeanDeviation(),
		HasRTTMeasurement: r.rttStats.HasMeasurement(),
		PTOCount:          r.ptoCount,
		NumProbesToSend:   r.numProbesToSend,
		LostPackets:       slices.Clone(r.lostPackets.lostPackets),
	}
	if t, ok := r.ecnTracker.(*ecnTracker); ok {
		s.ECN = *t
	}
	return s
}

func TestSentPacketHandlerMultipathPacketNumbers(t *testing.T) {
	sph := NewSentPacketHandler(0, 1200, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false, nil, protocol.PerspectiveClient, nil, utils.DefaultLogger).(*sentPacketHandler)
	require.Equal(t, protocol.PacketNumber(0), sph.PopPacketNumber(0, protocol.Encryption1RTT))
	require.Equal(t, protocol.PacketNumber(1), sph.PopPacketNumber(0, protocol.Encryption1RTT))
	sph.EnableMultipath(nil)
	// path 0 continues the packet number sequence used before
	pn, _ := sph.PeekPacketNumber(0, protocol.Encryption1RTT)
	require.Equal(t, protocol.PacketNumber(2), pn)
	require.Equal(t, protocol.PacketNumber(2), sph.PopPacketNumber(0, protocol.Encryption1RTT))
	// The next packet number is 3, unless the generator skips it to detect optimistic ACKs.
	next0, _ := sph.PeekPacketNumber(0, protocol.Encryption1RTT)
	require.Contains(t, []protocol.PacketNumber{3, 4}, next0)

	// paths 1 and 2 start at 0
	for _, pathID := range []protocol.PathID{1, 2} {
		pn, pnLen := sph.PeekPacketNumber(pathID, protocol.Encryption1RTT)
		require.Zero(t, pn)
		require.Equal(t, protocol.PacketNumberLengthForHeader(0, protocol.InvalidPacketNumber), pnLen)
	}

	// Send packets on paths 1 and 2 alternately, until both paths skipped two packet numbers.
	now := monotime.Now()
	send := func(pathID protocol.PathID) protocol.PacketNumber {
		pn := sph.PopPacketNumber(pathID, protocol.Encryption1RTT)
		sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.Encryption1RTT, protocol.ECNNon, 1200, false, false, pathID)
		return pn
	}
	popped := make(map[protocol.PathID][]protocol.PacketNumber)
	skipped := make(map[protocol.PathID][]protocol.PacketNumber)
	for len(skipped[1]) < 2 || len(skipped[2]) < 2 {
		for _, pathID := range []protocol.PathID{1, 2} {
			next, _ := sph.PeekPacketNumber(pathID, protocol.Encryption1RTT)
			pn := send(pathID)
			require.Equal(t, next, pn)
			pns := popped[pathID]
			if len(pns) == 0 {
				require.Zero(t, pn)
			} else if last := pns[len(pns)-1]; pn != last+1 {
				// at most one packet number is skipped at a time
				require.Equal(t, last+2, pn)
				skipped[pathID] = append(skipped[pathID], last+1)
			}
			popped[pathID] = append(pns, pn)
		}
		require.Less(t, len(popped[1]), 10000)
	}
	// every path records its own skipped packet numbers (the most recent ones, up to maxSkippedPackets)
	for _, pathID := range []protocol.PathID{1, 2} {
		expected := skipped[pathID]
		if len(expected) > maxSkippedPackets {
			expected = expected[len(expected)-maxSkippedPackets:]
		}
		require.Equal(t, expected, slices.Collect(sph.paths[pathID].space.history.SkippedPackets()))
	}
	// sending packets on one path doesn't affect the other paths
	next1, _ := sph.PeekPacketNumber(1, protocol.Encryption1RTT)
	for range 1000 {
		send(2)
	}
	pn, _ = sph.PeekPacketNumber(1, protocol.Encryption1RTT)
	require.Equal(t, next1, pn)
	pn, _ = sph.PeekPacketNumber(0, protocol.Encryption1RTT)
	require.Equal(t, next0, pn)
}

func TestSentPacketHandlerMultipathPacketNumberLength(t *testing.T) {
	sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
	now := monotime.Now()
	confirmHandshake(sph, now)
	// Send enough (non-ack-eliciting) packets that 2-byte packet numbers don't suffice without an acknowledgment.
	var pns []protocol.PacketNumber
	for range 1 << 15 {
		for _, pathID := range []protocol.PathID{1, 2} {
			pn := sph.PopPacketNumber(pathID, protocol.Encryption1RTT)
			sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, nil, protocol.Encryption1RTT, protocol.ECNNon, 100, false, false, pathID)
			if pathID == 1 {
				pns = append(pns, pn)
			}
		}
	}
	_, err := sph.ReceivedAck(pathAck(1, pns...), protocol.Encryption1RTT, now)
	require.NoError(t, err)
	// The packet number length depends on the largest acknowledged packet of the path.
	pn1, pnLen1 := sph.PeekPacketNumber(1, protocol.Encryption1RTT)
	require.Equal(t, protocol.PacketNumberLen2, pnLen1)
	require.Equal(t, protocol.PacketNumberLengthForHeader(pn1, pns[len(pns)-1]), pnLen1)
	pn2, pnLen2 := sph.PeekPacketNumber(2, protocol.Encryption1RTT)
	require.Equal(t, protocol.PacketNumberLen3, pnLen2)
	require.Equal(t, protocol.PacketNumberLengthForHeader(pn2, protocol.InvalidPacketNumber), pnLen2)
}

func TestSentPacketHandlerMultipathAckIsPerPath(t *testing.T) {
	sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, true, nil)
	now := monotime.Now()
	confirmHandshake(sph, now)
	tracker := newPathPacketTracker()

	// path 1: send 5 packets, 3 of them are acknowledged
	var pns1 []protocol.PacketNumber
	for range 5 {
		pns1 = append(pns1, sendPathPacket(sph, tracker, 1, now, 1200))
	}
	// path 2: send 10 packets
	var pns2 []protocol.PacketNumber
	for range 10 {
		pns2 = append(pns2, sendPathPacket(sph, tracker, 2, now, 1200))
	}
	sendPathPacket(sph, tracker, 0, now, 1200)
	ack1 := pathAck(1, pns1[:3]...)
	ack1.ECT0 = 3
	acked, err := sph.ReceivedAck(ack1, protocol.Encryption1RTT, now.Add(30*time.Millisecond))
	require.NoError(t, err)
	require.True(t, acked)
	require.Equal(t, pns1[:3], tracker.Acked(1))
	require.True(t, sph.paths[1].rttStats.HasMeasurement())
	require.Equal(t, 30*time.Millisecond, sph.paths[1].rttStats.LatestRTT())
	require.Equal(t, protocol.ByteCount(2*1200), sph.paths[1].bytesInFlight)

	path0 := getPathState(&sph.appData)
	path1 := getPathState(sph.paths[1])
	cwnd2 := sph.paths[2].congestion.GetCongestionWindow()

	// The PATH_ACK for path 2 acknowledges 8 of 10 packets.
	// Two packets are lost (packet threshold), which is a congestion event on path 2.
	// It is received after 50ms: the RTT sample is taken for path 2 only.
	ack2 := pathAck(2, append(slices.Clone(pns2[:2]), pns2[4:]...)...)
	ack2.ECT0 = 8
	acked, err = sph.ReceivedAck(ack2, protocol.Encryption1RTT, now.Add(50*time.Millisecond))
	require.NoError(t, err)
	require.True(t, acked)
	require.Equal(t, append(slices.Clone(pns2[:2]), pns2[4:]...), tracker.Acked(2))
	require.Equal(t, pns2[2:4], tracker.Lost(2))
	require.Empty(t, tracker.Lost(1))
	require.Equal(t, pns2[9], sph.paths[2].space.largestAcked)
	require.Equal(t, 50*time.Millisecond, sph.paths[2].rttStats.LatestRTT())
	require.Zero(t, sph.paths[2].bytesInFlight)
	require.Less(t, sph.paths[2].congestion.GetCongestionWindow(), cwnd2)
	require.Equal(t, ecnStateCapable, sph.paths[2].ecnTracker.(*ecnTracker).state)

	// path 0 and path 1 are unaffected
	require.Equal(t, path0, getPathState(&sph.appData))
	require.Equal(t, path1, getPathState(sph.paths[1]))
	require.Equal(t, ecnStateCapable, sph.paths[1].ecnTracker.(*ecnTracker).state)
	require.Equal(t, protocol.ByteCount(3*1200), sph.bytesInFlight)

	// An ACK frame acknowledges packets sent on path 0.
	acked, err = sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(0)}, protocol.Encryption1RTT, now.Add(10*time.Millisecond))
	require.NoError(t, err)
	require.True(t, acked)
	require.Equal(t, []protocol.PacketNumber{0}, tracker.Acked(0))
	require.Equal(t, 10*time.Millisecond, sph.rttStats.LatestRTT())
	require.Equal(t, protocol.ByteCount(2*1200), sph.bytesInFlight)
	require.Equal(t, path1, getPathState(sph.paths[1]))
}

func TestSentPacketHandlerMultipathAckValidation(t *testing.T) {
	t.Run("unknown path", func(t *testing.T) {
		sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
		_, err := sph.ReceivedAck(pathAck(3, 0), protocol.Encryption1RTT, monotime.Now())
		require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
	})

	t.Run("path that didn't send any packets", func(t *testing.T) {
		sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
		sph.AddPath(3, true)
		_, err := sph.ReceivedAck(pathAck(3, 0), protocol.Encryption1RTT, monotime.Now())
		require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
		require.ErrorContains(t, err, "received ACK for an unsent packet")
	})

	t.Run("packet number only sent on another path", func(t *testing.T) {
		sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
		tracker := newPathPacketTracker()
		now := monotime.Now()
		sendPathPacket(sph, tracker, 1, now, 1000)
		for range 3 {
			sendPathPacket(sph, tracker, 2, now, 1000)
		}
		_, err := sph.ReceivedAck(pathAck(1, 0, 1, 2), protocol.Encryption1RTT, now)
		require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
		require.Empty(t, tracker.acked)
	})

	t.Run("skipped packet number", func(t *testing.T) {
		sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
		tracker := newPathPacketTracker()
		now := monotime.Now()
		sph.AddPath(1, true)
		sph.AddPath(2, true)
		// path 2 never skips a packet number
		sph.paths[2].space.pns = newSequentialPacketNumberGenerator(0)
		var pns []protocol.PacketNumber
		for {
			pn := sendPathPacket(sph, tracker, 1, now, 1000)
			if len(pns) > 0 && pn != pns[len(pns)-1]+1 {
				pns = append(pns, pn)
				break
			}
			pns = append(pns, pn)
		}
		skipped := pns[len(pns)-1] - 1
		for pn := protocol.PacketNumber(0); pn <= pns[len(pns)-1]; pn++ {
			require.Equal(t, pn, sendPathPacket(sph, tracker, 2, now, 1000))
		}
		// path 2 sent a packet with the packet number that path 1 skipped
		_, err := sph.ReceivedAck(pathAck(2, skipped), protocol.Encryption1RTT, now)
		require.NoError(t, err)
		require.Equal(t, []protocol.PacketNumber{skipped}, tracker.Acked(2))
		// acknowledging the skipped packet number on path 1 is a protocol violation
		_, err = sph.ReceivedAck(pathAck(1, skipped-1, skipped, skipped+1), protocol.Encryption1RTT, now)
		require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
		require.ErrorContains(t, err, "skipped packet number")
	})

	t.Run("abandoned path", func(t *testing.T) {
		sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
		tracker := newPathPacketTracker()
		now := monotime.Now()
		pn := sendPathPacket(sph, tracker, 1, now, 1000)
		sph.AbandonPath(1, now)
		acked, err := sph.ReceivedAck(pathAck(1, pn), protocol.Encryption1RTT, now)
		require.NoError(t, err)
		require.False(t, acked)
		// even if the ACK acknowledges packets that were never sent
		acked, err = sph.ReceivedAck(pathAck(1, pn+100), protocol.Encryption1RTT, now)
		require.NoError(t, err)
		require.False(t, acked)
		require.Empty(t, tracker.acked)
	})

	t.Run("abandoned path 0", func(t *testing.T) {
		sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
		tracker := newPathPacketTracker()
		now := monotime.Now()
		pn := sendPathPacket(sph, tracker, 0, now, 1000)
		sph.AbandonPath(0, now)
		acked, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn)}, protocol.Encryption1RTT, now)
		require.NoError(t, err)
		require.False(t, acked)
		require.Empty(t, tracker.acked)
		require.Equal(t, []protocol.PacketNumber{pn}, tracker.Lost(0))
	})

	t.Run("removed path", func(t *testing.T) {
		sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
		tracker := newPathPacketTracker()
		now := monotime.Now()
		pn := sendPathPacket(sph, tracker, 1, now, 1000)
		sph.RemovePath(1, now)
		require.NotContains(t, sph.paths, protocol.PathID(1))
		require.Empty(t, sph.pathIDs)
		acked, err := sph.ReceivedAck(pathAck(1, pn), protocol.Encryption1RTT, now)
		require.NoError(t, err)
		require.False(t, acked)
		require.Equal(t, []protocol.PacketNumber{pn}, tracker.Lost(1))
		// The path ID can't be used again.
		require.Panics(t, func() { sph.PopPacketNumber(1, protocol.Encryption1RTT) })
		sph.AddPath(1, true)
		require.NotContains(t, sph.paths, protocol.PathID(1))
	})
}

func TestSentPacketHandlerMultipathAbandonPath(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
	now := monotime.Now()
	confirmHandshake(sph, now)
	sph.AddPath(1, true)
	sph.AddPath(2, true)
	// Congestion events are reported to the mocks as unexpected calls.
	ccs := make(map[protocol.PathID]*mocks.MockSendAlgorithmWithDebugInfos)
	for _, r := range []*pathRecovery{&sph.appData, sph.paths[1], sph.paths[2]} {
		cc := mocks.NewMockSendAlgorithmWithDebugInfos(mockCtrl)
		cc.EXPECT().OnPacketSent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
		cc.EXPECT().OnPacketAcked(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
		cc.EXPECT().MaybeExitSlowStart().AnyTimes()
		cc.EXPECT().CanSend(gomock.Any()).Return(true).AnyTimes()
		cc.EXPECT().HasPacingBudget(gomock.Any()).Return(true).AnyTimes()
		r.congestion = cc
		ccs[r.id] = cc
	}

	tracker := newPathPacketTracker()
	var pns1 []protocol.PacketNumber
	for i := range 6 {
		pns1 = append(pns1, sendPathPacket(sph, tracker, 1, now.Add(time.Duration(i)*time.Millisecond), 1000))
	}
	pns2 := []protocol.PacketNumber{
		sendPathPacket(sph, tracker, 2, now, 1000),
		sendPathPacket(sph, tracker, 2, now, 1000),
	}
	sendPathPacket(sph, tracker, 0, now, 1000)
	// a path probe packet (e.g. containing a PATH_CHALLENGE)
	var probeLost int
	probePN := sph.PopPacketNumber(1, protocol.Encryption1RTT)
	sph.SentPacket(now, probePN, protocol.InvalidPacketNumber, nil, []Frame{{
		Frame:   &wire.PathChallengeFrame{},
		Handler: &customFrameHandler{onLost: func(wire.Frame) { probeLost++ }},
	}}, protocol.Encryption1RTT, protocol.ECNNon, 1200, false, true, 1)

	// Acknowledge the second packet of path 1.
	_, err := sph.ReceivedAck(pathAck(1, pns1[1]), protocol.Encryption1RTT, now.Add(10*time.Millisecond))
	require.NoError(t, err)
	require.Equal(t, protocol.ByteCount(5000), sph.paths[1].bytesInFlight)
	require.Equal(t, protocol.ByteCount(8000), sph.bytesInFlight)
	// The timer of path 1 is the earliest.
	require.Equal(t, protocol.PathID(1), sph.alarmPathID)
	sph.paths[1].ptoCount = 2
	sph.paths[1].numProbesToSend = 1
	sph.paths[1].ptoMode = SendPTOAppData

	sph.AbandonPath(1, now.Add(20*time.Millisecond))
	// All outstanding frames of path 1 are queued for retransmission once.
	expectedLost := append([]protocol.PacketNumber{pns1[0]}, pns1[2:]...)
	require.Equal(t, expectedLost, tracker.Lost(1))
	for _, pn := range expectedLost {
		require.Equal(t, 1, tracker.lost[pathPacketNumber{PathID: 1, PacketNumber: pn}])
	}
	require.Equal(t, 1, probeLost)
	require.Empty(t, tracker.Lost(0))
	require.Empty(t, tracker.Lost(2))
	require.Zero(t, sph.paths[1].bytesInFlight)
	require.Equal(t, protocol.ByteCount(3000), sph.bytesInFlight)
	require.Equal(t, protocol.ByteCount(2000), sph.paths[2].bytesInFlight)
	require.False(t, sph.paths[1].space.history.HasOutstandingPackets())
	require.False(t, sph.paths[1].space.history.HasOutstandingPathProbes())
	require.Zero(t, sph.paths[1].ptoCount)
	require.Equal(t, SendNone, sph.SendModeForPath(1, now))
	_, ok := sph.NextProbePath()
	require.False(t, ok)
	// The loss detection timer doesn't fire for path 1 any more.
	require.NotEqual(t, protocol.PathID(1), sph.alarmPathID)
	require.Zero(t, sph.pathLossDetectionTime(now, sph.paths[1]))
	require.True(t, sph.paths[1].space.lossTime.IsZero())

	// Abandoning a path again, or removing it, doesn't queue the frames again.
	sph.AbandonPath(1, now.Add(30*time.Millisecond))
	sph.RemovePath(1, now.Add(40*time.Millisecond))
	for _, pn := range expectedLost {
		require.Equal(t, 1, tracker.lost[pathPacketNumber{PathID: 1, PacketNumber: pn}])
	}
	require.Equal(t, 1, probeLost)
	require.Equal(t, []protocol.PacketNumber{pns1[1]}, tracker.Acked(1))

	// path 2 is still in use
	_, err = sph.ReceivedAck(pathAck(2, pns2...), protocol.Encryption1RTT, now.Add(50*time.Millisecond))
	require.NoError(t, err)
	require.Equal(t, pns2, tracker.Acked(2))
	require.Zero(t, sph.paths[2].bytesInFlight)
	require.Equal(t, protocol.ByteCount(1000), sph.bytesInFlight)
}

func TestSentPacketHandlerMultipathRemovePath0(t *testing.T) {
	sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
	now := monotime.Now()
	confirmHandshake(sph, now)
	tracker := newPathPacketTracker()
	pn0 := sendPathPacket(sph, tracker, 0, now, 1000)
	sendPathPacket(sph, tracker, 1, now, 1000)
	// path 0 can't be removed, it is abandoned instead
	sph.RemovePath(0, now)
	require.Equal(t, []protocol.PacketNumber{pn0}, tracker.Lost(0))
	require.True(t, sph.appData.abandoned)
	require.Equal(t, SendNone, sph.SendModeForPath(0, now))
	require.Equal(t, SendAny, sph.SendMode(now))
	require.Equal(t, protocol.ByteCount(1000), sph.bytesInFlight)
}

// sendPathProbePacket sends a path probe packet (e.g. containing a PATH_CHALLENGE frame) on a path.
func sendPathProbePacket(sph *sentPacketHandler, tracker *pathPacketTracker, pathID protocol.PathID, t monotime.Time) protocol.PacketNumber {
	pn := sph.PopPacketNumber(pathID, protocol.Encryption1RTT)
	frame := tracker.NewPingFrame(pathID, pn)
	frame.Frame = &wire.PathChallengeFrame{}
	sph.SentPacket(t, pn, protocol.InvalidPacketNumber, nil, []Frame{frame}, protocol.Encryption1RTT, protocol.ECNNon, 1200, false, true, pathID)
	return pn
}

// Validating a path often takes several path probe packets.
// When the path is abandoned or removed, each of them is declared lost exactly once.
func TestSentPacketHandlerMultipathAbandonPathWithPathProbes(t *testing.T) {
	t.Run("abandon", func(t *testing.T) {
		testSentPacketHandlerMultipathAbandonPathWithPathProbes(t, false)
	})
	t.Run("remove", func(t *testing.T) {
		testSentPacketHandlerMultipathAbandonPathWithPathProbes(t, true)
	})
}

func testSentPacketHandlerMultipathAbandonPathWithPathProbes(t *testing.T, remove bool) {
	sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
	var observer recordingPacketObserver
	sph.SetPacketObserver(&observer)
	now := monotime.Now()
	confirmHandshake(sph, now)
	sph.AddPath(1, true)
	tracker := newPathPacketTracker()
	var probePNs []protocol.PacketNumber
	for i := range 4 {
		probePNs = append(probePNs, sendPathProbePacket(sph, tracker, 1, now.Add(time.Duration(i)*100*time.Millisecond)))
	}
	dataPN := sendPathPacket(sph, tracker, 1, now, 1000)
	requireAlarm(t, sph, 1, alarmTimer{
		Time:            now.Add(sph.paths[1].rttStats.PTO(true)),
		TimerType:       qlog.TimerTypePTO,
		EncryptionLevel: protocol.Encryption1RTT,
	})

	if remove {
		sph.RemovePath(1, now.Add(500*time.Millisecond))
	} else {
		sph.AbandonPath(1, now.Add(500*time.Millisecond))
		require.False(t, sph.paths[1].space.history.HasOutstandingPathProbes())
		require.False(t, sph.paths[1].space.history.HasOutstandingPackets())
	}
	for _, pn := range append(probePNs, dataPN) {
		require.Equal(t, 1, tracker.lost[pathPacketNumber{PathID: 1, PacketNumber: pn}], "packet %d", pn)
	}
	// Abandoning a path is not reported to the observer.
	require.Empty(t, observer.lost)
	require.Zero(t, sph.GetLossDetectionTimeout())

	// The path probe packets aren't declared lost again when they time out.
	require.NoError(t, sph.OnLossDetectionTimeout(now.Add(5*time.Second)))
	for _, pn := range probePNs {
		require.Equal(t, 1, tracker.lost[pathPacketNumber{PathID: 1, PacketNumber: pn}], "packet %d", pn)
	}
	require.Empty(t, observer.lost)
	require.Zero(t, sph.bytesInFlight)
}

// A migrated path forgets all its path probe packets.
func TestSentPacketHandlerMultipathMigratedPathWithPathProbes(t *testing.T) {
	sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
	now := monotime.Now()
	confirmHandshake(sph, now)
	sph.AddPath(1, true)
	tracker := newPathPacketTracker()
	for range 3 {
		sendPathProbePacket(sph, tracker, 1, now)
	}
	requireAlarm(t, sph, 1, alarmTimer{
		Time:            now.Add(pathProbePacketLossTimeout),
		TimerType:       qlog.TimerTypePathProbe,
		EncryptionLevel: protocol.Encryption1RTT,
	})
	sph.MigratedPathForPath(1, now, 1200)
	require.False(t, sph.paths[1].space.history.HasOutstandingPathProbes())
	require.Zero(t, sph.GetLossDetectionTimeout())
	require.Empty(t, tracker.Lost(1))
}

func TestSentPacketHandlerMultipathPTO(t *testing.T) {
	sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
	now := monotime.Now()
	confirmHandshake(sph, now)
	sph.AddPath(1, true)
	sph.AddPath(2, true)
	sph.rttStats.UpdateRTT(50*time.Millisecond, 0)
	sph.paths[1].rttStats.UpdateRTT(20*time.Millisecond, 0)
	sph.paths[2].rttStats.UpdateRTT(80*time.Millisecond, 0)

	tracker := newPathPacketTracker()
	pn0 := sendPathPacket(sph, tracker, 0, now, 1000)
	pn1 := sendPathPacket(sph, tracker, 1, now, 1000)
	pn2 := sendPathPacket(sph, tracker, 2, now, 1000)

	// path 1 has the smallest RTT: its PTO fires first
	timeout := sph.GetLossDetectionTimeout()
	require.Equal(t, now.Add(sph.paths[1].rttStats.PTO(true)), timeout)
	require.NoError(t, sph.OnLossDetectionTimeout(timeout))
	require.Equal(t, uint32(1), sph.paths[1].ptoCount)
	require.Zero(t, sph.paths[2].ptoCount)
	require.Zero(t, sph.appData.ptoCount)
	require.Equal(t, SendPTOAppData, sph.SendModeForPath(1, timeout))
	require.Equal(t, SendAny, sph.SendModeForPath(2, timeout))
	require.Equal(t, SendAny, sph.SendModeForPath(0, timeout))
	require.Equal(t, SendPTOAppData, sph.SendMode(timeout))
	probePath, ok := sph.NextProbePath()
	require.True(t, ok)
	require.Equal(t, protocol.PathID(1), probePath)
	// a packet number of path 1 was skipped, to elicit an immediate ACK
	require.Len(t, slices.Collect(sph.paths[1].space.history.SkippedPackets()), 1)
	require.Empty(t, slices.Collect(sph.paths[2].space.history.SkippedPackets()))
	// the PTO of path 1 backs off, the other paths' PTOs don't
	requireAlarm(t, sph, 1, alarmTimer{
		Time:            now.Add(2 * sph.paths[1].rttStats.PTO(true)),
		TimerType:       qlog.TimerTypePTO,
		EncryptionLevel: protocol.Encryption1RTT,
	})
	require.Less(t, sph.alarm.Time, now.Add(sph.rttStats.PTO(true)))
	require.Equal(t, 2*sph.paths[1].rttStats.PTO(true), sph.getScaledPathPTO(sph.paths[1]))
	require.Equal(t, sph.rttStats.PTO(true), sph.getScaledPathPTO(&sph.appData))
	require.Equal(t, sph.paths[2].rttStats.PTO(true), sph.getScaledPathPTO(sph.paths[2]))

	// Only path 1's packet is queued for retransmission.
	require.True(t, sph.QueueProbePacketForPath(1))
	require.Equal(t, []protocol.PacketNumber{pn1}, tracker.Lost(1))
	require.Empty(t, tracker.Lost(0))
	require.Empty(t, tracker.Lost(2))
	require.False(t, sph.QueueProbePacketForPath(1))

	// send the two probe packets on path 1
	probe1 := sendPathPacket(sph, tracker, 1, timeout, 1000)
	require.Equal(t, SendPTOAppData, sph.SendModeForPath(1, timeout))
	probe2 := sendPathPacket(sph, tracker, 1, timeout, 1000)
	require.Equal(t, SendAny, sph.SendModeForPath(1, timeout))
	_, ok = sph.NextProbePath()
	require.False(t, ok)

	// An ACK for path 1 resets path 1's PTO count.
	_, err := sph.ReceivedAck(pathAck(1, probe1, probe2), protocol.Encryption1RTT, timeout.Add(10*time.Millisecond))
	require.NoError(t, err)
	require.Zero(t, sph.paths[1].ptoCount)
	require.Zero(t, sph.paths[1].bytesInFlight)

	// PTOs on path 0 and path 2 don't affect path 1
	t0 := now.Add(sph.rttStats.PTO(true))
	require.NoError(t, sph.OnLossDetectionTimeout(t0))
	require.Equal(t, uint32(1), sph.appData.ptoCount)
	require.Equal(t, SendPTOAppData, sph.SendModeForPath(0, t0))
	// When several paths need to send probe packets, the one with the lowest path ID is first.
	require.NoError(t, sph.OnLossDetectionTimeout(now.Add(sph.paths[2].rttStats.PTO(true))))
	require.Equal(t, uint32(1), sph.paths[2].ptoCount)
	require.Zero(t, sph.paths[1].ptoCount)
	probePath, ok = sph.NextProbePath()
	require.True(t, ok)
	require.Zero(t, probePath)
	require.True(t, sph.QueueProbePacket(protocol.Encryption1RTT))
	require.Equal(t, []protocol.PacketNumber{pn0}, tracker.Lost(0))
	require.Empty(t, tracker.Lost(2))
	require.True(t, sph.QueueProbePacketForPath(2))
	require.Equal(t, []protocol.PacketNumber{pn2}, tracker.Lost(2))
}

func TestSentPacketHandlerMultipathLossDetectionAlarm(t *testing.T) {
	sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
	now := monotime.Now()
	tracker := newPathPacketTracker()
	sph.AddPath(1, true)
	sph.AddPath(2, true)
	for _, pathID := range []protocol.PathID{0, 1, 2} {
		sph.path(pathID).rttStats.UpdateRTT(80*time.Millisecond, 0)
	}
	// the frames of Initial and Handshake packets are tracked as if they were sent on paths 100 and 101
	cryptoTrackerPath := map[protocol.EncryptionLevel]protocol.PathID{protocol.EncryptionInitial: 100, protocol.EncryptionHandshake: 101}
	sendCrypto := func(encLevel protocol.EncryptionLevel, t monotime.Time) protocol.PacketNumber {
		pn := sph.PopPacketNumber(0, encLevel)
		sph.SentPacket(t, pn, protocol.InvalidPacketNumber, nil, []Frame{tracker.NewPingFrame(cryptoTrackerPath[encLevel], pn)}, encLevel, protocol.ECNNon, 1000, false, false, 0)
		return pn
	}

	// Send two packets in every packet number space.
	// Acknowledging the second packet arms the time threshold loss timer for the first.
	sendTimes := map[protocol.PathID]monotime.Time{
		0: now.Add(4 * time.Millisecond),
		1: now.Add(2 * time.Millisecond),
		2: now.Add(2 * time.Millisecond),
	}
	initial := []protocol.PacketNumber{sendCrypto(protocol.EncryptionInitial, now.Add(3*time.Millisecond)), sendCrypto(protocol.EncryptionInitial, now.Add(5*time.Millisecond))}
	handshake := []protocol.PacketNumber{sendCrypto(protocol.EncryptionHandshake, now.Add(3*time.Millisecond)), sendCrypto(protocol.EncryptionHandshake, now.Add(5*time.Millisecond))}
	paths := make(map[protocol.PathID][]protocol.PacketNumber)
	for _, pathID := range []protocol.PathID{2, 1, 0} {
		paths[pathID] = append(paths[pathID],
			sendPathPacket(sph, tracker, pathID, sendTimes[pathID], 1000),
			sendPathPacket(sph, tracker, pathID, now.Add(5*time.Millisecond), 1000),
		)
	}
	// All RTT samples are 80ms, the RTT estimates don't change.
	rcvTime := now.Add(85 * time.Millisecond)
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(initial[1])}, protocol.EncryptionInitial, rcvTime)
	require.NoError(t, err)
	_, err = sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(handshake[1])}, protocol.EncryptionHandshake, rcvTime)
	require.NoError(t, err)
	for _, pathID := range []protocol.PathID{2, 1, 0} {
		_, err = sph.ReceivedAck(pathAck(pathID, paths[pathID][1]), protocol.Encryption1RTT, rcvTime)
		require.NoError(t, err)
	}
	for _, pathID := range []protocol.PathID{0, 1, 2} {
		require.Equal(t, 80*time.Millisecond, sph.path(pathID).rttStats.SmoothedRTT())
	}
	lossDelay := time.Duration(timeThreshold * float64(80*time.Millisecond))
	require.Equal(t, now.Add(3*time.Millisecond+lossDelay), sph.initialPackets.lossTime)
	require.Equal(t, now.Add(3*time.Millisecond+lossDelay), sph.handshakePackets.lossTime)
	require.Equal(t, now.Add(4*time.Millisecond+lossDelay), sph.appData.space.lossTime)
	require.Equal(t, now.Add(2*time.Millisecond+lossDelay), sph.paths[1].space.lossTime)
	require.Equal(t, now.Add(2*time.Millisecond+lossDelay), sph.paths[2].space.lossTime)

	// Paths 1 and 2 have the earliest loss time. Path 1 has the lower path ID.
	lossAlarm := func(sendTime time.Duration, encLevel protocol.EncryptionLevel) alarmTimer {
		return alarmTimer{Time: now.Add(sendTime + lossDelay), TimerType: qlog.TimerTypeACK, EncryptionLevel: encLevel}
	}
	requireAlarm(t, sph, 1, lossAlarm(2*time.Millisecond, protocol.Encryption1RTT))
	require.NoError(t, sph.OnLossDetectionTimeout(sph.GetLossDetectionTimeout()))
	require.Equal(t, []protocol.PacketNumber{paths[1][0]}, tracker.Lost(1))
	require.Empty(t, tracker.Lost(2))

	// then path 2
	requireAlarm(t, sph, 2, lossAlarm(2*time.Millisecond, protocol.Encryption1RTT))
	require.NoError(t, sph.OnLossDetectionTimeout(sph.GetLossDetectionTimeout()))
	require.Equal(t, []protocol.PacketNumber{paths[2][0]}, tracker.Lost(2))

	// Initial and Handshake have the same loss time. Initial comes first.
	// Both are recovered together with path 0.
	requireAlarm(t, sph, 0, lossAlarm(3*time.Millisecond, protocol.EncryptionInitial))
	require.NoError(t, sph.OnLossDetectionTimeout(sph.GetLossDetectionTimeout()))
	require.Equal(t, []protocol.PacketNumber{initial[0]}, tracker.Lost(100))
	require.Empty(t, tracker.Lost(101))
	requireAlarm(t, sph, 0, lossAlarm(3*time.Millisecond, protocol.EncryptionHandshake))
	require.NoError(t, sph.OnLossDetectionTimeout(sph.GetLossDetectionTimeout()))
	require.Equal(t, []protocol.PacketNumber{handshake[0]}, tracker.Lost(101))
	require.Empty(t, tracker.Lost(0))

	// finally path 0
	requireAlarm(t, sph, 0, lossAlarm(4*time.Millisecond, protocol.Encryption1RTT))
	require.NoError(t, sph.OnLossDetectionTimeout(sph.GetLossDetectionTimeout()))
	require.Equal(t, []protocol.PacketNumber{paths[0][0]}, tracker.Lost(0))
}

func TestSentPacketHandlerMultipathPTOTie(t *testing.T) {
	sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
	now := monotime.Now()
	confirmHandshake(sph, now)
	sph.AddPath(1, true)
	sph.AddPath(2, true)
	sph.AddPath(3, true)
	tracker := newPathPacketTracker()
	for _, pathID := range []protocol.PathID{3, 2, 1} {
		sendPathPacket(sph, tracker, pathID, now, 1000)
	}
	require.Equal(t, now.Add(sph.paths[1].rttStats.PTO(true)), sph.GetLossDetectionTimeout())
	require.Equal(t, protocol.PathID(1), sph.alarmPathID)
	sendPathPacket(sph, tracker, 0, now, 1000)
	require.Equal(t, now.Add(sph.rttStats.PTO(true)), sph.GetLossDetectionTimeout())
	require.Zero(t, sph.alarmPathID)
}

// Every path has its own timer: a time threshold loss timer armed on a slow path
// doesn't delay the PTO of a fast path.
func TestSentPacketHandlerMultipathLossTimerAndPTOOnDifferentPaths(t *testing.T) {
	t.Run("fast path 0", func(t *testing.T) {
		testSentPacketHandlerMultipathLossTimerAndPTOOnDifferentPaths(t, 0, 1)
	})
	t.Run("fast path 1", func(t *testing.T) {
		testSentPacketHandlerMultipathLossTimerAndPTOOnDifferentPaths(t, 1, 0)
	})
}

func testSentPacketHandlerMultipathLossTimerAndPTOOnDifferentPaths(t *testing.T, fast, slow protocol.PathID) {
	sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
	now := monotime.Now()
	confirmHandshake(sph, now)
	sph.AddPath(1, true)
	sph.path(fast).rttStats.UpdateRTT(10*time.Millisecond, 0)
	sph.path(slow).rttStats.UpdateRTT(time.Second, 0)
	tracker := newPathPacketTracker()

	slowPNs := []protocol.PacketNumber{
		sendPathPacket(sph, tracker, slow, now, 1000),
		sendPathPacket(sph, tracker, slow, now.Add(time.Millisecond), 1000),
	}
	fastSendTime := now.Add(time.Second)
	sendPathPacket(sph, tracker, fast, fastSendTime, 1000)
	fastPTO := fastSendTime.Add(sph.path(fast).rttStats.PTO(true))
	require.Equal(t, fastPTO, sph.GetLossDetectionTimeout())

	// Acknowledging the second packet sent on the slow path arms its loss timer for the first one.
	_, err := sph.ReceivedAck(pathAck(slow, slowPNs[1]), protocol.Encryption1RTT, now.Add(1001*time.Millisecond))
	require.NoError(t, err)
	require.Equal(t, time.Second, sph.path(slow).rttStats.SmoothedRTT())
	slowLossTime := now.Add(time.Duration(timeThreshold * float64(time.Second)))
	require.Equal(t, slowLossTime, sph.path(slow).space.lossTime)
	require.Less(t, fastPTO, slowLossTime)
	// The PTO of the fast path is still the earliest timer.
	requireAlarm(t, sph, fast, alarmTimer{
		Time:            fastPTO,
		TimerType:       qlog.TimerTypePTO,
		EncryptionLevel: protocol.Encryption1RTT,
	})

	// The PTO of the fast path expires.
	require.NoError(t, sph.OnLossDetectionTimeout(fastPTO))
	require.Equal(t, uint32(1), sph.path(fast).ptoCount)
	require.Zero(t, sph.path(slow).ptoCount)
	require.Empty(t, tracker.Lost(slow))
	require.Equal(t, slowLossTime, sph.path(slow).space.lossTime)
	probePath, ok := sph.NextProbePath()
	require.True(t, ok)
	require.Equal(t, fast, probePath)
	require.True(t, sph.QueueProbePacketForPath(fast))
	probePNs := []protocol.PacketNumber{
		sendPathPacket(sph, tracker, fast, fastPTO, 1000),
		sendPathPacket(sph, tracker, fast, fastPTO, 1000),
	}
	// The backed off PTO of the fast path still expires before the loss timer of the slow path.
	require.Equal(t, fastPTO.Add(2*sph.path(fast).rttStats.PTO(true)), sph.GetLossDetectionTimeout())
	require.Equal(t, fast, sph.alarmPathID)

	// Once the probe packets are acknowledged, only the loss timer of the slow path is left.
	_, err = sph.ReceivedAck(pathAck(fast, probePNs...), protocol.Encryption1RTT, fastPTO.Add(10*time.Millisecond))
	require.NoError(t, err)
	require.Zero(t, sph.path(fast).ptoCount)
	requireAlarm(t, sph, slow, alarmTimer{
		Time:            slowLossTime,
		TimerType:       qlog.TimerTypeACK,
		EncryptionLevel: protocol.Encryption1RTT,
	})
	require.NoError(t, sph.OnLossDetectionTimeout(slowLossTime))
	require.Equal(t, []protocol.PacketNumber{slowPNs[0]}, tracker.Lost(slow))
	require.Zero(t, sph.path(fast).ptoCount)
	require.Zero(t, sph.path(slow).ptoCount)
	require.Zero(t, sph.GetLossDetectionTimeout())
}

// The timeout of a path probe packet doesn't fire the PTO of any path before it expired.
func TestSentPacketHandlerMultipathPathProbeTimeout(t *testing.T) {
	t.Run("path probe on path 0", func(t *testing.T) {
		testSentPacketHandlerMultipathPathProbeTimeout(t, 0)
	})
	t.Run("path probe on path 1", func(t *testing.T) {
		testSentPacketHandlerMultipathPathProbeTimeout(t, 1)
	})
}

func testSentPacketHandlerMultipathPathProbeTimeout(t *testing.T, probePath protocol.PathID) {
	sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
	now := monotime.Now()
	confirmHandshake(sph, now)
	sph.AddPath(1, true)
	tracker := newPathPacketTracker()
	for _, pathID := range []protocol.PathID{0, 1} {
		sph.path(pathID).rttStats.UpdateRTT(2*time.Second, 0)
		sendPathPacket(sph, tracker, pathID, now, 1000)
	}
	pto := now.Add(sph.rttStats.PTO(true))
	require.Equal(t, pto, now.Add(sph.paths[1].rttStats.PTO(true)))
	// a path probe packet (e.g. containing a PATH_CHALLENGE)
	var probeLost int
	probePN := sph.PopPacketNumber(probePath, protocol.Encryption1RTT)
	sph.SentPacket(now, probePN, protocol.InvalidPacketNumber, nil, []Frame{{
		Frame:   &wire.PathChallengeFrame{},
		Handler: &customFrameHandler{onLost: func(wire.Frame) { probeLost++ }},
	}}, protocol.Encryption1RTT, protocol.ECNNon, 1200, false, true, probePath)
	probeTimeout := now.Add(pathProbePacketLossTimeout)
	require.Less(t, probeTimeout, pto)
	requireAlarm(t, sph, probePath, alarmTimer{
		Time:            probeTimeout,
		TimerType:       qlog.TimerTypePathProbe,
		EncryptionLevel: protocol.Encryption1RTT,
	})
	skipped0 := slices.Collect(sph.appData.space.history.SkippedPackets())
	skipped1 := slices.Collect(sph.paths[1].space.history.SkippedPackets())

	// Only the path probe packet is declared lost.
	require.NoError(t, sph.OnLossDetectionTimeout(probeTimeout))
	require.Equal(t, 1, probeLost)
	require.False(t, sph.path(probePath).space.history.HasOutstandingPathProbes())
	for _, pathID := range []protocol.PathID{0, 1} {
		require.Zero(t, sph.path(pathID).ptoCount, "path %d", pathID)
		require.Zero(t, sph.path(pathID).numProbesToSend, "path %d", pathID)
		require.Empty(t, tracker.Lost(pathID))
	}
	require.Equal(t, skipped0, slices.Collect(sph.appData.space.history.SkippedPackets()))
	require.Equal(t, skipped1, slices.Collect(sph.paths[1].space.history.SkippedPackets()))
	_, ok := sph.NextProbePath()
	require.False(t, ok)

	// The PTOs expire at the same time. Path 0 has the lower path ID.
	requireAlarm(t, sph, 0, alarmTimer{Time: pto, TimerType: qlog.TimerTypePTO, EncryptionLevel: protocol.Encryption1RTT})
	require.NoError(t, sph.OnLossDetectionTimeout(pto))
	require.Equal(t, uint32(1), sph.appData.ptoCount)
	require.Zero(t, sph.paths[1].ptoCount)
	requireAlarm(t, sph, 1, alarmTimer{Time: pto, TimerType: qlog.TimerTypePTO, EncryptionLevel: protocol.Encryption1RTT})
	require.NoError(t, sph.OnLossDetectionTimeout(pto))
	require.Equal(t, uint32(1), sph.appData.ptoCount)
	require.Equal(t, uint32(1), sph.paths[1].ptoCount)
	require.Equal(t, 1, probeLost)
}

// The anti-deadlock PTO of the client (RFC 9002, section 6.2.2.1) is armed relative to the current time.
// It belongs to path 0.
func TestSentPacketHandlerMultipathAntiDeadlockPTO(t *testing.T) {
	sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
	now := monotime.Now()
	pn := sph.PopPacketNumber(0, protocol.EncryptionInitial)
	sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.EncryptionInitial, protocol.ECNNon, 999, false, false, 0)
	// Packets sent on another path don't keep path 0 from sending an anti-deadlock probe packet.
	sph.AddPath(1, true)
	sendPathPacket(sph, newPathPacketTracker(), 1, now, 1000)
	now = now.Add(10 * time.Millisecond)
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn)}, protocol.EncryptionInitial, now)
	require.NoError(t, err)
	require.Zero(t, sph.appData.bytesInFlight)
	require.Equal(t, protocol.ByteCount(1000), sph.bytesInFlight)

	timeout := now.Add(sph.rttStats.PTO(false))
	requireAlarm(t, sph, 0, alarmTimer{
		Time:            timeout,
		TimerType:       qlog.TimerTypePTO,
		EncryptionLevel: protocol.EncryptionInitial,
	})
	require.NoError(t, sph.OnLossDetectionTimeout(timeout))
	require.Equal(t, uint32(1), sph.appData.ptoCount)
	require.Zero(t, sph.paths[1].ptoCount)
	require.Equal(t, SendPTOInitial, sph.SendModeForPath(0, timeout))
	require.Equal(t, timeout.Add(2*sph.rttStats.PTO(false)), sph.GetLossDetectionTimeout())

	// Once the Initial packet number space is dropped, a Handshake probe packet is sent.
	sph.DropPackets(protocol.EncryptionInitial, timeout)
	require.Equal(t, timeout.Add(sph.rttStats.PTO(false)), sph.GetLossDetectionTimeout())
	require.NoError(t, sph.OnLossDetectionTimeout(sph.GetLossDetectionTimeout()))
	require.Equal(t, SendPTOHandshake, sph.SendModeForPath(0, timeout))
}

// The metrics and the PTO count logged to qlog don't name a path. They are those of path 0.
func TestSentPacketHandlerMultipathQlog(t *testing.T) {
	var eventRecorder events.Recorder
	sph := NewSentPacketHandler(
		0,
		1200,
		utils.NewRTTStats(),
		&utils.ConnectionStats{},
		true,
		false,
		nil,
		protocol.PerspectiveClient,
		&eventRecorder,
		utils.DefaultLogger,
	).(*sentPacketHandler)
	sph.EnableMultipath(nil)
	now := monotime.Now()
	confirmHandshake(sph, now)
	sph.AddPath(1, true)
	sph.rttStats.UpdateRTT(time.Second, 0)
	sph.paths[1].rttStats.UpdateRTT(10*time.Millisecond, 0)
	tracker := newPathPacketTracker()

	eventRecorder.Clear()
	pn0 := sendPathPacket(sph, tracker, 0, now, 1000)
	metrics := eventRecorder.Events(qlog.MetricsUpdated{})
	require.Len(t, metrics, 1)
	require.Equal(t, 1000, metrics[0].(qlog.MetricsUpdated).BytesInFlight)
	require.Equal(t, 1, metrics[0].(qlog.MetricsUpdated).PacketsInFlight)
	// packets sent on path 1 don't change the metrics
	eventRecorder.Clear()
	sendPathPacket(sph, tracker, 1, now, 1000)
	sendPathPacket(sph, tracker, 1, now, 1000)
	require.Empty(t, eventRecorder.Events(qlog.MetricsUpdated{}))

	// PTO on path 1
	eventRecorder.Clear()
	pto1 := now.Add(sph.paths[1].rttStats.PTO(true))
	require.Equal(t, pto1, sph.GetLossDetectionTimeout())
	require.NoError(t, sph.OnLossDetectionTimeout(pto1))
	require.Equal(t, uint32(1), sph.paths[1].ptoCount)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.LossTimerUpdated{
				Type:      qlog.LossTimerUpdateTypeExpired,
				TimerType: qlog.TimerTypePTO,
				EncLevel:  protocol.Encryption1RTT,
			},
			qlog.LossTimerUpdated{
				Type:      qlog.LossTimerUpdateTypeSet,
				TimerType: qlog.TimerTypePTO,
				EncLevel:  protocol.Encryption1RTT,
				Time:      now.Add(2 * sph.paths[1].rttStats.PTO(true)).ToTime(),
			},
		},
		eventRecorder.Events(qlog.PTOCountUpdated{}, qlog.LossTimerUpdated{}),
	)
	// the PTO count of path 1 is reset by an ACK for the probe packets
	require.True(t, sph.QueueProbePacketForPath(1))
	probePNs := []protocol.PacketNumber{
		sendPathPacket(sph, tracker, 1, pto1, 1000),
		sendPathPacket(sph, tracker, 1, pto1, 1000),
	}
	_, err := sph.ReceivedAck(pathAck(1, probePNs...), protocol.Encryption1RTT, pto1.Add(10*time.Millisecond))
	require.NoError(t, err)
	require.Zero(t, sph.paths[1].ptoCount)
	require.Empty(t, eventRecorder.Events(qlog.PTOCountUpdated{}))
	require.Empty(t, eventRecorder.Events(qlog.MetricsUpdated{}))

	// PTO on path 0
	eventRecorder.Clear()
	pto0 := now.Add(sph.rttStats.PTO(true))
	require.Equal(t, pto0, sph.GetLossDetectionTimeout())
	require.NoError(t, sph.OnLossDetectionTimeout(pto0))
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.LossTimerUpdated{
				Type:      qlog.LossTimerUpdateTypeExpired,
				TimerType: qlog.TimerTypePTO,
				EncLevel:  protocol.Encryption1RTT,
			},
			qlog.PTOCountUpdated{PTOCount: 1},
			qlog.LossTimerUpdated{
				Type:      qlog.LossTimerUpdateTypeSet,
				TimerType: qlog.TimerTypePTO,
				EncLevel:  protocol.Encryption1RTT,
				Time:      now.Add(2 * sph.rttStats.PTO(true)).ToTime(),
			},
		},
		eventRecorder.Events(qlog.PTOCountUpdated{}, qlog.LossTimerUpdated{}),
	)
	eventRecorder.Clear()
	_, err = sph.ReceivedAck(pathAck(0, pn0), protocol.Encryption1RTT, pto0.Add(10*time.Millisecond))
	require.NoError(t, err)
	require.Equal(t, []qlogwriter.Event{qlog.PTOCountUpdated{PTOCount: 0}}, eventRecorder.Events(qlog.PTOCountUpdated{}))
}

func TestSentPacketHandlerMultipathAmplificationLimit(t *testing.T) {
	t.Run("server", func(t *testing.T) {
		sph := newMultipathSentPacketHandler(protocol.PerspectiveServer, false, nil)
		now := monotime.Now()
		confirmHandshake(sph, now)
		tracker := newPathPacketTracker()

		sph.AddPath(1, false)
		sph.AddPath(2, true)
		// nothing was received on path 1 yet
		require.Equal(t, SendNone, sph.SendModeForPath(1, now))
		require.Zero(t, sph.AmplificationBudgetForPath(1))
		require.Equal(t, SendAny, sph.SendModeForPath(2, now))
		require.Equal(t, SendAny, sph.SendModeForPath(0, now))
		// the limit doesn't apply to path 0 (after the handshake) and to validated paths
		require.Equal(t, protocol.MaxByteCount, sph.AmplificationBudgetForPath(0))
		require.Equal(t, protocol.MaxByteCount, sph.AmplificationBudgetForPath(2))

		sph.ReceivedBytesForPath(1, 400, now)
		require.Equal(t, protocol.ByteCount(1200), sph.AmplificationBudgetForPath(1))
		require.Equal(t, SendAny, sph.SendModeForPath(1, now))
		sendPathPacket(sph, tracker, 1, now, 1000)
		require.Equal(t, protocol.ByteCount(200), sph.AmplificationBudgetForPath(1))
		require.Equal(t, SendAny, sph.SendModeForPath(1, now))
		sendPathPacket(sph, tracker, 1, now, 200)
		// 3x the bytes received on the path were sent
		require.Zero(t, sph.AmplificationBudgetForPath(1))
		require.Equal(t, SendNone, sph.SendModeForPath(1, now))
		require.Equal(t, SendAny, sph.SendModeForPath(2, now))
		require.Equal(t, SendAny, sph.SendMode(now))
		// The PTO isn't armed for path 1, since it can't send.
		require.Zero(t, sph.GetLossDetectionTimeout())

		// Bytes received on other paths don't count.
		sph.ReceivedBytesForPath(2, 10000, now)
		sph.ReceivedBytes(10000, now)
		require.Equal(t, SendNone, sph.SendModeForPath(1, now))

		sph.ReceivedBytesForPath(1, 1, now)
		require.Equal(t, SendAny, sph.SendModeForPath(1, now))
		require.Equal(t, now.Add(sph.paths[1].rttStats.PTO(true)), sph.GetLossDetectionTimeout())
		sendPathPacket(sph, tracker, 1, now, 1200)
		require.Equal(t, SendNone, sph.SendModeForPath(1, now))
		require.Zero(t, sph.GetLossDetectionTimeout())

		// once the address is validated, the limit doesn't apply any more
		sph.SetPathAddressValidated(1, now)
		require.Equal(t, SendAny, sph.SendModeForPath(1, now))
		require.Equal(t, protocol.MaxByteCount, sph.AmplificationBudgetForPath(1))
		require.Equal(t, now.Add(sph.paths[1].rttStats.PTO(true)), sph.GetLossDetectionTimeout())

		// a path created by receiving a packet is not validated
		sph.ReceivedBytesForPath(3, 100, now)
		sph.AddPath(3, false)
		require.Equal(t, SendAny, sph.SendModeForPath(3, now))
		sendPathPacket(sph, tracker, 3, now, 300)
		require.Equal(t, SendNone, sph.SendModeForPath(3, now))
		require.Equal(t, uint64(10000+10000+400+1+100), sph.connStats.BytesReceived.Load())
	})

	t.Run("client", func(t *testing.T) {
		sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
		now := monotime.Now()
		confirmHandshake(sph, now)
		sph.AddPath(1, false)
		require.Equal(t, SendAny, sph.SendModeForPath(1, now))
		sendPathPacket(sph, newPathPacketTracker(), 1, now, 1200)
		require.Equal(t, SendAny, sph.SendModeForPath(1, now))
		require.Equal(t, protocol.MaxByteCount, sph.AmplificationBudgetForPath(1))
	})

	t.Run("without IETF Multipath QUIC", func(t *testing.T) {
		sph := NewSentPacketHandler(0, 1200, utils.NewRTTStats(), &utils.ConnectionStats{}, false, false, nil, protocol.PerspectiveServer, nil, utils.DefaultLogger)
		sph.AddPath(1, false)
		require.Equal(t, protocol.MaxByteCount, sph.AmplificationBudgetForPath(1))
	})
}

func TestSentPacketHandlerMultipathCongestionControl(t *testing.T) {
	sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
	now := monotime.Now()
	confirmHandshake(sph, now)
	sph.AddPath(1, true)
	sph.AddPath(2, true)
	tracker := newPathPacketTracker()
	require.NotSame(t, sph.paths[1].congestion, sph.paths[2].congestion)
	require.NotSame(t, sph.appData.congestion, sph.paths[1].congestion)

	// fill the congestion window of path 1
	cwnd := sph.paths[1].congestion.GetCongestionWindow()
	for sph.paths[1].bytesInFlight < cwnd {
		sendPathPacket(sph, tracker, 1, now, 1200)
	}
	require.Equal(t, SendAck, sph.SendModeForPath(1, now))
	require.Equal(t, SendAny, sph.SendModeForPath(2, now))
	require.Equal(t, SendAny, sph.SendModeForPath(0, now))
	require.Equal(t, SendAny, sph.SendMode(now))
	require.Equal(t, cwnd, sph.paths[2].congestion.GetCongestionWindow())
	require.Equal(t, cwnd, sph.appData.congestion.GetCongestionWindow())

	// fill the congestion window of the other paths
	for sph.paths[2].bytesInFlight < cwnd {
		sendPathPacket(sph, tracker, 2, now, 1200)
	}
	require.Equal(t, SendAny, sph.SendMode(now))
	for sph.appData.bytesInFlight < cwnd {
		sendPathPacket(sph, tracker, 0, now, 1200)
	}
	require.Equal(t, SendAck, sph.SendMode(now))

	cwnd1, inFlight1, ok := sph.PathCongestionState(1)
	require.True(t, ok)
	require.Equal(t, cwnd, cwnd1)
	require.Equal(t, sph.paths[1].bytesInFlight, inFlight1)
	_, inFlight0, ok := sph.PathCongestionState(0)
	require.True(t, ok)
	require.Equal(t, sph.appData.bytesInFlight, inFlight0)
	_, _, ok = sph.PathCongestionState(5)
	require.False(t, ok)
}

func TestSentPacketHandlerMultipathMaxDatagramSize(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
	sph.AddPath(1, true)
	sph.AddPath(2, true)
	ccs := make(map[protocol.PathID]*mocks.MockSendAlgorithmWithDebugInfos)
	for _, pathID := range []protocol.PathID{0, 1, 2} {
		cc := mocks.NewMockSendAlgorithmWithDebugInfos(mockCtrl)
		sph.path(pathID).congestion = cc
		ccs[pathID] = cc
	}
	ccs[2].EXPECT().SetMaxDatagramSize(protocol.ByteCount(1400))
	sph.SetMaxDatagramSizeForPath(2, 1400)
	ccs[0].EXPECT().SetMaxDatagramSize(protocol.ByteCount(1450))
	sph.SetMaxDatagramSize(1450)
	ccs[0].EXPECT().SetMaxDatagramSize(protocol.ByteCount(1452))
	sph.SetMaxDatagramSizeForPath(0, 1452)
	sph.SetMaxDatagramSizeForPath(3, 1400) // unknown path
}

func TestSentPacketHandlerMultipathPacing(t *testing.T) {
	sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
	now := monotime.Now()
	confirmHandshake(sph, now)
	sph.AddPath(1, true)
	tracker := newPathPacketTracker()
	// use up the pacing budget of path 1
	for sph.SendModeForPath(1, now) == SendAny {
		sendPathPacket(sph, tracker, 1, now, 1200)
	}
	require.Equal(t, SendPacingLimited, sph.SendModeForPath(1, now))
	require.Equal(t, SendAny, sph.SendModeForPath(0, now))
	require.Equal(t, SendAny, sph.SendMode(now))
	require.Zero(t, sph.TimeUntilSendForPath(0))
	require.Zero(t, sph.TimeUntilSend())
	next := sph.TimeUntilSendForPath(1)
	require.True(t, next.After(now))

	for sph.SendModeForPath(0, now) == SendAny {
		sendPathPacket(sph, tracker, 0, now, 1200)
	}
	require.Equal(t, SendPacingLimited, sph.SendMode(now))
	require.Equal(t, min(next, sph.TimeUntilSendForPath(0)), sph.TimeUntilSend())
}

func TestSentPacketHandlerMultipathECNValidationPerPath(t *testing.T) {
	sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, true, nil)
	now := monotime.Now()
	confirmHandshake(sph, now)
	sph.AddPath(1, true)
	tracker := newPathPacketTracker()
	require.Equal(t, protocol.ECT0, sph.ECNModeForPath(0))
	require.Equal(t, protocol.ECT0, sph.ECNModeForPath(1))
	require.Equal(t, protocol.ECNNon, sph.ECNModeForPath(2))
	var pns []protocol.PacketNumber
	for range 10 {
		pns = append(pns, sendPathPacket(sph, tracker, 1, now, 1200))
	}
	// path 1 sent all its testing packets, path 0 didn't
	require.Equal(t, protocol.ECNNon, sph.ECNModeForPath(1))
	require.Equal(t, protocol.ECT0, sph.ECNModeForPath(0))
	require.Equal(t, protocol.ECT0, sph.ECNMode(true))
	// ECN validation fails on path 1: the ACK doesn't contain ECN counts
	_, err := sph.ReceivedAck(pathAck(1, pns...), protocol.Encryption1RTT, now.Add(time.Millisecond))
	require.NoError(t, err)
	require.Equal(t, ecnStateFailed, sph.paths[1].ecnTracker.(*ecnTracker).state)
	require.Equal(t, ecnStateTesting, sph.appData.ecnTracker.(*ecnTracker).state)
}

func TestSentPacketHandlerMultipathMaxPTO(t *testing.T) {
	t.Run("without multipath", func(t *testing.T) {
		rttStats := utils.NewRTTStats()
		rttStats.SetMaxAckDelay(25 * time.Millisecond)
		rttStats.UpdateRTT(30*time.Millisecond, 0)
		sph := NewSentPacketHandler(0, 1200, rttStats, &utils.ConnectionStats{}, true, false, nil, protocol.PerspectiveClient, nil, utils.DefaultLogger)
		require.Equal(t, rttStats.PTO(true), sph.MaxPTO(true))
		require.Equal(t, rttStats.PTO(false), sph.MaxPTO(false))
	})

	t.Run("with multipath", func(t *testing.T) {
		rttStats := utils.NewRTTStats()
		rttStats.SetMaxAckDelay(25 * time.Millisecond)
		sph := NewSentPacketHandler(0, 1200, rttStats, &utils.ConnectionStats{}, true, false, nil, protocol.PerspectiveClient, nil, utils.DefaultLogger).(*sentPacketHandler)
		sph.EnableMultipath(nil)
		now := monotime.Now()
		rttStats.UpdateRTT(10*time.Millisecond, 0)
		require.Equal(t, rttStats.PTO(true), sph.MaxPTO(true))

		sph.AddPath(1, true)
		sph.AddPath(2, true)
		// the peer's max_ack_delay applies to all paths
		require.Equal(t, 25*time.Millisecond, sph.paths[1].rttStats.MaxAckDelay())
		// path 2 doesn't have an RTT estimate yet
		require.Equal(t, sph.paths[2].rttStats.PTO(true), sph.MaxPTO(true))
		sph.paths[1].rttStats.UpdateRTT(200*time.Millisecond, 0)
		sph.paths[2].rttStats.UpdateRTT(100*time.Millisecond, 0)
		require.Equal(t, sph.paths[1].rttStats.PTO(true), sph.MaxPTO(true))
		require.Equal(t, sph.paths[1].rttStats.PTO(false), sph.MaxPTO(false))
		require.Greater(t, sph.MaxPTO(true), sph.MaxPTO(false))

		// Abandoned paths count until they are removed:
		// packets sent by the peer on these paths might still arrive.
		sph.AbandonPath(1, now)
		require.Equal(t, sph.paths[1].rttStats.PTO(true), sph.MaxPTO(true))
		sph.RemovePath(1, now)
		require.Equal(t, sph.paths[2].rttStats.PTO(true), sph.MaxPTO(true))
		sph.RemovePath(2, now)
		require.Equal(t, rttStats.PTO(true), sph.MaxPTO(true))
		// PTO backoff isn't included
		sph.appData.ptoCount = 3
		require.Equal(t, rttStats.PTO(true), sph.MaxPTO(true))
		// once path 0 is removed, the largest PTO of the other paths is used
		sph.AddPath(3, true)
		sph.paths[3].rttStats.UpdateRTT(5*time.Millisecond, 0)
		require.Equal(t, rttStats.PTO(true), sph.MaxPTO(true))
		sph.RemovePath(0, now)
		require.Equal(t, sph.paths[3].rttStats.PTO(true), sph.MaxPTO(true))
	})
}

func TestSentPacketHandlerMultipathTrackedPacketsLimit(t *testing.T) {
	sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
	now := monotime.Now()
	confirmHandshake(sph, now)
	sph.AddPath(1, true)
	sph.AddPath(2, true)
	// send non-ack-eliciting packets, which are not congestion controlled
	send := func(pathID protocol.PathID) {
		pn := sph.PopPacketNumber(pathID, protocol.Encryption1RTT)
		sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, nil, protocol.Encryption1RTT, protocol.ECNNon, 100, false, false, pathID)
	}
	for range protocol.MaxOutstandingSentPackets {
		send(1)
	}
	require.Equal(t, SendAck, sph.SendModeForPath(1, now))
	require.Equal(t, SendAny, sph.SendModeForPath(2, now))
	for sph.paths[1].space.history.Len() < protocol.MaxTrackedSentPackets {
		send(1)
	}
	require.Equal(t, SendNone, sph.SendModeForPath(1, now))
	for sph.paths[2].space.history.Len() < protocol.MaxTrackedSentPackets-1 {
		send(2)
	}
	// the limit applies per path
	require.Equal(t, SendAck, sph.SendModeForPath(2, now))
	require.Equal(t, SendAny, sph.SendModeForPath(0, now))
	require.Equal(t, SendAny, sph.SendMode(now))
}

func TestSentPacketHandlerMultipathIgnorePacketsBelow(t *testing.T) {
	var ignored []pathPacketNumber
	sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, func(pathID protocol.PathID, pn protocol.PacketNumber) {
		ignored = append(ignored, pathPacketNumber{PathID: pathID, PacketNumber: pn})
	})
	now := monotime.Now()
	confirmHandshake(sph, now)
	tracker := newPathPacketTracker()
	send := func(pathID protocol.PathID, largestAcked protocol.PacketNumber, acks ...PathAck) protocol.PacketNumber {
		pn := sph.PopPacketNumber(pathID, protocol.Encryption1RTT)
		sph.SentPacket(now, pn, largestAcked, nil, []Frame{tracker.NewPingFrame(pathID, pn)}, protocol.Encryption1RTT, protocol.ECNNon, 1000, false, false, pathID, acks...)
		return pn
	}
	// an ACK frame (for path 0) and PATH_ACK frames for paths 1 and 2
	pn1 := send(1, 10, PathAck{PathID: 1, LargestAcked: 20}, PathAck{PathID: 2, LargestAcked: 30})
	// only PATH_ACK frames
	pn2 := send(2, protocol.InvalidPacketNumber, PathAck{PathID: 2, LargestAcked: 40})
	pn3 := send(2, protocol.InvalidPacketNumber, PathAck{PathID: 3, LargestAcked: 50}, PathAck{PathID: 0, LargestAcked: 60})
	// no ACK
	pn4 := send(2, protocol.InvalidPacketNumber)
	// only an ACK frame
	pn5 := send(0, 70)
	// The first ACK or PATH_ACK frame is stored inline.
	p1 := sph.paths[1].space.history.packets[0]
	require.Equal(t, protocol.PacketNumber(10), p1.LargestAcked)
	require.Equal(t, protocol.PathID(0), p1.AckPathID)
	require.Equal(t, []PathAck{{PathID: 1, LargestAcked: 20}, {PathID: 2, LargestAcked: 30}}, p1.extraAcks)
	p2 := sph.paths[2].space.history.packets[0]
	require.Equal(t, protocol.PacketNumber(40), p2.LargestAcked)
	require.Equal(t, protocol.PathID(2), p2.AckPathID)
	require.Nil(t, p2.extraAcks)

	_, err := sph.ReceivedAck(pathAck(1, pn1), protocol.Encryption1RTT, now)
	require.NoError(t, err)
	require.Equal(t, []pathPacketNumber{{0, 11}, {1, 21}, {2, 31}}, ignored)
	ignored = nil

	_, err = sph.ReceivedAck(pathAck(2, pn2, pn3, pn4), protocol.Encryption1RTT, now)
	require.NoError(t, err)
	require.Equal(t, []pathPacketNumber{{2, 41}, {3, 51}, {0, 61}}, ignored)
	ignored = nil

	_, err = sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn5)}, protocol.Encryption1RTT, now)
	require.NoError(t, err)
	require.Equal(t, []pathPacketNumber{{0, 71}}, ignored)
	ignored = nil

	// lost packets don't count
	send(1, protocol.InvalidPacketNumber, PathAck{PathID: 1, LargestAcked: 80})
	sph.AbandonPath(1, now)
	require.Empty(t, ignored)
}

func TestSentPacketHandlerMultipathIgnorePacketsBelowPath0(t *testing.T) {
	var ignored []protocol.PacketNumber
	sph := NewSentPacketHandler(0, 1200, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false, func(pn protocol.PacketNumber) {
		ignored = append(ignored, pn)
	}, protocol.PerspectiveClient, nil, utils.DefaultLogger).(*sentPacketHandler)
	sph.EnableMultipath(nil)
	now := monotime.Now()
	tracker := newPathPacketTracker()
	pn := sph.PopPacketNumber(1, protocol.Encryption1RTT)
	sph.SentPacket(now, pn, 10, nil, []Frame{tracker.NewPingFrame(1, pn)}, protocol.Encryption1RTT, protocol.ECNNon, 1000, false, false, 1,
		PathAck{PathID: 0, LargestAcked: 20}, PathAck{PathID: 2, LargestAcked: 30},
	)
	_, err := sph.ReceivedAck(pathAck(1, pn), protocol.Encryption1RTT, now)
	require.NoError(t, err)
	// only the ACK frame and the PATH_ACK frame for path 0
	require.Equal(t, []protocol.PacketNumber{11, 21}, ignored)
}

func TestSentPacketHandlerMultipathMigratedPath(t *testing.T) {
	sph := newMultipathSentPacketHandler(protocol.PerspectiveServer, false, nil)
	now := monotime.Now()
	confirmHandshake(sph, now)
	sph.AddPath(1, true)
	sph.AddPath(2, true)
	tracker := newPathPacketTracker()
	sph.paths[1].rttStats.UpdateRTT(30*time.Millisecond, 0)
	sph.paths[2].rttStats.UpdateRTT(40*time.Millisecond, 0)
	sendPathPacket(sph, tracker, 0, now, 1000)
	pn1 := sendPathPacket(sph, tracker, 1, now, 1000)
	sendPathPacket(sph, tracker, 2, now, 1000)
	path0 := getPathState(&sph.appData)
	path2 := getPathState(sph.paths[2])
	cc1 := sph.paths[1].congestion

	sph.MigratedPathForPath(1, now, 1300)
	require.Equal(t, []protocol.PacketNumber{pn1}, tracker.Lost(1))
	require.False(t, sph.paths[1].rttStats.HasMeasurement())
	require.NotSame(t, cc1, sph.paths[1].congestion)
	require.Zero(t, sph.paths[1].bytesInFlight)
	require.Equal(t, path0, getPathState(&sph.appData))
	require.Equal(t, path2, getPathState(sph.paths[2]))
	require.Empty(t, tracker.Lost(0))
	require.Empty(t, tracker.Lost(2))

	// MigratedPath migrates path 0
	sph.MigratedPath(now, 1300)
	require.Len(t, tracker.Lost(0), 1)
	require.Empty(t, tracker.Lost(2))
	require.Equal(t, path2, getPathState(sph.paths[2]))
}

// After a migration of a path, ECN is validated again on that path (section 9.2 of RFC 9000).
// The other paths are not affected.
func TestSentPacketHandlerMultipathMigratedPathECN(t *testing.T) {
	sph := newMultipathSentPacketHandler(protocol.PerspectiveServer, true, nil)
	now := monotime.Now()
	confirmHandshake(sph, now)
	sph.AddPath(1, true)
	for _, id := range []protocol.PathID{0, 1} {
		// ECN validation fails on both paths: all testing packets are lost
		tracker := sph.path(id).ecnTracker.(*ecnTracker)
		for pn := range protocol.PacketNumber(numECNTestingPackets) {
			require.Equal(t, protocol.ECT0, sph.ECNModeForPath(id))
			tracker.SentPacket(pn, protocol.ECT0)
		}
		for pn := range protocol.PacketNumber(numECNTestingPackets) {
			tracker.LostPacket(pn)
		}
		require.Equal(t, protocol.ECNNon, sph.ECNModeForPath(id))
	}

	sph.MigratedPathForPath(1, now, 1200)
	require.Equal(t, protocol.ECT0, sph.ECNModeForPath(1))
	require.Equal(t, protocol.ECNNon, sph.ECNModeForPath(0))

	sph.MigratedPathForPath(0, now, 1200)
	require.Equal(t, protocol.ECT0, sph.ECNModeForPath(0))
}

type recordingPacketObserver struct {
	sent, acked, lost []PacketEvent
}

func (o *recordingPacketObserver) OnPacketSent(ev PacketEvent)  { o.sent = append(o.sent, ev) }
func (o *recordingPacketObserver) OnPacketAcked(ev PacketEvent) { o.acked = append(o.acked, ev) }
func (o *recordingPacketObserver) OnPacketLost(ev PacketEvent)  { o.lost = append(o.lost, ev) }

func TestSentPacketHandlerMultipathPacketObserver(t *testing.T) {
	sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
	var observer recordingPacketObserver
	sph.SetPacketObserver(&observer)
	now := monotime.Now()
	confirmHandshake(sph, now)
	tracker := newPathPacketTracker()
	var pns []protocol.PacketNumber
	for range 4 {
		pns = append(pns, sendPathPacket(sph, tracker, 1, now, 1000))
	}
	sendPathPacket(sph, tracker, 0, now, 1000)
	require.Len(t, observer.sent, 5)
	for i, ev := range observer.sent[:4] {
		require.Equal(t, protocol.PathID(1), ev.PathID)
		require.Equal(t, pns[i], ev.PacketNumber)
		require.Equal(t, protocol.ByteCount(1000), ev.Length)
		require.True(t, ev.IsAckEliciting)
	}
	require.Zero(t, observer.sent[4].PathID)

	_, err := sph.ReceivedAck(pathAck(1, pns[3]), protocol.Encryption1RTT, now.Add(10*time.Millisecond))
	require.NoError(t, err)
	require.Len(t, observer.acked, 1)
	require.Equal(t, protocol.PathID(1), observer.acked[0].PathID)
	require.Equal(t, pns[3], observer.acked[0].PacketNumber)
	// the first packet is lost (packet threshold)
	require.Len(t, observer.lost, 1)
	require.Equal(t, protocol.PathID(1), observer.lost[0].PathID)
	require.Equal(t, pns[0], observer.lost[0].PacketNumber)
}

// testSkippingPacketNumberGenerator is a skippingPacketNumberGenerator with a deterministic random source.
type testSkippingPacketNumberGenerator struct {
	next, nextToSkip protocol.PacketNumber
	rand             *rand.Rand
}

func newTestSkippingPacketNumberGenerator(r *rand.Rand) *testSkippingPacketNumberGenerator {
	g := &testSkippingPacketNumberGenerator{rand: r}
	g.nextToSkip = 3 + protocol.PacketNumber(r.IntN(20))
	return g
}

func (g *testSkippingPacketNumberGenerator) Peek() protocol.PacketNumber {
	if g.next == g.nextToSkip {
		return g.next + 1
	}
	return g.next
}

func (g *testSkippingPacketNumberGenerator) Pop() (bool, protocol.PacketNumber) {
	if g.next == g.nextToSkip {
		pn := g.next + 1
		g.next += 2
		g.nextToSkip = g.next + 3 + protocol.PacketNumber(g.rand.IntN(20))
		return true, pn
	}
	pn := g.next
	g.next++
	return false, pn
}

// TestSentPacketHandlerMultipathRandomized interleaves sends, PATH_ACKs, losses and PTOs on three paths,
// and checks that every path is recovered independently.
func TestSentPacketHandlerMultipathRandomized(t *testing.T) {
	r := rand.New(rand.NewPCG(13, 37))
	sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
	now := monotime.Now()
	confirmHandshake(sph, now)
	pathIDs := []protocol.PathID{0, 1, 2}
	sph.AddPath(1, true)
	sph.AddPath(2, true)
	for _, pathID := range pathIDs {
		sph.path(pathID).space.pns = newTestSkippingPacketNumberGenerator(r)
	}
	// every path has a different RTT
	rtts := map[protocol.PathID]time.Duration{0: 10 * time.Millisecond, 1: 50 * time.Millisecond, 2: 200 * time.Millisecond}

	tracker := newPathPacketTracker()
	sent := make(map[protocol.PathID][]protocol.PacketNumber)     // in the order sent
	received := make(map[protocol.PathID][]protocol.PacketNumber) // packets "received" by the peer
	sendTimes := make(map[pathPacketNumber]monotime.Time)

	checkInvariants := func(t *testing.T) {
		t.Helper()
		var total protocol.ByteCount
		for _, pathID := range pathIDs {
			p := sph.path(pathID)
			var inFlight protocol.ByteCount
			for pn, pkt := range p.space.history.Packets() {
				require.Equal(t, pathID, pkt.PathID)
				pp := pathPacketNumber{PathID: pathID, PacketNumber: pn}
				require.Zero(t, tracker.acked[pp], "acknowledged packet still in history")
				if pkt.includedInBytesInFlight {
					inFlight += pkt.Length
				}
			}
			require.Equal(t, inFlight, p.bytesInFlight, "path %d", pathID)
			total += p.bytesInFlight
		}
		require.Equal(t, total, sph.bytesInFlight)
	}

	for range 3000 {
		pathID := pathIDs[r.IntN(len(pathIDs))]
		switch op := r.IntN(10); {
		case op < 6: // send a packet
			pn := sendPathPacket(sph, tracker, pathID, now, protocol.ByteCount(100+r.IntN(1100)))
			if s := sent[pathID]; len(s) > 0 {
				require.Greater(t, pn, s[len(s)-1])
			} else {
				require.Zero(t, pn)
			}
			sent[pathID] = append(sent[pathID], pn)
			sendTimes[pathPacketNumber{PathID: pathID, PacketNumber: pn}] = now
			// most packets arrive at the peer
			if r.IntN(10) < 8 {
				received[pathID] = append(received[pathID], pn)
			}
		case op < 8: // receive a PATH_ACK, acknowledging all packets received so far
			if len(received[pathID]) == 0 {
				continue
			}
			// take an RTT sample on the path
			last := received[pathID][len(received[pathID])-1]
			rcvTime := max(now, sendTimes[pathPacketNumber{PathID: pathID, PacketNumber: last}].Add(rtts[pathID]))
			others := make(map[protocol.PathID]pathState)
			for _, id := range pathIDs {
				if id != pathID {
					others[id] = getPathState(sph.path(id))
				}
			}
			largestAckedBefore := sph.path(pathID).space.largestAcked
			_, err := sph.ReceivedAck(pathAck(pathID, received[pathID]...), protocol.Encryption1RTT, rcvTime)
			require.NoError(t, err)
			require.Equal(t, max(largestAckedBefore, last), sph.path(pathID).space.largestAcked)
			for id, s := range others {
				require.Equal(t, s, getPathState(sph.path(id)), "path %d modified by an ACK for path %d", id, pathID)
			}
			now = max(now, rcvTime)
		case op < 9: // let time pass
			now = now.Add(time.Duration(r.IntN(50)) * time.Millisecond)
		default: // run the loss detection timer
			if timeout := sph.GetLossDetectionTimeout(); !timeout.IsZero() {
				now = max(now, timeout)
				require.NoError(t, sph.OnLossDetectionTimeout(now))
				// send the probe packets
				for {
					probePath, ok := sph.NextProbePath()
					if !ok {
						break
					}
					require.Equal(t, SendPTOAppData, sph.SendModeForPath(probePath, now))
					sph.QueueProbePacketForPath(probePath)
					pn := sendPathPacket(sph, tracker, probePath, now, 1000)
					sent[probePath] = append(sent[probePath], pn)
					sendTimes[pathPacketNumber{PathID: probePath, PacketNumber: pn}] = now
					received[probePath] = append(received[probePath], pn)
				}
			}
		}
		checkInvariants(t)
	}

	// Acknowledge all packets received by the peer.
	for _, pathID := range pathIDs {
		if len(received[pathID]) == 0 {
			continue
		}
		now = now.Add(time.Second)
		_, err := sph.ReceivedAck(pathAck(pathID, received[pathID]...), protocol.Encryption1RTT, now)
		require.NoError(t, err)
		checkInvariants(t)
	}
	// Abandon the paths: every packet is either acknowledged or lost.
	for _, pathID := range pathIDs {
		sph.AbandonPath(pathID, now)
	}
	checkInvariants(t)
	require.Zero(t, sph.bytesInFlight)
	// Every frame was either acknowledged or declared lost, exactly once.
	for _, pathID := range pathIDs {
		for _, pn := range sent[pathID] {
			pp := pathPacketNumber{PathID: pathID, PacketNumber: pn}
			require.Equal(t, 1, tracker.acked[pp]+tracker.lost[pp], "%v", pp)
		}
		require.NotEmpty(t, tracker.Acked(pathID))
		require.NotEmpty(t, tracker.Lost(pathID))
	}
	require.True(t, sph.GetLossDetectionTimeout().IsZero())
}

// TestSentPacketHandlerMultipathRandomizedTimers interleaves sends, path probe packets, PATH_ACKs, timeouts,
// and the abandonment and removal of paths with very different RTTs.
// It checks that the alarm is set for the earliest timer of all paths (RFC 9002, Appendix A.8, applied per path),
// that a timeout only handles a timer that expired, and that every packet is acknowledged or declared lost exactly once.
func TestSentPacketHandlerMultipathRandomizedTimers(t *testing.T) {
	for seed := range uint64(20) {
		t.Run(fmt.Sprintf("seed %d", seed), func(t *testing.T) {
			testSentPacketHandlerMultipathRandomizedTimers(t, seed)
		})
	}
}

func testSentPacketHandlerMultipathRandomizedTimers(t *testing.T, seed uint64) {
	r := rand.New(rand.NewPCG(seed, 7))
	sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
	now := monotime.Now()
	confirmHandshake(sph, now)
	pathIDs := []protocol.PathID{0, 1, 2, 3}
	rtts := make(map[protocol.PathID]time.Duration)
	for _, pathID := range pathIDs {
		sph.AddPath(pathID, true)
		sph.path(pathID).space.pns = newTestSkippingPacketNumberGenerator(r)
		// fast and slow paths
		if r.IntN(2) == 0 {
			rtts[pathID] = time.Duration(5+r.IntN(20)) * time.Millisecond
		} else {
			rtts[pathID] = time.Duration(200+r.IntN(800)) * time.Millisecond
		}
	}

	tracker := newPathPacketTracker()
	sent := make(map[protocol.PathID][]protocol.PacketNumber)
	received := make(map[protocol.PathID][]protocol.PacketNumber) // packets "received" by the peer
	sendTimes := make(map[pathPacketNumber]monotime.Time)
	isProbe := make(map[pathPacketNumber]bool)
	abandoned := make(map[protocol.PathID]bool)
	removed := make(map[protocol.PathID]bool)

	send := func(pathID protocol.PathID, probe bool) {
		var pn protocol.PacketNumber
		if probe {
			pn = sendPathProbePacket(sph, tracker, pathID, now)
		} else {
			pn = sendPathPacket(sph, tracker, pathID, now, protocol.ByteCount(100+r.IntN(1100)))
		}
		pp := pathPacketNumber{PathID: pathID, PacketNumber: pn}
		sent[pathID] = append(sent[pathID], pn)
		sendTimes[pp] = now
		isProbe[pp] = probe
		if r.IntN(10) < 7 {
			received[pathID] = append(received[pathID], pn)
		}
	}
	ptoTime := func(p *pathRecovery) monotime.Time {
		return p.space.lastAckElicitingPacketTime.Add(scalePTO(p.rttStats.PTO(true), p.ptoCount))
	}
	// the timer of a path: its loss time if one is set, and its PTO time otherwise,
	// or the loss time of its first path probe packet, if that is earlier
	pathTimer := func(p *pathRecovery) monotime.Time {
		var timer monotime.Time
		if !p.abandoned && p.space.history.HasOutstandingPackets() {
			timer = p.space.lossTime
			if timer.IsZero() {
				timer = ptoTime(p)
			}
		}
		if _, probe := p.space.history.FirstOutstandingPathProbe(); probe != nil {
			if lossTime := probe.SendTime.Add(pathProbePacketLossTimeout); timer.IsZero() || lossTime.Before(timer) {
				timer = lossTime
			}
		}
		return timer
	}
	lostDataPackets := func(pathID protocol.PathID) int {
		var n int
		for _, pn := range tracker.Lost(pathID) {
			if !isProbe[pathPacketNumber{PathID: pathID, PacketNumber: pn}] {
				n++
			}
		}
		return n
	}
	checkInvariants := func(t *testing.T) {
		t.Helper()
		var total protocol.ByteCount
		var alarm monotime.Time
		for _, pathID := range pathIDs {
			if removed[pathID] {
				continue
			}
			p := sph.path(pathID)
			var inFlight protocol.ByteCount
			for _, pkt := range p.space.history.Packets() {
				if pkt.includedInBytesInFlight {
					inFlight += pkt.Length
				}
			}
			require.Equal(t, inFlight, p.bytesInFlight, "path %d", pathID)
			total += inFlight
			if timer := pathTimer(p); !timer.IsZero() && (alarm.IsZero() || timer.Before(alarm)) {
				alarm = timer
			}
		}
		require.Equal(t, total, sph.bytesInFlight)
		require.Equal(t, alarm, sph.GetLossDetectionTimeout())
	}
	// fireTimers runs the loss detection timer as long as it expired, as the connection does
	fireTimers := func(t *testing.T) {
		t.Helper()
		for {
			timeout := sph.GetLossDetectionTimeout()
			if timeout.IsZero() || timeout.After(now) {
				return
			}
			firedPath := sph.alarmPathID
			isProbeTimer := sph.alarm.TimerType == qlog.TimerTypePathProbe
			ptoCounts := make(map[protocol.PathID]uint32)
			ptoTimes := make(map[protocol.PathID]monotime.Time)
			lossTimes := make(map[protocol.PathID]monotime.Time)
			lost := make(map[protocol.PathID]int)
			for _, pathID := range pathIDs {
				if removed[pathID] {
					continue
				}
				p := sph.path(pathID)
				ptoCounts[pathID] = p.ptoCount
				ptoTimes[pathID] = ptoTime(p)
				lossTimes[pathID] = p.space.lossTime
				lost[pathID] = lostDataPackets(pathID)
			}
			require.NoError(t, sph.OnLossDetectionTimeout(now))
			for pathID, ptoCount := range ptoCounts {
				p := sph.path(pathID)
				if p.ptoCount != ptoCount {
					// only the PTO that expired fires
					require.False(t, isProbeTimer)
					require.Equal(t, firedPath, pathID)
					require.Equal(t, ptoCount+1, p.ptoCount)
					require.True(t, lossTimes[pathID].IsZero())
					require.False(t, ptoTimes[pathID].After(now), "PTO of path %d fired %s early", pathID, ptoTimes[pathID].Sub(now))
				}
				if n := lostDataPackets(pathID); n != lost[pathID] {
					// only the loss timer that expired fires
					require.False(t, isProbeTimer)
					require.Equal(t, firedPath, pathID)
					require.False(t, lossTimes[pathID].IsZero())
					require.False(t, lossTimes[pathID].After(now))
				}
			}
			// send the probe packets
			for {
				probePath, ok := sph.NextProbePath()
				if !ok {
					break
				}
				require.Equal(t, SendPTOAppData, sph.SendModeForPath(probePath, now))
				sph.QueueProbePacketForPath(probePath)
				send(probePath, false)
			}
			checkInvariants(t)
		}
	}

	for range 1000 {
		pathID := pathIDs[r.IntN(len(pathIDs))]
		switch op := r.IntN(40); {
		case op < 20: // send a packet
			if abandoned[pathID] {
				continue
			}
			send(pathID, r.IntN(10) == 0)
		case op < 30: // receive a PATH_ACK, acknowledging all packets received so far
			if len(received[pathID]) == 0 {
				continue
			}
			last := received[pathID][len(received[pathID])-1]
			rcvTime := max(now, sendTimes[pathPacketNumber{PathID: pathID, PacketNumber: last}].Add(rtts[pathID]))
			// let the timers that expired before the ACK arrives fire
			now = rcvTime
			fireTimers(t)
			_, err := sph.ReceivedAck(pathAck(pathID, received[pathID]...), protocol.Encryption1RTT, rcvTime)
			require.NoError(t, err)
		case op < 37: // let time pass
			now = now.Add(time.Duration(r.IntN(500)) * time.Millisecond)
			fireTimers(t)
		case op < 38: // rarely abandon a path
			if r.IntN(20) == 0 && !abandoned[pathID] {
				abandoned[pathID] = true
				sph.AbandonPath(pathID, now)
			}
		case op < 39: // rarely remove a path
			if r.IntN(20) == 0 && pathID != 0 && !removed[pathID] {
				abandoned[pathID] = true
				removed[pathID] = true
				sph.RemovePath(pathID, now)
			}
		default: // jump to the next timeout
			if timeout := sph.GetLossDetectionTimeout(); !timeout.IsZero() {
				now = max(now, timeout)
				fireTimers(t)
			}
		}
		checkInvariants(t)
	}

	// Abandon all paths: every packet is either acknowledged or lost, exactly once.
	for _, pathID := range pathIDs {
		if !removed[pathID] {
			sph.AbandonPath(pathID, now)
		}
	}
	checkInvariants(t)
	require.Zero(t, sph.bytesInFlight)
	require.Zero(t, sph.GetLossDetectionTimeout())
	for pathID, pns := range sent {
		for _, pn := range pns {
			pp := pathPacketNumber{PathID: pathID, PacketNumber: pn}
			require.Equal(t, 1, tracker.acked[pp]+tracker.lost[pp], "%v (path probe: %t)", pp, isProbe[pp])
		}
	}
}

// unregisteringCongestionController is a coupled congestion controller (like OLIA).
// It counts how often it was removed from the shared state.
type unregisteringCongestionController struct {
	congestion.SendAlgorithmWithDebugInfos

	pathID       protocol.PathID
	unregistered *map[protocol.PathID]int
	// the state taken over from the controller that this controller replaced
	state *congestion.State
}

func (c *unregisteringCongestionController) Unregister() { (*c.unregistered)[c.pathID]++ }

func (c *unregisteringCongestionController) TakeOverState(s congestion.State) { c.state = &s }

// With IETF Multipath QUIC, the congestion control factory creates a congestion controller for every path,
// including path 0. A coupled congestion controller is removed from the state it shares with the other paths
// when its path is abandoned, or migrates to another 4-tuple.
func TestSentPacketHandlerMultipathCongestionControlFactory(t *testing.T) {
	sph := NewSentPacketHandler(0, 1200, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false, nil, protocol.PerspectiveClient, nil, utils.DefaultLogger).(*sentPacketHandler)
	var created []protocol.PathID
	unregistered := make(map[protocol.PathID]int)
	controllers := make(map[protocol.PathID]*unregisteringCongestionController)
	sph.SetCongestionControlFactory(func(pathID protocol.PathID, rttStats *utils.RTTStats, size protocol.ByteCount) congestion.SendAlgorithmWithDebugInfos {
		created = append(created, pathID)
		c := &unregisteringCongestionController{
			SendAlgorithmWithDebugInfos: congestion.NewCubicSender(congestion.DefaultClock{}, rttStats, &utils.ConnectionStats{}, size, true, nil),
			pathID:                      pathID,
			unregistered:                &unregistered,
		}
		controllers[pathID] = c
		return c
	})
	sph.EnableMultipath(nil)
	now := monotime.Now()
	confirmHandshake(sph, now)
	sph.AddPath(1, true)
	sph.AddPath(2, true)
	require.Equal(t, []protocol.PathID{0, 1, 2}, created)
	require.Same(t, controllers[0], sph.appData.congestion)
	require.Same(t, controllers[1], sph.paths[1].congestion)

	sph.AbandonPath(1, now)
	require.Equal(t, map[protocol.PathID]int{1: 1}, unregistered)
	sph.RemovePath(1, now)
	require.NotZero(t, unregistered[1])
	require.Zero(t, unregistered[2])

	// path 2 migrates: it gets a new controller
	sph.MigratedPathForPath(2, now, 1200)
	require.Equal(t, 1, unregistered[2])
	require.Equal(t, []protocol.PathID{0, 1, 2, 2}, created)

	sph.RemovePath(0, now)
	require.Equal(t, 1, unregistered[0])
}

// Path 0 was used before IETF Multipath QUIC was enabled. The controller created for path 0 by the congestion control
// factory continues with the state of the controller used so far: the response to a loss detected before is kept
// (section 7.3.2 of RFC 9002).
func TestSentPacketHandlerMultipathCongestionControlFactoryKeepsState(t *testing.T) {
	t.Run("controller takes over the state", func(t *testing.T) {
		testSentPacketHandlerMultipathCongestionControlFactoryKeepsState(t, true)
	})
	t.Run("controller can't take over the state", func(t *testing.T) {
		testSentPacketHandlerMultipathCongestionControlFactoryKeepsState(t, false)
	})
}

// cubicCongestionController is a congestion controller that can't take over the state of another controller.
type cubicCongestionController struct {
	congestion.SendAlgorithmWithDebugInfos
	unregistered bool
}

func (c *cubicCongestionController) Unregister() { c.unregistered = true }

func testSentPacketHandlerMultipathCongestionControlFactoryKeepsState(t *testing.T, takesOverState bool) {
	sph := NewSentPacketHandler(0, 1200, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false, nil, protocol.PerspectiveClient, nil, utils.DefaultLogger).(*sentPacketHandler)
	now := monotime.Now()
	confirmHandshake(sph, now)
	tracker := newPathPacketTracker()
	var pns []protocol.PacketNumber
	for range 6 {
		pns = append(pns, sendPathPacket(sph, tracker, 0, now, 1200))
	}
	// the first 3 packets are lost
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[3:]...)}, protocol.Encryption1RTT, now.Add(20*time.Millisecond))
	require.NoError(t, err)
	require.Len(t, tracker.Lost(0), 3)
	cc := sph.appData.congestion
	require.False(t, cc.InSlowStart())
	state := cc.(congestion.StateExporter).State()
	require.Equal(t, cc.GetCongestionWindow(), state.CongestionWindow)

	unregistered := make(map[protocol.PathID]int)
	var created congestion.SendAlgorithmWithDebugInfos
	sph.SetCongestionControlFactory(func(pathID protocol.PathID, rttStats *utils.RTTStats, size protocol.ByteCount) congestion.SendAlgorithmWithDebugInfos {
		require.Zero(t, pathID)
		cubic := congestion.NewCubicSender(congestion.DefaultClock{}, rttStats, &utils.ConnectionStats{}, size, true, nil)
		if takesOverState {
			created = &unregisteringCongestionController{SendAlgorithmWithDebugInfos: cubic, pathID: pathID, unregistered: &unregistered}
		} else {
			created = &cubicCongestionController{SendAlgorithmWithDebugInfos: cubic}
		}
		return created
	})
	sph.EnableMultipath(nil)
	require.NotNil(t, created)
	if takesOverState {
		require.Same(t, created, sph.appData.congestion)
		require.Equal(t, &state, created.(*unregisteringCongestionController).state)
		require.Empty(t, unregistered)
	} else {
		// path 0 keeps its controller
		require.Same(t, cc, sph.appData.congestion)
		require.True(t, created.(*cubicCongestionController).unregistered)
	}
}

// OutstandingPackets returns the ack-eliciting packets sent on a path that were neither acknowledged nor declared lost.
func TestSentPacketHandlerMultipathOutstandingPackets(t *testing.T) {
	sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
	now := monotime.Now()
	confirmHandshake(sph, now)
	sph.AddPath(1, true)
	tracker := newPathPacketTracker()
	var pns []protocol.PacketNumber
	for range 3 {
		pns = append(pns, sendPathPacket(sph, tracker, 1, now, 1000))
	}
	sendPathProbePacket(sph, tracker, 1, now)
	// an MTU probe packet
	mtuPN := sph.PopPacketNumber(1, protocol.Encryption1RTT)
	sph.SentPacket(now, mtuPN, protocol.InvalidPacketNumber, nil, []Frame{tracker.NewPingFrame(1, mtuPN)}, protocol.Encryption1RTT, protocol.ECNNon, 1500, true, false, 1)
	sendPathPacket(sph, tracker, 0, now, 1000)

	outstanding := func(pathID protocol.PathID) []protocol.PacketNumber {
		var pns []protocol.PacketNumber
		for ev := range sph.OutstandingPackets(pathID) {
			require.Equal(t, pathID, ev.PathID)
			require.Len(t, ev.Frames, 1)
			pns = append(pns, ev.PacketNumber)
		}
		return pns
	}
	require.Equal(t, pns, outstanding(1))
	_, err := sph.ReceivedAck(pathAck(1, pns[1]), protocol.Encryption1RTT, now.Add(10*time.Millisecond))
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{pns[0], pns[2]}, outstanding(1))
	require.Len(t, outstanding(0), 1)
	require.Empty(t, outstanding(5))
	sph.AbandonPath(1, now)
	require.Empty(t, outstanding(1))
}

// DeclareOutstandingLost declares the outstanding packets of a path lost.
// Like other lost packets, they are reported to the packet observer and to the path's congestion controller.
// The PTO state of the path is kept. Acknowledgments for these packets are ignored.
func TestSentPacketHandlerMultipathDeclareOutstandingLost(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
	var observer recordingPacketObserver
	sph.SetPacketObserver(&observer)
	now := monotime.Now()
	confirmHandshake(sph, now)
	sph.AddPath(1, true)
	cc := mocks.NewMockSendAlgorithmWithDebugInfos(mockCtrl)
	cc.EXPECT().OnPacketSent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	cc.EXPECT().CanSend(gomock.Any()).Return(true).AnyTimes()
	cc.EXPECT().HasPacingBudget(gomock.Any()).Return(true).AnyTimes()
	sph.paths[1].congestion = cc
	tracker := newPathPacketTracker()
	var pns []protocol.PacketNumber
	for range 3 {
		pns = append(pns, sendPathPacket(sph, tracker, 1, now, 1000))
	}
	probePN := sendPathProbePacket(sph, tracker, 1, now)
	pn0 := sendPathPacket(sph, tracker, 0, now, 1000)
	sph.paths[1].ptoCount = 2

	for _, pn := range pns {
		cc.EXPECT().OnCongestionEvent(pn, protocol.ByteCount(1000), protocol.ByteCount(3000))
	}
	sph.DeclareOutstandingLost(1, now)
	require.True(t, mockCtrl.Satisfied())
	require.Equal(t, pns, tracker.Lost(1))
	require.Len(t, observer.lost, 3)
	for i, ev := range observer.lost {
		require.Equal(t, protocol.PathID(1), ev.PathID)
		require.Equal(t, pns[i], ev.PacketNumber)
	}
	require.Zero(t, sph.paths[1].bytesInFlight)
	require.Equal(t, protocol.ByteCount(1000), sph.bytesInFlight)
	require.Equal(t, uint32(2), sph.paths[1].ptoCount)
	require.True(t, sph.paths[1].space.history.HasOutstandingPathProbes())
	require.False(t, sph.paths[1].abandoned)
	require.Empty(t, tracker.Lost(0))
	require.NotEqual(t, protocol.PathID(1), sph.alarmPathID)

	// acknowledgments for the packets are ignored
	_, err := sph.ReceivedAck(pathAck(1, append(slices.Clone(pns), probePN)...), protocol.Encryption1RTT, now.Add(10*time.Millisecond))
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{probePN}, tracker.Acked(1))
	// a new packet is sent on the path: the PTO timer of the path is set
	require.True(t, sph.pathPTOTime(sph.paths[1]).IsZero())
	pn := sendPathPacket(sph, tracker, 1, now.Add(20*time.Millisecond), 1000)
	require.Equal(t, protocol.ByteCount(1000), sph.paths[1].bytesInFlight)
	require.False(t, sph.pathPTOTime(sph.paths[1]).IsZero())
	for ev := range sph.OutstandingPackets(1) {
		require.Equal(t, pn, ev.PacketNumber)
	}
	// the packet sent on path 0 is still outstanding
	for ev := range sph.OutstandingPackets(0) {
		require.Equal(t, pn0, ev.PacketNumber)
	}
}

// The loss of the packets declared lost by DeclareOutstandingLost reduces the congestion window of the path,
// and ends slow start (section 7.3.2 of RFC 9002). When the path recovers, it doesn't send at the old rate.
func TestSentPacketHandlerMultipathDeclareOutstandingLostCongestion(t *testing.T) {
	sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
	now := monotime.Now()
	confirmHandshake(sph, now)
	sph.AddPath(1, true)
	tracker := newPathPacketTracker()
	pn := sendPathPacket(sph, tracker, 1, now, 1000)
	now = now.Add(10 * time.Millisecond)
	_, err := sph.ReceivedAck(pathAck(1, pn), protocol.Encryption1RTT, now)
	require.NoError(t, err)
	cc := sph.paths[1].congestion
	cwnd := cc.GetCongestionWindow()
	require.True(t, cc.InSlowStart())

	var pns []protocol.PacketNumber
	for range 10 {
		pns = append(pns, sendPathPacket(sph, tracker, 1, now, 1000))
	}
	now = now.Add(600 * time.Millisecond)
	sph.DeclareOutstandingLost(1, now)
	require.Equal(t, pns, tracker.Lost(1))
	require.Less(t, cc.GetCongestionWindow(), cwnd)
	require.False(t, cc.InSlowStart())
	require.True(t, cc.InRecovery())
	reduced := cc.GetCongestionWindow()

	// The path recovers: a PING is acknowledged. The recovery period ends, the window stays reduced.
	ping := sendPathPacket(sph, tracker, 1, now, 50)
	now = now.Add(10 * time.Millisecond)
	_, err = sph.ReceivedAck(pathAck(1, ping), protocol.Encryption1RTT, now)
	require.NoError(t, err)
	require.False(t, cc.InRecovery())
	require.False(t, cc.InSlowStart())
	require.Equal(t, reduced, cc.GetCongestionWindow())
	// path 0 is not affected
	require.True(t, sph.appData.congestion.InSlowStart())
}

// If all ECN testing packets of a path are declared lost by DeclareOutstandingLost, ECN validation fails on the path
// (section 13.4.2.1 of RFC 9000).
func TestSentPacketHandlerMultipathDeclareOutstandingLostECN(t *testing.T) {
	sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, true, nil)
	now := monotime.Now()
	confirmHandshake(sph, now)
	sph.AddPath(1, true)
	tracker := newPathPacketTracker()
	for range numECNTestingPackets {
		require.Equal(t, protocol.ECT0, sph.ECNModeForPath(1))
		sendPathPacket(sph, tracker, 1, now, 1000)
	}
	sendPathPacket(sph, tracker, 0, now, 1000)
	ecn := sph.path(1).ecnTracker.(*ecnTracker)
	require.Equal(t, ecnStateUnknown, ecn.state)
	sph.DeclareOutstandingLost(1, now)
	require.Equal(t, ecnStateFailed, ecn.state)
	require.Equal(t, protocol.ECT0, sph.ECNModeForPath(0))
}
