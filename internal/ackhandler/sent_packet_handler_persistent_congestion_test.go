package ackhandler

import (
	"fmt"
	"testing"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/congestion"
	"github.com/AeonDave/mp-quic-go/internal/mocks"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/utils"
	"github.com/AeonDave/mp-quic-go/internal/wire"
	"github.com/AeonDave/mp-quic-go/qlog"
	"github.com/AeonDave/mp-quic-go/qlogwriter"
	"github.com/AeonDave/mp-quic-go/testutils/events"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// These tests cover persistent congestion (section 7.6 of RFC 9002).

const (
	pcTestRTT         = 100 * time.Millisecond
	pcTestMaxAckDelay = 25 * time.Millisecond
	pcTestPacketSize  = protocol.ByteCount(1200)
	// the minimum congestion window of the Reno controller
	pcTestMinCwnd = 2 * pcTestPacketSize
)

// newPersistentCongestionTestHandler returns the sent packet handler of a server whose handshake is confirmed.
// If rttSample is set, an RTT sample of pcTestRTT is taken 1ms before the time returned.
func newPersistentCongestionTestHandler(t *testing.T, rttSample bool, qlogger qlogwriter.Recorder) (*sentPacketHandler, *packetTracker, monotime.Time) {
	t.Helper()
	rttStats := utils.NewRTTStats()
	rttStats.SetMaxAckDelay(pcTestMaxAckDelay)
	sph := NewSentPacketHandler(
		0,
		pcTestPacketSize,
		rttStats,
		&utils.ConnectionStats{},
		true,
		false,
		nil,
		protocol.PerspectiveServer,
		qlogger,
		utils.DefaultLogger,
	).(*sentPacketHandler)
	now := monotime.Now()
	confirmHandshake(sph, now)
	var packets packetTracker
	if rttSample {
		pn := sendPCTestPacket(sph, &packets, now)
		now = now.Add(pcTestRTT)
		_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn)}, protocol.Encryption1RTT, now)
		require.NoError(t, err)
		require.Equal(t, now, sph.appData.firstRTTSampleTime)
		packets.Reset()
		now = now.Add(time.Millisecond)
	}
	return sph, &packets, now
}

func sendPCTestPacket(sph *sentPacketHandler, packets *packetTracker, t monotime.Time) protocol.PacketNumber {
	pn := sph.PopPacketNumber(0, protocol.Encryption1RTT)
	sph.SentPacket(t, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.Encryption1RTT, protocol.ECNNon, pcTestPacketSize, false, false, 0)
	return pn
}

// pcTestDuration returns the persistent congestion duration after n RTT samples of pcTestRTT.
func pcTestDuration(n int) time.Duration {
	rttStats := utils.NewRTTStats()
	rttStats.SetMaxAckDelay(pcTestMaxAckDelay)
	for range n {
		rttStats.UpdateRTT(pcTestRTT, 0)
	}
	return persistentCongestionThreshold * rttStats.PTO(true)
}

func requirePersistentCongestion(t *testing.T, cong congestion.SendAlgorithmWithDebugInfos, established bool) {
	t.Helper()
	if established {
		require.Equal(t, pcTestMinCwnd, cong.GetCongestionWindow(), "expected persistent congestion")
	} else {
		require.Greater(t, cong.GetCongestionWindow(), pcTestMinCwnd, "expected no persistent congestion")
	}
}

type pcTestPacket struct {
	offset          time.Duration // the send time, relative to the first RTT sample
	nonAckEliciting bool
	mtuProbe        bool
	acked           bool // acknowledged together with the last packet
}

func TestSentPacketHandlerPersistentCongestion(t *testing.T) {
	const ms = time.Millisecond
	for _, tc := range []struct {
		name        string
		packets     []pcTestPacket
		established bool
	}{
		{
			name:        "established",
			packets:     []pcTestPacket{{offset: 0}, {offset: 300 * ms}, {offset: 600 * ms}, {offset: 900 * ms}, {offset: 1200 * ms}},
			established: true,
		},
		{
			name:        "duration too short",
			packets:     []pcTestPacket{{offset: 0}, {offset: 300 * ms}, {offset: 600 * ms}, {offset: 800 * ms}},
			established: false,
		},
		{
			name:        "packet acknowledged in between",
			packets:     []pcTestPacket{{offset: 0}, {offset: 300 * ms}, {offset: 600 * ms, acked: true}, {offset: 900 * ms}, {offset: 1200 * ms}},
			established: false,
		},
		{
			name:        "first packet not ack-eliciting",
			packets:     []pcTestPacket{{offset: 0, nonAckEliciting: true}, {offset: 500 * ms}, {offset: 1200 * ms}},
			established: false,
		},
		{
			name:        "last packet not ack-eliciting",
			packets:     []pcTestPacket{{offset: 0}, {offset: 600 * ms}, {offset: 1200 * ms, nonAckEliciting: true}},
			established: false,
		},
		{
			name:        "non-ack-eliciting packet in between",
			packets:     []pcTestPacket{{offset: 0}, {offset: 600 * ms, nonAckEliciting: true}, {offset: 1200 * ms}},
			established: true,
		},
		{
			name:        "first packet is a Path MTU probe packet",
			packets:     []pcTestPacket{{offset: 0, mtuProbe: true}, {offset: 500 * ms}, {offset: 1200 * ms}},
			established: false,
		},
		{
			name:        "Path MTU probe packet in between",
			packets:     []pcTestPacket{{offset: 0}, {offset: 600 * ms, mtuProbe: true}, {offset: 1200 * ms}},
			established: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sph, packets, start := newPersistentCongestionTestHandler(t, true, nil)
			var acked []protocol.PacketNumber
			var last time.Duration
			for _, p := range tc.packets {
				pn := sph.PopPacketNumber(0, protocol.Encryption1RTT)
				var frames []Frame
				if !p.nonAckEliciting {
					frames = []Frame{packets.NewPingFrame(pn)}
				}
				sph.SentPacket(start.Add(p.offset), pn, protocol.InvalidPacketNumber, nil, frames, protocol.Encryption1RTT, protocol.ECNNon, pcTestPacketSize, p.mtuProbe, false, 0)
				if p.acked {
					acked = append(acked, pn)
				}
				last = p.offset
			}
			sendTime := start.Add(last + 100*time.Millisecond)
			acked = append(acked, sendPCTestPacket(sph, packets, sendTime))
			_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(acked...)}, protocol.Encryption1RTT, sendTime.Add(pcTestRTT))
			require.NoError(t, err)
			require.NotEmpty(t, packets.Lost)
			requirePersistentCongestion(t, sph.appData.congestion, tc.established)
			if tc.established {
				// slow start begins again, up to the slow start threshold of the congestion event
				require.True(t, sph.appData.congestion.InSlowStart())
			}
		})
	}
}

// The duration between the send times of the two packets must exceed the persistent congestion duration.
func TestSentPacketHandlerPersistentCongestionDuration(t *testing.T) {
	// the RTT sample taken when the last packet is acknowledged is the second sample
	duration := pcTestDuration(2)
	require.Equal(t, 3*(pcTestRTT+4*pcTestRTT*3/8+pcTestMaxAckDelay), duration)

	t.Run("equal to the duration", func(t *testing.T) {
		testSentPacketHandlerPersistentCongestionDuration(t, duration, false)
	})
	t.Run("longer than the duration", func(t *testing.T) {
		testSentPacketHandlerPersistentCongestionDuration(t, duration+time.Microsecond, true)
	})
}

func testSentPacketHandlerPersistentCongestionDuration(t *testing.T, span time.Duration, established bool) {
	sph, packets, start := newPersistentCongestionTestHandler(t, true, nil)
	t1 := start.Add(time.Millisecond)
	sendPCTestPacket(sph, packets, t1)
	sendPCTestPacket(sph, packets, t1.Add(span))
	t3 := t1.Add(span + 100*time.Millisecond)
	pn := sendPCTestPacket(sph, packets, t3)
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn)}, protocol.Encryption1RTT, t3.Add(pcTestRTT))
	require.NoError(t, err)
	require.Len(t, packets.Lost, 2)
	requirePersistentCongestion(t, sph.appData.congestion, established)
}

// A packet sent between the two lost packets, acknowledged by an earlier ACK frame,
// prevents persistent congestion.
func TestSentPacketHandlerPersistentCongestionAckedEarlier(t *testing.T) {
	t.Run("acknowledged", func(t *testing.T) {
		testSentPacketHandlerPersistentCongestionAckedEarlier(t, true)
	})
	t.Run("not acknowledged", func(t *testing.T) {
		testSentPacketHandlerPersistentCongestionAckedEarlier(t, false)
	})
}

func testSentPacketHandlerPersistentCongestionAckedEarlier(t *testing.T, ackEarlier bool) {
	sph, packets, start := newPersistentCongestionTestHandler(t, true, nil)
	pn0 := sendPCTestPacket(sph, packets, start)
	pn1 := sendPCTestPacket(sph, packets, start.Add(time.Millisecond))
	if ackEarlier {
		// packet 0 is neither acknowledged nor declared lost by this ACK
		_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn1)}, protocol.Encryption1RTT, start.Add(time.Millisecond+pcTestRTT))
		require.NoError(t, err)
		require.Equal(t, []protocol.PacketNumber{pn1}, packets.Acked)
		require.Empty(t, packets.Lost)
	}
	pn2 := sendPCTestPacket(sph, packets, start.Add(500*time.Millisecond))
	pn3 := sendPCTestPacket(sph, packets, start.Add(1100*time.Millisecond))
	pn4 := sendPCTestPacket(sph, packets, start.Add(1200*time.Millisecond))
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn4)}, protocol.Encryption1RTT, start.Add(1200*time.Millisecond+pcTestRTT))
	require.NoError(t, err)
	if ackEarlier {
		require.Equal(t, []protocol.PacketNumber{pn0, pn2, pn3}, packets.Lost)
	} else {
		require.Equal(t, []protocol.PacketNumber{pn0, pn1, pn2, pn3}, packets.Lost)
	}
	requirePersistentCongestion(t, sph.appData.congestion, !ackEarlier)
}

// Only packets sent after the first RTT sample are taken into account.
func TestSentPacketHandlerPersistentCongestionRTTSample(t *testing.T) {
	t.Run("no RTT sample", func(t *testing.T) {
		sph, packets, start := newPersistentCongestionTestHandler(t, false, nil)
		sendPCTestPacket(sph, packets, start)
		sendPCTestPacket(sph, packets, start.Add(1200*time.Millisecond))
		pn := sendPCTestPacket(sph, packets, start.Add(1300*time.Millisecond))
		// this ACK provides the first RTT sample, but the lost packets were sent before
		_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn)}, protocol.Encryption1RTT, start.Add(1300*time.Millisecond+pcTestRTT))
		require.NoError(t, err)
		require.Len(t, packets.Lost, 2)
		require.False(t, sph.appData.firstRTTSampleTime.IsZero())
		requirePersistentCongestion(t, sph.appData.congestion, false)
	})

	t.Run("ACK without RTT sample", func(t *testing.T) {
		sph, packets, start := newPersistentCongestionTestHandler(t, false, nil)
		pn := sendPCTestPacket(sph, packets, start)
		// an RTT sample of 0 is not used
		_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn)}, protocol.Encryption1RTT, start)
		require.NoError(t, err)
		require.Equal(t, []protocol.PacketNumber{pn}, packets.Acked)
		require.False(t, sph.rttStats.HasMeasurement())
		require.Zero(t, sph.appData.firstRTTSampleTime)
	})

	t.Run("first packet sent before the RTT sample", func(t *testing.T) {
		sph, packets, start := newPersistentCongestionTestHandler(t, false, nil)
		sendPCTestPacket(sph, packets, start)
		pn1 := sendPCTestPacket(sph, packets, start.Add(10*time.Millisecond))
		// the first RTT sample
		sampleTime := start.Add(10*time.Millisecond + pcTestRTT)
		_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn1)}, protocol.Encryption1RTT, sampleTime)
		require.NoError(t, err)
		require.Equal(t, sampleTime, sph.appData.firstRTTSampleTime)
		require.Empty(t, packets.Lost)
		// The packet sent at the time of the sample doesn't count either.
		// Only the packets sent after it are taken into account.
		duration := pcTestDuration(2)
		sendPCTestPacket(sph, packets, sampleTime)
		sendPCTestPacket(sph, packets, sampleTime.Add(time.Millisecond))
		lastLost := sampleTime.Add(duration + 500*time.Microsecond)
		sendPCTestPacket(sph, packets, lastLost)
		pn := sendPCTestPacket(sph, packets, lastLost.Add(100*time.Millisecond))
		_, err = sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn)}, protocol.Encryption1RTT, lastLost.Add(100*time.Millisecond+pcTestRTT))
		require.NoError(t, err)
		require.Len(t, packets.Lost, 4)
		requirePersistentCongestion(t, sph.appData.congestion, false)
	})
}

// The packets whose frames were retransmitted in PTO probe packets can establish persistent congestion
// when they are declared lost.
func TestSentPacketHandlerPersistentCongestionProbedPackets(t *testing.T) {
	sph, packets, start := newPersistentCongestionTestHandler(t, true, nil)
	pn0 := sendPCTestPacket(sph, packets, start)
	pn1 := sendPCTestPacket(sph, packets, start.Add(500*time.Millisecond))
	require.Equal(t, 2, sph.appData.space.history.NumOutstanding())

	// the PTO expires, and the frames of the first packet are retransmitted
	require.True(t, sph.QueueProbePacket(protocol.Encryption1RTT))
	require.Equal(t, []protocol.PacketNumber{pn0}, packets.Lost)
	require.Equal(t, 1, sph.appData.space.history.NumOutstanding())
	require.Equal(t, pcTestPacketSize, sph.BytesInFlight())

	pn2 := sendPCTestPacket(sph, packets, start.Add(1100*time.Millisecond))
	pn3 := sendPCTestPacket(sph, packets, start.Add(1200*time.Millisecond))
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn3)}, protocol.Encryption1RTT, start.Add(1200*time.Millisecond+pcTestRTT))
	require.NoError(t, err)
	// the frames of the probed packet are not declared lost again
	require.Equal(t, []protocol.PacketNumber{pn0, pn1, pn2}, packets.Lost)
	require.Zero(t, sph.BytesInFlight())
	require.Zero(t, sph.appData.space.history.Len())
	requirePersistentCongestion(t, sph.appData.congestion, true)
}

// An acknowledged probed packet is an acknowledged packet: it prevents persistent congestion.
func TestSentPacketHandlerPersistentCongestionProbedPacketAcked(t *testing.T) {
	sph, packets, start := newPersistentCongestionTestHandler(t, true, nil)
	pn0 := sendPCTestPacket(sph, packets, start)
	pn1 := sendPCTestPacket(sph, packets, start.Add(10*time.Millisecond))
	require.True(t, sph.QueueProbePacket(protocol.Encryption1RTT))
	require.True(t, sph.QueueProbePacket(protocol.Encryption1RTT))
	require.Equal(t, []protocol.PacketNumber{pn0, pn1}, packets.Lost)
	require.Zero(t, sph.BytesInFlight())
	require.False(t, sph.appData.space.history.HasOutstandingPackets())

	pn2 := sendPCTestPacket(sph, packets, start.Add(1100*time.Millisecond))
	pn3 := sendPCTestPacket(sph, packets, start.Add(1200*time.Millisecond))
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn1, pn3)}, protocol.Encryption1RTT, start.Add(1200*time.Millisecond+pcTestRTT))
	require.NoError(t, err)
	// the frames of the probed packet were already declared lost
	require.Equal(t, []protocol.PacketNumber{pn3}, packets.Acked)
	require.Equal(t, []protocol.PacketNumber{pn0, pn1, pn2}, packets.Lost)
	require.Zero(t, sph.appData.space.history.Len())
	requirePersistentCongestion(t, sph.appData.congestion, false)
}

// When persistent congestion is established, the congestion controller is told after the congestion event,
// and the event is logged.
func TestSentPacketHandlerPersistentCongestionCongestionController(t *testing.T) {
	var eventRecorder events.Recorder
	sph, packets, start := newPersistentCongestionTestHandler(t, true, &eventRecorder)
	cwnd := sph.appData.congestion.GetCongestionWindow()
	for i := range 4 {
		sendPCTestPacket(sph, packets, start.Add(time.Duration(i)*400*time.Millisecond))
	}
	eventRecorder.Clear()

	mockCtrl := gomock.NewController(t)
	cong := mocks.NewMockSendAlgorithmWithDebugInfos(mockCtrl)
	realCong := sph.appData.congestion
	sph.appData.congestion = cong
	var calls []string
	cong.EXPECT().MaybeExitSlowStart().AnyTimes()
	cong.EXPECT().GetCongestionWindow().Return(cwnd).AnyTimes()
	cong.EXPECT().OnPacketAcked(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	cong.EXPECT().OnPacketSent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	cong.EXPECT().OnCongestionEvent(gomock.Any(), gomock.Any(), gomock.Any()).Do(
		func(pn protocol.PacketNumber, _, _ protocol.ByteCount) {
			calls = append(calls, fmt.Sprintf("congestion event %d", pn))
			realCong.OnCongestionEvent(pn, pcTestPacketSize, 4*pcTestPacketSize)
		},
	).AnyTimes()
	cong.EXPECT().OnPersistentCongestion().Do(func() {
		calls = append(calls, "persistent congestion")
		realCong.OnPersistentCongestion()
	})
	pn := sendPCTestPacket(sph, packets, start.Add(1300*time.Millisecond))
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn)}, protocol.Encryption1RTT, start.Add(1300*time.Millisecond+pcTestRTT))
	require.NoError(t, err)
	require.Len(t, packets.Lost, 4)
	expected := make([]string, 0, 5)
	for _, lost := range packets.Lost {
		expected = append(expected, fmt.Sprintf("congestion event %d", lost))
	}
	expected = append(expected, "persistent congestion")
	require.Equal(t, expected, calls)

	requirePersistentCongestion(t, realCong, true)
	require.True(t, realCong.InRecovery())
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.CongestionStateUpdated{State: qlog.CongestionStateRecovery},
			qlog.CongestionStateUpdated{State: qlog.CongestionStateRecovery, Trigger: qlog.CongestionStateTriggerPersistentCongestion},
		},
		eventRecorder.Events(qlog.CongestionStateUpdated{}),
	)
}

// Persistent congestion is established in the Initial and Handshake packet number spaces as well.
func TestSentPacketHandlerPersistentCongestionHandshake(t *testing.T) {
	rttStats := utils.NewRTTStats()
	sph := NewSentPacketHandler(
		0,
		pcTestPacketSize,
		rttStats,
		&utils.ConnectionStats{},
		true,
		false,
		nil,
		protocol.PerspectiveServer,
		nil,
		utils.DefaultLogger,
	).(*sentPacketHandler)
	var packets packetTracker
	sendHandshakePacket := func(t monotime.Time) protocol.PacketNumber {
		pn := sph.PopPacketNumber(0, protocol.EncryptionHandshake)
		sph.SentPacket(t, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.EncryptionHandshake, protocol.ECNNon, pcTestPacketSize, false, false, 0)
		return pn
	}

	// the RTT sample is taken from an Initial packet
	start := monotime.Now()
	pn := sph.PopPacketNumber(0, protocol.EncryptionInitial)
	sph.SentPacket(start, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.EncryptionInitial, protocol.ECNNon, pcTestPacketSize, false, false, 0)
	start = start.Add(pcTestRTT)
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn)}, protocol.EncryptionInitial, start)
	require.NoError(t, err)
	sph.DropPackets(protocol.EncryptionInitial, start)

	sendHandshakePacket(start.Add(time.Millisecond))
	sendHandshakePacket(start.Add(1200 * time.Millisecond))
	pn = sendHandshakePacket(start.Add(1300 * time.Millisecond))
	_, err = sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn)}, protocol.EncryptionHandshake, start.Add(1300*time.Millisecond+pcTestRTT))
	require.NoError(t, err)
	require.Len(t, packets.Lost, 2)
	requirePersistentCongestion(t, sph.appData.congestion, true)
}

// After a migration, the RTT estimate starts again, and so does the RTT sample requirement.
func TestSentPacketHandlerPersistentCongestionMigration(t *testing.T) {
	sph, packets, start := newPersistentCongestionTestHandler(t, true, nil)
	sph.MigratedPath(start, pcTestPacketSize)
	require.Zero(t, sph.appData.firstRTTSampleTime)

	sendPCTestPacket(sph, packets, start)
	sendPCTestPacket(sph, packets, start.Add(1200*time.Millisecond))
	pn := sendPCTestPacket(sph, packets, start.Add(1300*time.Millisecond))
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn)}, protocol.Encryption1RTT, start.Add(1300*time.Millisecond+pcTestRTT))
	require.NoError(t, err)
	require.Len(t, packets.Lost, 2)
	requirePersistentCongestion(t, sph.appData.congestion, false)
}

// With IETF Multipath QUIC, persistent congestion is established per path,
// using the RTT sample and the congestion controller of the path.
func TestSentPacketHandlerMultipathPersistentCongestion(t *testing.T) {
	sph := newMultipathSentPacketHandler(protocol.PerspectiveClient, false, nil)
	sph.rttStats.SetMaxAckDelay(pcTestMaxAckDelay)
	start := monotime.Now()
	confirmHandshake(sph, start)
	sph.AddPath(1, true)
	sph.AddPath(2, true)
	tracker := newPathPacketTracker()

	// path 0 and path 1 take an RTT sample, path 2 doesn't
	for _, pathID := range []protocol.PathID{0, 1} {
		pn := sendPathPacket(sph, tracker, pathID, start, pcTestPacketSize)
		_, err := sph.ReceivedAck(pathAck(pathID, pn), protocol.Encryption1RTT, start.Add(pcTestRTT))
		require.NoError(t, err)
	}
	start = start.Add(pcTestRTT)
	require.Equal(t, start, sph.appData.firstRTTSampleTime)
	require.Equal(t, start, sph.paths[1].firstRTTSampleTime)
	require.Zero(t, sph.paths[2].firstRTTSampleTime)
	cwnd := sph.appData.congestion.GetCongestionWindow()

	// packets are lost on all paths during the same period
	last := make(map[protocol.PathID]protocol.PacketNumber)
	for _, pathID := range []protocol.PathID{0, 1, 2} {
		sendPathPacket(sph, tracker, pathID, start.Add(time.Millisecond), pcTestPacketSize)
		sendPathPacket(sph, tracker, pathID, start.Add(1200*time.Millisecond), pcTestPacketSize)
		last[pathID] = sendPathPacket(sph, tracker, pathID, start.Add(1300*time.Millisecond), pcTestPacketSize)
	}
	ackTime := start.Add(1300*time.Millisecond + pcTestRTT)

	// path 1 establishes persistent congestion
	_, err := sph.ReceivedAck(pathAck(1, last[1]), protocol.Encryption1RTT, ackTime)
	require.NoError(t, err)
	require.Len(t, tracker.Lost(1), 2)
	requirePersistentCongestion(t, sph.paths[1].congestion, true)
	require.Equal(t, cwnd, sph.appData.congestion.GetCongestionWindow())
	require.Equal(t, cwnd, sph.paths[2].congestion.GetCongestionWindow())

	// Path 2 doesn't, since it has no RTT sample.
	// The RTT sample of the other paths doesn't count.
	_, err = sph.ReceivedAck(pathAck(2, last[2]), protocol.Encryption1RTT, ackTime)
	require.NoError(t, err)
	require.Len(t, tracker.Lost(2), 2)
	requirePersistentCongestion(t, sph.paths[2].congestion, false)
	require.Equal(t, cwnd, sph.appData.congestion.GetCongestionWindow())

	// path 0 establishes persistent congestion as well
	_, err = sph.ReceivedAck(pathAck(0, last[0]), protocol.Encryption1RTT, ackTime)
	require.NoError(t, err)
	require.Len(t, tracker.Lost(0), 2)
	requirePersistentCongestion(t, sph.appData.congestion, true)

	// when the peer address of a path changes, the RTT sample requirement applies again
	sph.MigratedPathForPath(1, ackTime, pcTestPacketSize)
	require.Zero(t, sph.paths[1].firstRTTSampleTime)
	require.Equal(t, start, sph.appData.firstRTTSampleTime)
}

// The RTT estimate derived from a Retry is not an RTT sample.
func TestSentPacketHandlerPersistentCongestionRetry(t *testing.T) {
	sph := NewSentPacketHandler(
		0,
		pcTestPacketSize,
		utils.NewRTTStats(),
		&utils.ConnectionStats{},
		true,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
	).(*sentPacketHandler)
	var packets packetTracker
	start := monotime.Now()
	pn := sph.PopPacketNumber(0, protocol.EncryptionInitial)
	sph.SentPacket(start, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.EncryptionInitial, protocol.ECNNon, pcTestPacketSize, false, false, 0)
	sph.ResetForRetry(start.Add(pcTestRTT))
	require.True(t, sph.rttStats.HasMeasurement())
	require.Zero(t, sph.appData.firstRTTSampleTime)

	// the first acknowledgment provides the first RTT sample
	now := start.Add(pcTestRTT)
	pn = sph.PopPacketNumber(0, protocol.EncryptionInitial)
	sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.EncryptionInitial, protocol.ECNNon, pcTestPacketSize, false, false, 0)
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn)}, protocol.EncryptionInitial, now.Add(pcTestRTT))
	require.NoError(t, err)
	require.Equal(t, now.Add(pcTestRTT), sph.appData.firstRTTSampleTime)
}
