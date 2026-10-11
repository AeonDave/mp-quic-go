package quic

import (
	"math"
	"sync"
	"testing"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/congestion"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/utils"
	"github.com/AeonDave/mp-quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

const oliaTestMSS = protocol.ByteCount(protocol.InitialPacketSize)

func (s *oliaSharedState) numPaths() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.paths)
}

func (s *oliaSharedState) hasPath(pathID protocol.PathID) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.paths[pathID]
	return ok
}

// setOLIAWindow puts the controller into congestion avoidance with the given window.
func setOLIAWindow(o *OLIACongestionControl, cwnd protocol.ByteCount) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.congestionWindow = cwnd
	o.slowStartThreshold = cwnd
	o.cwndRemainder = 0
	o.publishLocked()
}

// newOLIAWithRTT creates a controller through the factory, with RTT stats that measured rtt.
func newOLIAWithRTT(
	t *testing.T,
	factory func(protocol.PathID, *utils.RTTStats, protocol.ByteCount) congestion.SendAlgorithmWithDebugInfos,
	pathID protocol.PathID,
	rtt time.Duration,
) *OLIACongestionControl {
	t.Helper()
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(rtt, 0)
	cc := factory(pathID, rttStats, oliaTestMSS)
	adapter, ok := cc.(*oliaCongestionAdapter)
	require.True(t, ok)
	return adapter.OLIACongestionControl
}

// oliaSimPath is a path in a round-based simulation: every RTT, the path sends a full window
// and then receives the ACKs (or loss notifications) for it.
type oliaSimPath struct {
	cc        *OLIACongestionControl
	rtt       time.Duration
	lossEvery int // every lossEvery-th packet sent on the path is lost; 0: no losses

	sent      int
	next      time.Duration
	rounds    int
	windowSum float64 // sum of the window at the start of each round, in bytes
}

func (p *oliaSimPath) avgWindow() float64 { return p.windowSum / float64(p.rounds) }

type oliaSim struct {
	pn protocol.PacketNumber // one packet number space for all paths
}

func (s *oliaSim) round(p *oliaSimPath) {
	cwnd := p.cc.GetCongestionWindow()
	n := max(int(cwnd/oliaTestMSS), 1)
	first := s.pn
	for range n {
		p.cc.OnPacketSent(time.Now(), s.pn, oliaTestMSS, true)
		s.pn++
	}
	for i := range n {
		pn := first + protocol.PacketNumber(i)
		p.sent++
		// The sender keeps the window full, so the bytes in flight are the window.
		if p.lossEvery > 0 && p.sent%p.lossEvery == 0 {
			p.cc.OnCongestionEvent(pn, oliaTestMSS, p.cc.GetCongestionWindow())
		} else {
			p.cc.OnPacketAcked(pn, oliaTestMSS, p.cc.GetCongestionWindow(), time.Now())
		}
	}
	p.rounds++
	p.windowSum += float64(cwnd)
}

func (s *oliaSim) run(paths []*oliaSimPath, duration time.Duration) {
	for {
		var p *oliaSimPath
		for _, q := range paths {
			if p == nil || q.next < p.next {
				p = q
			}
		}
		if p.next >= duration {
			return
		}
		s.round(p)
		p.next += p.rtt
	}
}

func TestOLIA_NewInstance(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)

	require.NotNil(t, olia)
	require.Equal(t, protocol.PathID(1), olia.pathID)
	require.Equal(t, defaultOLIAInitialWindow, olia.GetCongestionWindow())
	require.Equal(t, protocol.MaxByteCount, olia.slowStartThreshold)
	require.True(t, olia.InSlowStart())
	require.False(t, olia.InRecovery())

	// Should be registered in shared state
	require.True(t, sharedState.hasPath(1))
}

func TestOLIA_NilSharedState(t *testing.T) {
	olia := NewOLIACongestionControl(1, nil, protocol.InitialPacketSize)
	setOLIAWindow(olia, 10*oliaTestMSS)
	// Uncoupled: Reno increase of 1/w packets per acknowledged packet.
	olia.OnPacketAcked(1, oliaTestMSS, olia.GetCongestionWindow(), time.Now())
	require.Equal(t, 10*oliaTestMSS+oliaTestMSS/10, olia.GetCongestionWindow())
	olia.Unregister()
}

func TestOLIA_CanSend(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)

	// Initially, should be able to send
	require.True(t, olia.CanSend(0))

	// Can send up to congestion window
	require.True(t, olia.CanSend(olia.GetCongestionWindow()-1))

	// Cannot send if bytes in flight >= cwnd
	require.False(t, olia.CanSend(olia.GetCongestionWindow()))
	require.False(t, olia.CanSend(olia.GetCongestionWindow()+1000))
}

func TestOLIA_SlowStart(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)

	initialCwnd := olia.GetCongestionWindow()
	require.True(t, olia.InSlowStart())

	// ACK a packet in slow start - cwnd should increase by acked bytes
	ackedBytes := protocol.ByteCount(1200)
	olia.OnPacketAcked(1, ackedBytes, initialCwnd, time.Now())

	newCwnd := olia.GetCongestionWindow()
	require.Equal(t, initialCwnd+ackedBytes, newCwnd)
	require.True(t, olia.InSlowStart())

	// ACK more packets
	for i := range 20 {
		olia.OnPacketAcked(protocol.PacketNumber(i+2), ackedBytes, olia.GetCongestionWindow(), time.Now())
	}

	// Should still be increasing
	finalCwnd := olia.GetCongestionWindow()
	require.Equal(t, newCwnd+20*ackedBytes, finalCwnd)
}

func TestOLIA_SlowStartDoublesPerRound(t *testing.T) {
	olia := NewOLIACongestionControl(1, NewOLIASharedState(), oliaTestMSS)
	sim := &oliaSim{}
	p := &oliaSimPath{cc: olia, rtt: 50 * time.Millisecond}
	for range 3 {
		before := olia.GetCongestionWindow()
		sim.round(p)
		require.Equal(t, 2*before, olia.GetCongestionWindow())
	}
	require.True(t, olia.InSlowStart())
}

func TestOLIA_SlowStartStopsAtThreshold(t *testing.T) {
	olia := NewOLIACongestionControl(1, NewOLIASharedState(), oliaTestMSS)
	olia.mu.Lock()
	olia.slowStartThreshold = olia.congestionWindow + oliaTestMSS/2
	olia.mu.Unlock()

	olia.OnPacketAcked(1, oliaTestMSS, olia.GetCongestionWindow(), time.Now())
	require.Equal(t, olia.slowStartThreshold, olia.GetCongestionWindow())
	require.False(t, olia.InSlowStart())
}

func TestOLIA_NoGrowthWhenApplicationLimited(t *testing.T) {
	olia := NewOLIACongestionControl(1, NewOLIASharedState(), oliaTestMSS)
	cwnd := olia.GetCongestionWindow()
	for i := range 20 {
		olia.OnPacketAcked(protocol.PacketNumber(i), oliaTestMSS, 2*oliaTestMSS, time.Now())
	}
	require.Equal(t, cwnd, olia.GetCongestionWindow())
	// ℓ still counts the acknowledged bytes.
	require.Equal(t, 20*oliaTestMSS, olia.SmoothedBytesBetweenLosses())
}

func TestOLIA_ExitSlowStart(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)

	// Simulate packet loss to exit slow start
	olia.OnCongestionEvent(10, 1200, olia.GetCongestionWindow())

	require.False(t, olia.InSlowStart())
	require.Equal(t, olia.congestionWindow, olia.slowStartThreshold)
}

func TestOLIA_MaybeExitSlowStartHybridSlowStart(t *testing.T) {
	newController := func(rttStats *utils.RTTStats) *OLIACongestionControl {
		olia := newOLIACongestionControl(1, NewOLIASharedState(), oliaTestMSS, rttStats)
		olia.mu.Lock()
		olia.congestionWindow = 20 * oliaTestMSS // hybrid slow start only exits above 16 packets
		olia.mu.Unlock()
		return olia
	}

	// Stable RTT: stay in slow start.
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(10*time.Millisecond, 0)
	olia := newController(rttStats)
	for range 20 {
		olia.MaybeExitSlowStart()
	}
	require.True(t, olia.InSlowStart())

	// The RTT increases a lot: exit slow start.
	rttStats.UpdateRTT(50*time.Millisecond, 0)
	olia = newController(rttStats)
	for range 8 {
		olia.MaybeExitSlowStart()
	}
	require.False(t, olia.InSlowStart())
	require.Equal(t, 20*oliaTestMSS, olia.slowStartThreshold)
	require.Equal(t, 20*oliaTestMSS, olia.GetCongestionWindow())

	// Without RTT information, MaybeExitSlowStart doesn't do anything.
	olia = NewOLIACongestionControl(1, NewOLIASharedState(), oliaTestMSS)
	olia.MaybeExitSlowStart()
	require.True(t, olia.InSlowStart())
}

func TestOLIA_CongestionEvent(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)

	// Increase cwnd first
	for i := range 10 {
		olia.OnPacketSent(time.Now(), protocol.PacketNumber(i), 1200, true)
		olia.OnPacketAcked(protocol.PacketNumber(i), 1200, olia.GetCongestionWindow(), time.Now())
	}

	cwndBeforeLoss := olia.GetCongestionWindow()
	require.Greater(t, cwndBeforeLoss, defaultOLIAInitialWindow)

	// Simulate congestion event
	olia.OnPacketSent(time.Now(), 20, 1200, true)
	olia.OnCongestionEvent(20, 1200, cwndBeforeLoss)

	// Cwnd should be halved (multiplicative decrease)
	require.Equal(t, cwndBeforeLoss/2, olia.GetCongestionWindow())
	require.True(t, olia.InRecovery())

	// Should not go below minimum
	setOLIAWindow(olia, defaultOLIAMinWindow+1000)
	olia.OnPacketSent(time.Now(), 21, 1200, true)
	olia.OnCongestionEvent(21, 1200, olia.GetCongestionWindow())
	require.Equal(t, defaultOLIAMinWindow, olia.GetCongestionWindow())
}

func TestOLIA_OneCutbackPerRecoveryEpoch(t *testing.T) {
	olia := NewOLIACongestionControl(1, NewOLIASharedState(), oliaTestMSS)
	setOLIAWindow(olia, 40*oliaTestMSS)

	// One flight of 20 packets.
	for pn := protocol.PacketNumber(1); pn <= 20; pn++ {
		olia.OnPacketSent(time.Now(), pn, oliaTestMSS, true)
	}
	require.False(t, olia.InRecovery())

	// 5 packets of this flight are lost: a single halving.
	for _, pn := range []protocol.PacketNumber{3, 5, 7, 9, 11} {
		olia.OnCongestionEvent(pn, oliaTestMSS, 20*oliaTestMSS)
	}
	require.Equal(t, 20*oliaTestMSS, olia.GetCongestionWindow())
	require.Equal(t, 20*oliaTestMSS, olia.slowStartThreshold)
	require.True(t, olia.InRecovery())

	// ECN-CE for a packet of the same flight: still the same epoch.
	olia.OnCongestionEvent(20, 0, 20*oliaTestMSS)
	require.Equal(t, 20*oliaTestMSS, olia.GetCongestionWindow())

	// ACKs for packets of the flight don't grow the window during recovery.
	olia.OnPacketAcked(12, oliaTestMSS, olia.GetCongestionWindow(), time.Now())
	require.True(t, olia.InRecovery())
	require.Equal(t, 20*oliaTestMSS, olia.GetCongestionWindow())

	// A packet sent after the cutback is acknowledged: recovery ends.
	olia.OnPacketSent(time.Now(), 21, oliaTestMSS, true)
	olia.OnPacketSent(time.Now(), 22, oliaTestMSS, true)
	olia.OnPacketAcked(21, oliaTestMSS, olia.GetCongestionWindow(), time.Now())
	require.False(t, olia.InRecovery())
	require.Greater(t, olia.GetCongestionWindow(), 20*oliaTestMSS)

	// A loss of a packet sent after the cutback starts a new epoch.
	cwnd := olia.GetCongestionWindow()
	olia.OnCongestionEvent(22, oliaTestMSS, cwnd)
	require.Equal(t, cwnd/2, olia.GetCongestionWindow())
	require.True(t, olia.InRecovery())
}

func TestOLIA_RetransmissionTimeout(t *testing.T) {
	olia := NewOLIACongestionControl(1, NewOLIASharedState(), oliaTestMSS)
	setOLIAWindow(olia, 40*oliaTestMSS)
	olia.OnPacketSent(time.Now(), 1, oliaTestMSS, true)
	olia.OnCongestionEvent(1, oliaTestMSS, 40*oliaTestMSS)
	require.True(t, olia.InRecovery())

	// An RTO without retransmissions only resets the recovery epoch.
	olia.OnRetransmissionTimeout(false)
	require.False(t, olia.InRecovery())
	require.Equal(t, 20*oliaTestMSS, olia.GetCongestionWindow())

	olia.OnRetransmissionTimeout(true)
	require.Equal(t, defaultOLIAMinWindow, olia.GetCongestionWindow())
	require.Equal(t, 10*oliaTestMSS, olia.slowStartThreshold)
	require.True(t, olia.InSlowStart())
	require.False(t, olia.InRecovery())
}

// When persistent congestion is established (section 7.6 of RFC 9002), the window drops to the minimum window,
// and slow start begins again. The other paths see the new window.
func TestOLIA_PersistentCongestion(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, oliaTestMSS)
	other := NewOLIACongestionControl(2, sharedState, oliaTestMSS)
	setOLIAWindow(olia, 40*oliaTestMSS)
	for pn := range protocol.PacketNumber(3) {
		olia.OnPacketSent(time.Now(), pn, oliaTestMSS, true)
	}
	olia.OnCongestionEvent(0, oliaTestMSS, 3*oliaTestMSS)
	require.Equal(t, 20*oliaTestMSS, olia.GetCongestionWindow())
	require.True(t, olia.InRecovery())

	olia.OnPersistentCongestion()
	require.Equal(t, 2*oliaTestMSS, olia.GetCongestionWindow())
	require.Equal(t, 20*oliaTestMSS, olia.slowStartThreshold)
	require.True(t, olia.InSlowStart())
	require.True(t, olia.InRecovery())
	others := sharedState.snapshotOthers(other, 2, nil)
	require.Len(t, others, 1)
	require.Equal(t, 2*oliaTestMSS, others[0].cwnd)

	// losses of packets sent before the congestion event don't reduce the window again
	olia.OnCongestionEvent(1, oliaTestMSS, 2*oliaTestMSS)
	require.Equal(t, 2*oliaTestMSS, olia.GetCongestionWindow())

	// once a packet sent afterwards is acknowledged, the window grows in slow start
	olia.OnPacketSent(time.Now(), 3, oliaTestMSS, true)
	olia.OnPacketAcked(3, oliaTestMSS, 2*oliaTestMSS, time.Now())
	require.False(t, olia.InRecovery())
	require.Equal(t, 3*oliaTestMSS, olia.GetCongestionWindow())
}

func TestOLIA_SmoothedBytesBetweenLosses(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)

	// Initially zero
	require.Equal(t, protocol.ByteCount(0), olia.SmoothedBytesBetweenLosses())

	// ACK some bytes
	olia.OnPacketAcked(1, 1000, 0, time.Now())
	olia.OnPacketAcked(2, 1000, 0, time.Now())
	require.Equal(t, protocol.ByteCount(2000), olia.SmoothedBytesBetweenLosses())

	// Loss event: the 2000 bytes are now the bytes between losses.
	olia.OnCongestionEvent(3, 1200, 5000)
	require.Equal(t, protocol.ByteCount(2000), olia.SmoothedBytesBetweenLosses())

	// ACK more bytes: the bytes since the last loss are larger.
	olia.OnPacketAcked(4, 2000, 0, time.Now())
	require.Equal(t, protocol.ByteCount(2000), olia.SmoothedBytesBetweenLosses())
	olia.OnPacketAcked(5, 2000, 0, time.Now())
	require.Equal(t, protocol.ByteCount(4000), olia.SmoothedBytesBetweenLosses())

	// A second loss: 4000 bytes between the last two losses.
	olia.OnCongestionEvent(6, 1200, 5000)
	require.Equal(t, protocol.ByteCount(4000), olia.SmoothedBytesBetweenLosses())
	// Another loss without any ACK in between keeps the interval.
	olia.OnCongestionEvent(7, 1200, 5000)
	require.Equal(t, protocol.ByteCount(4000), olia.SmoothedBytesBetweenLosses())
}

func TestOLIA_IncreaseSinglePathIsReno(t *testing.T) {
	for _, w := range []protocol.ByteCount{2, 10, 333, 10000} {
		inc, num, den := oliaIncrease(oliaPathState{cwnd: w * oliaTestMSS, mss: oliaTestMSS, rtt: 30 * time.Millisecond}, nil)
		require.InDelta(t, 1/float64(w), inc, 1e-12)
		require.Equal(t, 0, num)
		require.Equal(t, uint32(1), den)
	}
}

func TestOLIA_IncreaseFormula(t *testing.T) {
	rtt := 50 * time.Millisecond

	t.Run("equal paths", func(t *testing.T) {
		self := oliaPathState{cwnd: 40 * oliaTestMSS, mss: oliaTestMSS, rtt: rtt, ell: 100000}
		inc, num, _ := oliaIncrease(self, []oliaPathState{self})
		// (w/rtt²)/(2w/rtt)² = 1/(4w), and α = 0: both paths have the largest window.
		require.InDelta(t, 1.0/160, inc, 1e-12)
		require.Zero(t, num)
	})

	t.Run("different RTTs", func(t *testing.T) {
		fast := oliaPathState{cwnd: 20 * oliaTestMSS, mss: oliaTestMSS, rtt: 20 * time.Millisecond}
		slow := oliaPathState{cwnd: 20 * oliaTestMSS, mss: oliaTestMSS, rtt: 80 * time.Millisecond}
		sum := 20/0.02 + 20/0.08
		inc, _, _ := oliaIncrease(fast, []oliaPathState{slow})
		require.InEpsilon(t, (20/(0.02*0.02))/(sum*sum), inc, 1e-9)
		inc, _, _ = oliaIncrease(slow, []oliaPathState{fast})
		require.InEpsilon(t, (20/(0.08*0.08))/(sum*sum), inc, 1e-9)
	})

	t.Run("window moves from the max-window path to the best path", func(t *testing.T) {
		big := oliaPathState{cwnd: 20 * oliaTestMSS, mss: oliaTestMSS, rtt: rtt, ell: 10000}
		best := oliaPathState{cwnd: 10 * oliaTestMSS, mss: oliaTestMSS, rtt: rtt, ell: 100000}
		// big is in max_w_paths, best is in collected_paths. n = 2.
		inc, num, den := oliaIncrease(big, []oliaPathState{best})
		require.Equal(t, -1, num)
		require.Equal(t, uint32(2), den)
		require.InDelta(t, 20.0/900-0.5/20, inc, 1e-12)
		require.Negative(t, inc)

		inc, num, den = oliaIncrease(best, []oliaPathState{big})
		require.Equal(t, 1, num)
		require.Equal(t, uint32(2), den)
		require.InDelta(t, 10.0/900+0.5/10, inc, 1e-12)
	})

	t.Run("no losses yet", func(t *testing.T) {
		// ℓ = 0 everywhere: all paths are best paths, the smaller paths are collected.
		a := oliaPathState{cwnd: 30 * oliaTestMSS, mss: oliaTestMSS, rtt: rtt}
		b := oliaPathState{cwnd: 10 * oliaTestMSS, mss: oliaTestMSS, rtt: rtt}
		c := oliaPathState{cwnd: 10 * oliaTestMSS, mss: oliaTestMSS, rtt: rtt}
		_, num, den := oliaIncrease(b, []oliaPathState{a, c})
		require.Equal(t, 1, num)
		require.Equal(t, uint32(3*2), den)
		_, num, den = oliaIncrease(a, []oliaPathState{b, c})
		require.Equal(t, -1, num)
		require.Equal(t, uint32(3*1), den)
	})
}

func TestOLIA_CongestionAvoidanceGrowthWithRealisticRTTs(t *testing.T) {
	shared := NewOLIASharedState()
	factory := NewOLIACongestionControlFactory(shared)
	fast := newOLIAWithRTT(t, factory, 1, 20*time.Millisecond)
	slow := newOLIAWithRTT(t, factory, 2, 80*time.Millisecond)
	require.Equal(t, 20*time.Millisecond, fast.GetStatistics().RTT)
	require.Equal(t, 80*time.Millisecond, slow.GetStatistics().RTT)

	sim := &oliaSim{}
	paths := []*oliaSimPath{
		{cc: fast, rtt: 20 * time.Millisecond},
		{cc: slow, rtt: 80 * time.Millisecond},
	}
	// A loss on each path ends slow start.
	for _, p := range paths {
		p.cc.OnPacketSent(time.Now(), sim.pn, oliaTestMSS, true)
		p.cc.OnCongestionEvent(sim.pn, oliaTestMSS, p.cc.GetCongestionWindow())
		sim.pn++
		require.False(t, p.cc.InSlowStart())
		require.Equal(t, 5*oliaTestMSS, p.cc.GetCongestionWindow())
	}

	sim.run(paths, 2*time.Second)
	fastGrowth := fast.GetCongestionWindow() - 5*oliaTestMSS
	slowGrowth := slow.GetCongestionWindow() - 5*oliaTestMSS
	t.Logf("20ms path: %d rounds, cwnd %d (+%.2f packets)", paths[0].rounds, fast.GetCongestionWindow(), float64(fastGrowth)/float64(oliaTestMSS))
	t.Logf("80ms path: %d rounds, cwnd %d (+%.2f packets)", paths[1].rounds, slow.GetCongestionWindow(), float64(slowGrowth)/float64(oliaTestMSS))

	require.Equal(t, 100, paths[0].rounds)
	require.Equal(t, 25, paths[1].rounds)
	// Both paths grow in congestion avoidance...
	require.Positive(t, fastGrowth)
	require.Positive(t, slowGrowth)
	// ... but by at most 1 packet per RTT (Reno), not by 1 packet per ACK.
	require.LessOrEqual(t, fastGrowth, protocol.ByteCount(paths[0].rounds)*oliaTestMSS)
	require.LessOrEqual(t, slowGrowth, protocol.ByteCount(paths[1].rounds)*oliaTestMSS)
	// The fast path takes most of the increase.
	require.Greater(t, fastGrowth, protocol.ByteCount(paths[0].rounds)*oliaTestMSS/2)
	require.Greater(t, fastGrowth, slowGrowth)
	require.False(t, fast.InSlowStart())
	require.False(t, slow.InSlowStart())
}

func TestOLIA_TrafficMovesToLessCongestedPath(t *testing.T) {
	shared := NewOLIASharedState()
	factory := NewOLIACongestionControlFactory(shared)
	fast := newOLIAWithRTT(t, factory, 1, 20*time.Millisecond)
	slow := newOLIAWithRTT(t, factory, 2, 80*time.Millisecond)

	sim := &oliaSim{}
	paths := []*oliaSimPath{
		{cc: fast, rtt: 20 * time.Millisecond, lossEvery: 20}, // lossy (5%)
		{cc: slow, rtt: 80 * time.Millisecond},                // no losses
	}
	for _, p := range paths {
		p.cc.OnPacketSent(time.Now(), sim.pn, oliaTestMSS, true)
		p.cc.OnCongestionEvent(sim.pn, oliaTestMSS, p.cc.GetCongestionWindow())
		sim.pn++
	}
	sim.run(paths, 30*time.Second)
	t.Logf("lossy 20ms path: cwnd %.1f packets, lossless 80ms path: cwnd %.1f packets",
		float64(fast.GetCongestionWindow())/float64(oliaTestMSS), float64(slow.GetCongestionWindow())/float64(oliaTestMSS))

	// The lossless path becomes the best path: it collects window, and the lossy path gives up window.
	require.Greater(t, slow.GetCongestionWindow(), 50*oliaTestMSS)
	require.Less(t, fast.GetCongestionWindow(), 10*oliaTestMSS)
}

func TestOLIA_CouplingTwoEqualPathsVsReno(t *testing.T) {
	const w = 40
	rtt := 50 * time.Millisecond

	// Increase over one RTT, with both paths in congestion avoidance at w packets.
	shared := NewOLIASharedState()
	p1 := NewOLIACongestionControl(1, shared, oliaTestMSS)
	p2 := NewOLIACongestionControl(2, shared, oliaTestMSS)
	p1.UpdateRTT(rtt, rtt)
	p2.UpdateRTT(rtt, rtt)
	setOLIAWindow(p1, w*oliaTestMSS)
	setOLIAWindow(p2, w*oliaTestMSS)
	for i := range w {
		p1.OnPacketAcked(protocol.PacketNumber(2*i), oliaTestMSS, p1.GetCongestionWindow(), time.Now())
		p2.OnPacketAcked(protocol.PacketNumber(2*i+1), oliaTestMSS, p2.GetCongestionWindow(), time.Now())
	}
	coupledIncrease := float64(p1.GetCongestionWindow()+p2.GetCongestionWindow()-2*w*oliaTestMSS) / float64(oliaTestMSS)

	// A single Reno flow with the same total window, over one RTT.
	reno := NewOLIACongestionControl(3, NewOLIASharedState(), oliaTestMSS)
	reno.UpdateRTT(rtt, rtt)
	setOLIAWindow(reno, 2*w*oliaTestMSS)
	for i := range 2 * w {
		reno.OnPacketAcked(protocol.PacketNumber(i), oliaTestMSS, reno.GetCongestionWindow(), time.Now())
	}
	renoIncrease := float64(reno.GetCongestionWindow()-2*w*oliaTestMSS) / float64(oliaTestMSS)
	t.Logf("increase per RTT: OLIA (2 paths) %.3f packets, Reno %.3f packets", coupledIncrease, renoIncrease)

	require.InDelta(t, 1, renoIncrease, 0.05)
	// Each path increases by 1/(4w) per ACK, i.e. 1/4 packet per RTT: the aggregate grows half
	// as fast as a single Reno flow, and halving one path removes a quarter of the aggregate.
	// In equilibrium, the aggregate gets the same window as a single Reno flow.
	require.InDelta(t, 0.5, coupledIncrease/renoIncrease, 0.1)
}

func TestOLIA_CouplingEquilibriumMatchesReno(t *testing.T) {
	const lossEvery = 400
	rtt := 50 * time.Millisecond
	duration := 1500 * rtt

	shared := NewOLIASharedState()
	p1 := NewOLIACongestionControl(1, shared, oliaTestMSS)
	p2 := NewOLIACongestionControl(2, shared, oliaTestMSS)
	p1.UpdateRTT(rtt, rtt)
	p2.UpdateRTT(rtt, rtt)
	oliaPaths := []*oliaSimPath{
		{cc: p1, rtt: rtt, lossEvery: lossEvery},
		{cc: p2, rtt: rtt, lossEvery: lossEvery},
	}
	(&oliaSim{}).run(oliaPaths, duration)

	reno := NewOLIACongestionControl(1, NewOLIASharedState(), oliaTestMSS)
	reno.UpdateRTT(rtt, rtt)
	renoPath := &oliaSimPath{cc: reno, rtt: rtt, lossEvery: lossEvery}
	(&oliaSim{}).run([]*oliaSimPath{renoPath}, duration)

	aggregate := (oliaPaths[0].avgWindow() + oliaPaths[1].avgWindow()) / float64(oliaTestMSS)
	single := renoPath.avgWindow() / float64(oliaTestMSS)
	t.Logf("average window: OLIA path 1 %.1f, path 2 %.1f, aggregate %.1f packets; Reno %.1f packets",
		oliaPaths[0].avgWindow()/float64(oliaTestMSS), oliaPaths[1].avgWindow()/float64(oliaTestMSS), aggregate, single)
	require.InDelta(t, 1, aggregate/single, 0.3)
}

func TestOLIA_NegativeAlphaShrinksWindow(t *testing.T) {
	shared := NewOLIASharedState()
	big := NewOLIACongestionControl(1, shared, oliaTestMSS)
	best := NewOLIACongestionControl(2, shared, oliaTestMSS)
	big.UpdateRTT(10*time.Second, 10*time.Second)
	best.UpdateRTT(100*time.Microsecond, 100*time.Microsecond)
	setOLIAWindow(big, 100*oliaTestMSS)
	setOLIAWindow(best, 2*oliaTestMSS)
	// best has a much larger ℓ, so it is a collected path, and big gets a negative α.
	best.mu.Lock()
	best.bytesSinceLoss = 1 << 30
	best.publishLocked()
	best.mu.Unlock()

	big.OnPacketAcked(2, oliaTestMSS, big.GetCongestionWindow(), time.Now())
	require.Equal(t, -1, big.GetStatistics().EpsilonNum)
	prev := big.GetCongestionWindow()
	require.Less(t, prev, 100*oliaTestMSS)
	for i := range 100000 {
		big.OnPacketAcked(protocol.PacketNumber(i+3), oliaTestMSS, big.GetCongestionWindow(), time.Now())
		cwnd := big.GetCongestionWindow()
		require.LessOrEqual(t, cwnd, prev)
		require.GreaterOrEqual(t, cwnd, defaultOLIAMinWindow)
		prev = cwnd
	}
	// The window shrinks until it's in the same whole packet as the other path's window.
	require.Less(t, big.GetCongestionWindow(), 3*oliaTestMSS)
	require.Zero(t, big.GetStatistics().EpsilonNum)
}

func TestOLIA_WindowNeverBelowTwoPackets(t *testing.T) {
	shared := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, shared, oliaTestMSS)
	olia.UpdateRTT(10*time.Second, 10*time.Second)
	setOLIAWindow(olia, 100*oliaTestMSS)
	// A (bogus) path with a window below one packet and a huge ℓ makes α negative forever.
	shared.register(nil, 2, oliaPathState{cwnd: 1, mss: oliaTestMSS, rtt: 100 * time.Microsecond, ell: protocol.MaxByteCount})

	for i := range 100000 {
		olia.OnPacketAcked(protocol.PacketNumber(i), oliaTestMSS, olia.GetCongestionWindow(), time.Now())
		require.GreaterOrEqual(t, olia.GetCongestionWindow(), defaultOLIAMinWindow)
	}
	require.Equal(t, defaultOLIAMinWindow, olia.GetCongestionWindow())
	require.Equal(t, -1, olia.GetStatistics().EpsilonNum)

	// Same with a huge negative change at once.
	setOLIAWindow(olia, 100*oliaTestMSS)
	olia.mu.Lock()
	olia.applyWindowChangeLocked(-1e30)
	olia.mu.Unlock()
	require.Equal(t, defaultOLIAMinWindow, olia.GetCongestionWindow())
}

func TestOLIA_ExtremeValues(t *testing.T) {
	cwnds := []protocol.ByteCount{0, 1, 2 * oliaTestMSS, 1e8, protocol.MaxByteCount}
	mssValues := []protocol.ByteCount{0, 1, oliaTestMSS, oliaMaxDatagramSize}
	rtts := []time.Duration{0, time.Nanosecond, 100 * time.Microsecond, 10 * time.Second, time.Hour}
	ells := []protocol.ByteCount{0, 1, 1e8, protocol.MaxByteCount}

	var states []oliaPathState
	for _, cwnd := range cwnds {
		for _, mss := range mssValues {
			for _, rtt := range rtts {
				for _, ell := range ells {
					states = append(states, oliaPathState{cwnd: cwnd, mss: mss, rtt: rtt, ell: ell})
				}
			}
		}
	}
	check := func(self oliaPathState, others []oliaPathState) {
		inc, num, den := oliaIncrease(self, others)
		require.False(t, math.IsNaN(inc) || math.IsInf(inc, 0), "self %+v, others %+v", self, others)
		require.GreaterOrEqual(t, inc, -1.0)
		require.LessOrEqual(t, inc, 1.0)
		require.Contains(t, []int{-1, 0, 1}, num)
		require.NotZero(t, den)
	}
	for i, self := range states {
		check(self, nil)
		// 7 other paths with varied extreme values.
		others := make([]oliaPathState, 7)
		for j := range others {
			others[j] = states[(i*7+j*131)%len(states)]
		}
		check(self, others)
	}

	// Full controllers: 8 paths, windows of up to 10^8 bytes, RTTs from 100µs to 10s,
	// datagram sizes of 1 byte and 64 KB.
	shared := NewOLIASharedState()
	pathRTTs := []time.Duration{100 * time.Microsecond, time.Millisecond, 20 * time.Millisecond, 80 * time.Millisecond, 300 * time.Millisecond, time.Second, 5 * time.Second, 10 * time.Second}
	var ccs []*OLIACongestionControl
	for i, rtt := range pathRTTs {
		rttStats := utils.NewRTTStats()
		rttStats.UpdateRTT(rtt, 0)
		mss := oliaMaxDatagramSize
		if i%3 == 0 {
			mss = 1
		}
		cc := newOLIACongestionControl(protocol.PathID(i), shared, mss, rttStats)
		setOLIAWindow(cc, min(1e8, oliaMaxWindowPackets*mss))
		ccs = append(ccs, cc)
	}
	pn := protocol.PacketNumber(0)
	for round := range 200 {
		for i, cc := range ccs {
			mss := cc.maxDatagramSize
			cc.OnPacketSent(time.Now(), pn, mss, true)
			if round%50 == 49 && i%2 == 0 {
				cc.OnCongestionEvent(pn, mss, 1e8)
			} else {
				cc.OnPacketAcked(pn, protocol.ByteCount(1+round*1e6), protocol.MaxByteCount, time.Now())
			}
			pn++
			stats := cc.GetStatistics()
			require.GreaterOrEqual(t, stats.CongestionWindow, oliaMinWindowPackets*mss)
			require.LessOrEqual(t, stats.CongestionWindow, oliaMaxWindowPackets*mss)
			require.NotZero(t, stats.EpsilonDen)
		}
	}

	// Huge ACKs and a huge datagram size don't overflow.
	cc := NewOLIACongestionControl(100, shared, protocol.MaxByteCount)
	cc.OnPacketAcked(1, protocol.MaxByteCount, protocol.MaxByteCount, time.Now())
	require.Equal(t, oliaMaxWindowPackets*oliaMaxDatagramSize, cc.GetCongestionWindow())
	cc.OnPacketAcked(2, protocol.MaxByteCount, protocol.MaxByteCount, time.Now())
	require.Equal(t, protocol.MaxByteCount, cc.SmoothedBytesBetweenLosses())
	cc.OnCongestionEvent(3, protocol.MaxByteCount, protocol.MaxByteCount)
	cc.OnPacketAcked(4, protocol.MaxByteCount, protocol.MaxByteCount, time.Now())
	require.Positive(t, cc.GetCongestionWindow())
}

func TestOLIA_FactoryUsesRTTStats(t *testing.T) {
	shared := NewOLIASharedState()
	factory := NewOLIACongestionControlFactory(shared)

	// Before the first measurement, the RTT stats report the initial RTT.
	rttStats := utils.NewRTTStats()
	olia := factory(1, rttStats, oliaTestMSS).(*oliaCongestionAdapter).OLIACongestionControl
	require.Equal(t, utils.DefaultInitialRTT, olia.GetStatistics().RTT)

	rttStats.UpdateRTT(30*time.Millisecond, 0)
	olia.OnPacketAcked(1, oliaTestMSS, olia.GetCongestionWindow(), time.Now())
	require.Equal(t, 30*time.Millisecond, olia.GetStatistics().RTT)
	rttStats.UpdateRTT(60*time.Millisecond, 0)
	olia.OnPacketAcked(2, oliaTestMSS, olia.GetCongestionWindow(), time.Now())
	require.Equal(t, rttStats.SmoothedRTT(), olia.GetStatistics().RTT)

	// RTT stats without any RTT: the initial RTT is used for the coupling.
	empty := factory(2, &utils.RTTStats{}, oliaTestMSS).(*oliaCongestionAdapter).OLIACongestionControl
	require.Zero(t, empty.GetStatistics().RTT)
	shared.mu.RLock()
	require.Equal(t, utils.DefaultInitialRTT, shared.paths[2].state.rtt)
	shared.mu.RUnlock()

	// A nil shared state still works.
	single := NewOLIACongestionControlFactory(nil)(1, rttStats, 0)
	require.Equal(t, defaultOLIAInitialWindow, single.GetCongestionWindow())
}

func TestOLIA_Adapter(t *testing.T) {
	cc := NewOLIACongestionControlFactory(NewOLIASharedState())(1, utils.NewRTTStats(), oliaTestMSS)
	cwnd := cc.GetCongestionWindow()
	require.True(t, cc.CanSend(cwnd-1))
	require.False(t, cc.CanSend(cwnd))
	require.True(t, cc.HasPacingBudget(monotime.Now()))
	require.Zero(t, cc.TimeUntilSend(cwnd))
	require.Zero(t, cc.TimeUntilSend(0))
	require.True(t, cc.InSlowStart())
	require.False(t, cc.InRecovery())

	cc.OnPacketSent(monotime.Now(), cwnd, 1, oliaTestMSS, true)
	cc.OnPacketAcked(1, oliaTestMSS, cwnd, monotime.Now())
	require.Equal(t, cwnd+oliaTestMSS, cc.GetCongestionWindow())
	cc.MaybeExitSlowStart()

	cc.OnPacketSent(monotime.Now(), cwnd, 2, oliaTestMSS, true)
	cc.OnCongestionEvent(2, oliaTestMSS, cwnd)
	require.Equal(t, (cwnd+oliaTestMSS)/2, cc.GetCongestionWindow())
	require.True(t, cc.InRecovery())
	require.False(t, cc.InSlowStart())

	cc.SetMaxDatagramSize(1400)
	cc.OnRetransmissionTimeout(true)
	require.Equal(t, protocol.ByteCount(2*1400), cc.GetCongestionWindow())
}

func TestOLIA_UpdateRTT(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)

	require.Equal(t, time.Duration(0), olia.rtt)
	require.Equal(t, time.Duration(0), olia.minRTT)

	// Update RTT
	olia.UpdateRTT(50*time.Millisecond, 45*time.Millisecond)
	require.Equal(t, 50*time.Millisecond, olia.rtt)
	require.Equal(t, 45*time.Millisecond, olia.minRTT)

	// Update with new min
	olia.UpdateRTT(55*time.Millisecond, 40*time.Millisecond)
	require.Equal(t, 55*time.Millisecond, olia.rtt)
	require.Equal(t, 40*time.Millisecond, olia.minRTT)

	// Update with higher min (should not change minRTT)
	olia.UpdateRTT(60*time.Millisecond, 50*time.Millisecond)
	require.Equal(t, 60*time.Millisecond, olia.rtt)
	require.Equal(t, 40*time.Millisecond, olia.minRTT)

	// Invalid values are ignored
	olia.UpdateRTT(0, 0)
	require.Equal(t, 60*time.Millisecond, olia.rtt)
	require.Equal(t, 40*time.Millisecond, olia.minRTT)
}

func TestOLIA_SetMaxDatagramSize(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)

	require.Equal(t, olia.maxDatagramSize, protocol.ByteCount(protocol.InitialPacketSize))

	newSize := protocol.ByteCount(1400)
	olia.SetMaxDatagramSize(newSize)
	require.Equal(t, olia.maxDatagramSize, newSize)

	// A window at the minimum follows the datagram size.
	olia.OnRetransmissionTimeout(true)
	require.Equal(t, 2*newSize, olia.GetCongestionWindow())
	olia.SetMaxDatagramSize(1500)
	require.Equal(t, protocol.ByteCount(2*1500), olia.GetCongestionWindow())

	olia.SetMaxDatagramSize(0)
	require.Equal(t, protocol.ByteCount(1500), olia.maxDatagramSize)
}

func TestOLIA_Reset(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)

	// Modify state
	olia.UpdateRTT(50*time.Millisecond, 50*time.Millisecond)
	for i := range 20 {
		olia.OnPacketAcked(protocol.PacketNumber(i), 1200, olia.GetCongestionWindow(), time.Now())
	}
	olia.OnCongestionEvent(21, 1200, olia.GetCongestionWindow())
	olia.OnPacketAcked(20, 1200, olia.GetCongestionWindow(), time.Now())
	require.True(t, olia.InRecovery())

	// Reset
	olia.Reset()

	// Should be back to initial state
	require.Equal(t, defaultOLIAInitialWindow, olia.GetCongestionWindow())
	require.Equal(t, protocol.MaxByteCount, olia.slowStartThreshold)
	require.Equal(t, protocol.ByteCount(0), olia.bytesBetweenLosses)
	require.Equal(t, protocol.ByteCount(0), olia.bytesSinceLoss)
	require.True(t, olia.InSlowStart())
	require.False(t, olia.InRecovery())
	require.Equal(t, 50*time.Millisecond, olia.GetStatistics().RTT)
}

// takeOverState continues with the congestion window, the slow start threshold and the recovery period
// of another controller.
func TestOLIA_TakeOverState(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(0, sharedState, protocol.InitialPacketSize)
	olia.takeOverState(congestion.State{
		CongestionWindow:         20 * oliaTestMSS,
		SlowStartThreshold:       20 * oliaTestMSS,
		LargestSentPacketNumber:  30,
		LargestAckedPacketNumber: 25,
		LargestSentAtLastCutback: 30,
	})
	require.Equal(t, 20*oliaTestMSS, olia.GetCongestionWindow())
	require.False(t, olia.InSlowStart())
	require.True(t, olia.InRecovery())
	require.Equal(t, 20*oliaTestMSS, sharedState.paths[0].state.cwnd)

	// the loss of a packet sent before the window was reduced belongs to the same loss event
	olia.OnCongestionEvent(28, oliaTestMSS, 10*oliaTestMSS)
	require.Equal(t, 20*oliaTestMSS, olia.GetCongestionWindow())
	// acknowledgments don't increase the window during the recovery period
	olia.OnPacketAcked(29, oliaTestMSS, olia.GetCongestionWindow(), time.Now())
	require.Equal(t, 20*oliaTestMSS, olia.GetCongestionWindow())
	// the recovery period ends when a packet sent after the reduction is acknowledged
	olia.OnPacketSent(time.Now(), 31, oliaTestMSS, true)
	olia.OnPacketAcked(31, oliaTestMSS, olia.GetCongestionWindow(), time.Now())
	require.False(t, olia.InRecovery())
	require.False(t, olia.InSlowStart())

	// the window is kept within the limits of the controller
	olia.takeOverState(congestion.State{CongestionWindow: oliaTestMSS, SlowStartThreshold: protocol.MaxByteCount})
	require.Equal(t, defaultOLIAMinWindow, olia.GetCongestionWindow())
	require.True(t, olia.InSlowStart())
}

// With OLIA, path 0 gets an OLIA controller when IETF Multipath QUIC becomes active (see activateMultipath).
// It continues with the state of the controller used until then: the response to a loss detected before is kept
// (section 7.3.2 of RFC 9002).
func TestOLIA_Path0KeepsCongestionStateWhenMultipathBecomesActive(t *testing.T) {
	sph := ackhandler.NewSentPacketHandler(0, protocol.InitialPacketSize, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false, nil, protocol.PerspectiveClient, nil, utils.DefaultLogger)
	now := monotime.Now()
	sph.DropPackets(protocol.EncryptionInitial, now)
	sph.DropPackets(protocol.EncryptionHandshake, now)
	var pns []protocol.PacketNumber
	for range 6 {
		pn := sph.PopPacketNumber(0, protocol.Encryption1RTT)
		sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []ackhandler.Frame{{Frame: &wire.PingFrame{}, Handler: emptyHandler{}}}, protocol.Encryption1RTT, protocol.ECNNon, oliaTestMSS, false, false, 0)
		pns = append(pns, pn)
	}
	// the first 3 packets are lost
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRangesFor(pns[3:])}, protocol.Encryption1RTT, now.Add(20*time.Millisecond))
	require.NoError(t, err)

	sharedState := NewOLIASharedState()
	sph.SetCongestionControlFactory(NewOLIACongestionControlFactory(sharedState))
	sph.EnableMultipath(nil)
	olia := sharedState.paths[0].owner
	require.NotNil(t, olia)
	cwnd, _, ok := sph.PathCongestionState(0)
	require.True(t, ok)
	require.Equal(t, olia.GetCongestionWindow(), cwnd)
	require.NotEqual(t, defaultOLIAInitialWindow, cwnd)
	// slow start ended, and the recovery period continues
	require.False(t, olia.InSlowStart())
	require.True(t, olia.InRecovery())
	require.Equal(t, pns[5], olia.largestSentAtLastCutback)
}

func TestOLIA_Unregister(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)
	other := NewOLIACongestionControl(2, sharedState, protocol.InitialPacketSize)
	require.Equal(t, 2, sharedState.numPaths())

	// Unregister
	olia.Unregister()
	require.False(t, sharedState.hasPath(1))
	require.True(t, sharedState.hasPath(2))
	require.Equal(t, 1, sharedState.numPaths())

	// Unregistering twice is fine, and events after unregistering don't re-register the path.
	olia.Unregister()
	olia.OnPacketAcked(1, 1200, olia.GetCongestionWindow(), time.Now())
	olia.OnCongestionEvent(2, 1200, olia.GetCongestionWindow())
	olia.UpdateRTT(time.Second, time.Second)
	require.False(t, sharedState.hasPath(1))

	// The remaining path is no longer coupled to the removed one: it behaves like Reno.
	setOLIAWindow(other, 10*oliaTestMSS)
	other.OnPacketAcked(10, oliaTestMSS, other.GetCongestionWindow(), time.Now())
	require.Equal(t, 10*oliaTestMSS+oliaTestMSS/10, other.GetCongestionWindow())

	// A controller replaced by a new controller for the same path ID can't remove the new one.
	replaced := NewOLIACongestionControl(3, sharedState, protocol.InitialPacketSize)
	replacement := NewOLIACongestionControl(3, sharedState, protocol.InitialPacketSize)
	setOLIAWindow(replaced, 100*oliaTestMSS)
	replaced.Unregister()
	require.True(t, sharedState.hasPath(3))
	sharedState.mu.RLock()
	require.Same(t, replacement, sharedState.paths[3].owner)
	require.Equal(t, defaultOLIAInitialWindow, sharedState.paths[3].state.cwnd)
	sharedState.mu.RUnlock()
	replacement.Unregister()
	other.Unregister()
	require.Zero(t, sharedState.numPaths())
}

func TestOLIA_SharedStateIsBounded(t *testing.T) {
	sharedState := NewOLIASharedState()
	active := NewOLIACongestionControl(0, sharedState, protocol.InitialPacketSize)
	for i := 1; i <= 10*oliaMaxPaths; i++ {
		NewOLIACongestionControl(protocol.PathID(i), sharedState, protocol.InitialPacketSize)
		// The active path keeps updating its state.
		active.OnPacketAcked(protocol.PacketNumber(i), 1200, 0, time.Now())
		require.LessOrEqual(t, sharedState.numPaths(), oliaMaxPaths)
	}
	require.Equal(t, oliaMaxPaths, sharedState.numPaths())
	// The least recently updated paths were dropped, not the active one.
	require.True(t, sharedState.hasPath(0))
	require.True(t, sharedState.hasPath(10*oliaMaxPaths))
	require.False(t, sharedState.hasPath(1))
}

func TestOLIA_GetStatistics(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)

	olia.UpdateRTT(50*time.Millisecond, 50*time.Millisecond)
	olia.OnPacketAcked(1, 1200, 0, time.Now())

	stats := olia.GetStatistics()
	require.Equal(t, protocol.PathID(1), stats.PathID)
	require.Equal(t, olia.GetCongestionWindow(), stats.CongestionWindow)
	require.Equal(t, olia.slowStartThreshold, stats.SlowStartThreshold)
	require.True(t, stats.InSlowStart)
	require.False(t, stats.InRecovery)
	require.Equal(t, 50*time.Millisecond, stats.RTT)
	require.Equal(t, uint32(1), stats.EpsilonDen)
}

func TestOLIA_ZeroMaxDatagramSize(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, 0)

	// Should default to InitialPacketSize
	require.Equal(t, olia.maxDatagramSize, protocol.ByteCount(protocol.InitialPacketSize))
}

func TestOLIA_ConcurrentAccess(t *testing.T) {
	sharedState := NewOLIASharedState()
	path1 := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)
	path2 := NewOLIACongestionControl(2, sharedState, protocol.InitialPacketSize)

	path1.UpdateRTT(50*time.Millisecond, 50*time.Millisecond)
	path2.UpdateRTT(100*time.Millisecond, 100*time.Millisecond)
	setOLIAWindow(path1, 20*oliaTestMSS)
	setOLIAWindow(path2, 20*oliaTestMSS)

	exercise := func(p *OLIACongestionControl, offset int) {
		for i := range 500 {
			pn := protocol.PacketNumber(offset + i)
			p.OnPacketSent(time.Now(), pn, 1200, true)
			if i%50 == 49 {
				p.OnCongestionEvent(pn, 1200, p.GetCongestionWindow())
			} else {
				p.OnPacketAcked(pn, 1200, p.GetCongestionWindow(), time.Now())
			}
			_ = p.CanSend(5000)
			_ = p.InSlowStart()
			_ = p.InRecovery()
			p.MaybeExitSlowStart()
		}
	}

	var wg sync.WaitGroup
	wg.Add(4)
	go func() { defer wg.Done(); exercise(path1, 0) }()
	go func() { defer wg.Done(); exercise(path2, 10000) }()
	// Concurrent statistics retrieval
	go func() {
		defer wg.Done()
		for range 500 {
			_ = path1.GetStatistics()
			_ = path2.GetStatistics()
			_ = path1.SmoothedBytesBetweenLosses()
		}
	}()
	// Paths come and go concurrently.
	go func() {
		defer wg.Done()
		for i := range 100 {
			p := NewOLIACongestionControl(protocol.PathID(3+i%3), sharedState, protocol.InitialPacketSize)
			p.OnPacketAcked(1, 1200, p.GetCongestionWindow(), time.Now())
			p.Unregister()
		}
	}()
	wg.Wait()

	for _, p := range []*OLIACongestionControl{path1, path2} {
		require.GreaterOrEqual(t, p.GetCongestionWindow(), defaultOLIAMinWindow)
		require.LessOrEqual(t, p.GetCongestionWindow(), defaultOLIAMaxWindow)
	}
	require.Equal(t, 2, sharedState.numPaths())
}

func TestOLIA_MaxCongestionWindow(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)
	olia.mu.Lock()
	olia.congestionWindow = defaultOLIAMaxWindow - 100*oliaTestMSS
	olia.mu.Unlock()

	// ACK many packets to try to exceed max window
	for i := range 1000 {
		olia.OnPacketAcked(protocol.PacketNumber(i), 1200, olia.GetCongestionWindow(), time.Now())
	}

	// Should not exceed max window
	require.Equal(t, defaultOLIAMaxWindow, olia.GetCongestionWindow())

	// Same in congestion avoidance
	setOLIAWindow(olia, defaultOLIAMaxWindow-oliaTestMSS/2)
	for i := range 100000 {
		olia.OnPacketAcked(protocol.PacketNumber(1000+i), oliaTestMSS, olia.GetCongestionWindow(), time.Now())
	}
	require.Equal(t, defaultOLIAMaxWindow, olia.GetCongestionWindow())
}

func TestOLIA_MinCongestionWindow(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)

	// Force window to be close to minimum
	setOLIAWindow(olia, defaultOLIAMinWindow+100)

	// Multiple loss events, each in a new recovery epoch
	for i := range 10 {
		olia.OnPacketSent(time.Now(), protocol.PacketNumber(i), 1200, true)
		olia.OnCongestionEvent(protocol.PacketNumber(i), 1200, olia.GetCongestionWindow())
	}

	// Should not go below minimum
	require.Equal(t, defaultOLIAMinWindow, olia.GetCongestionWindow())
}

func BenchmarkOLIA_OnPacketAcked(b *testing.B) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)
	olia.UpdateRTT(50*time.Millisecond, 50*time.Millisecond)
	setOLIAWindow(olia, 100*oliaTestMSS)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		olia.OnPacketAcked(protocol.PacketNumber(i), 1200, 100*oliaTestMSS, time.Now())
	}
}

func BenchmarkOLIA_MultiPath_OnPacketAcked(b *testing.B) {
	sharedState := NewOLIASharedState()
	path1 := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)
	path2 := NewOLIACongestionControl(2, sharedState, protocol.InitialPacketSize)
	path3 := NewOLIACongestionControl(3, sharedState, protocol.InitialPacketSize)

	path1.UpdateRTT(50*time.Millisecond, 50*time.Millisecond)
	path2.UpdateRTT(75*time.Millisecond, 75*time.Millisecond)
	path3.UpdateRTT(100*time.Millisecond, 100*time.Millisecond)
	paths := []*OLIACongestionControl{path1, path2, path3}
	for _, p := range paths {
		setOLIAWindow(p, 100*oliaTestMSS)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := paths[i%3]
		p.OnPacketAcked(protocol.PacketNumber(i), 1200, p.GetCongestionWindow(), time.Now())
	}
}

func BenchmarkOLIA_CanSend(b *testing.B) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = olia.CanSend(5000)
	}
}
