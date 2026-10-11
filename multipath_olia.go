package quic

import (
	"math"
	"sync"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/congestion"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/utils"
)

// OLIACongestionControl implements the OLIA (Opportunistic Linked-Increase Algorithm)
// congestion control for multipath connections. OLIA provides coupled congestion control
// across multiple paths to ensure fairness and performance.
//
// Every path of a connection has its own OLIACongestionControl, and all of them share one
// oliaSharedState (see NewOLIASharedState). The window of path r evolves as follows,
// with windows w in packets and RTTs in seconds:
//
//   - Slow start (cwnd < ssthresh): the window grows by the number of acknowledged bytes.
//     Slow start ends at the first loss, or earlier when hybrid slow start detects
//     a rising RTT (MaybeExitSlowStart).
//   - Congestion avoidance: for each acknowledged packet, w_r grows by
//     (w_r/rtt_r²) / (Σ_p w_p/rtt_p)² + α_r/w_r.
//     α_r moves window from the paths with the largest window to the presumably best paths
//     (largest ℓ_p²/rtt_p, where ℓ_p is the number of bytes acknowledged between the last two
//     losses, or since the last loss if that is larger).
//   - Loss: the window is halved, at most once per recovery epoch, as in Reno.
//   - Persistent congestion (section 7.6 of RFC 9002): the window drops to the minimum window,
//     and slow start begins again.
//
// The window never drops below 2 packets.
//
// All methods are safe for concurrent use. Each controller is protected by its own mutex.
// The shared state has a separate mutex and only stores copies of the paths' states,
// so a controller never takes another controller's mutex. The lock order is always
// controller first, then shared state.
//
// Reference: "MPTCP is not Pareto-optimal: performance issues and a possible solution"
// by R. Khalili et al., CoNEXT 2012, and draft-khalili-mptcp-congestion-control.
type OLIACongestionControl struct {
	mu sync.Mutex

	pathID protocol.PathID

	// Shared state across all OLIA instances of a connection.
	sharedState *oliaSharedState

	// Optional RTT source. When set, it takes precedence over UpdateRTT.
	rttStats *utils.RTTStats

	// Congestion window and slow start threshold, in bytes.
	congestionWindow   protocol.ByteCount
	slowStartThreshold protocol.ByteCount
	// Fraction of a byte of window change that has not been applied yet.
	cwndRemainder float64

	// ℓ_r: bytes acknowledged between the last two losses, and since the last loss.
	bytesBetweenLosses protocol.ByteCount
	bytesSinceLoss     protocol.ByteCount

	// α_r = epsilonNum / epsilonDen, from the last congestion avoidance update.
	epsilonNum int
	epsilonDen uint32

	// RTT measurements. 0 means unknown.
	rtt    time.Duration
	minRTT time.Duration

	// Recovery epoch tracking, as in quic-go's cubic sender.
	largestSentPacketNumber  protocol.PacketNumber
	largestAckedPacketNumber protocol.PacketNumber
	largestSentAtLastCutback protocol.PacketNumber

	hybridSlowStart congestion.HybridSlowStart

	maxDatagramSize protocol.ByteCount
	initialWindow   protocol.ByteCount

	// Reused buffer for snapshots of the other paths.
	others []oliaPathState
}

const (
	oliaInitialWindowPackets = 10
	oliaMinWindowPackets     = 2
	oliaMaxWindowPackets     = protocol.MaxCongestionWindowPackets
	// Do not increase the window unless less than this many packets of the window are unused.
	oliaMaxBurstPackets = 3
	// Upper bound for the datagram size. It keeps all window computations far away from int64 overflow.
	oliaMaxDatagramSize = protocol.ByteCount(1 << 16)
	// Lower bound for RTTs used in the increase computation.
	oliaMinRTT = time.Microsecond
	// Relative tolerance when looking for the best paths.
	oliaRelTolerance = 1e-9
	// Maximum number of paths tracked by one shared state.
	// When a new path is registered and the limit is reached, the path updated least recently is dropped.
	oliaMaxPaths = protocol.MaxMultipathPaths
)

var (
	defaultOLIAInitialWindow = protocol.ByteCount(oliaInitialWindowPackets * protocol.InitialPacketSize)
	defaultOLIAMaxWindow     = protocol.ByteCount(oliaMaxWindowPackets * protocol.InitialPacketSize)
	defaultOLIAMinWindow     = protocol.ByteCount(oliaMinWindowPackets * protocol.InitialPacketSize)
)

// oliaPathState is the per-path information OLIA needs about every path of a connection.
type oliaPathState struct {
	cwnd protocol.ByteCount // congestion window, in bytes
	mss  protocol.ByteCount // maximum datagram size, in bytes
	rtt  time.Duration      // smoothed RTT
	ell  protocol.ByteCount // ℓ_r, in bytes
}

// oliaSharedState contains state shared across all OLIA instances in a multipath connection.
// It holds a copy of each path's state, updated by the path's controller.
// Use one shared state per connection.
type oliaSharedState struct {
	mu    sync.RWMutex
	paths map[protocol.PathID]oliaPathEntry
	seq   uint64
}

type oliaPathEntry struct {
	// owner identifies the controller that registered the path. It is only compared, never dereferenced.
	owner *OLIACongestionControl
	state oliaPathState
	// seq is the shared state's update counter at the last update of this path.
	seq uint64
}

// NewOLIASharedState creates shared state for OLIA congestion control.
func NewOLIASharedState() *oliaSharedState {
	return &oliaSharedState{
		paths: make(map[protocol.PathID]oliaPathEntry),
	}
}

// register adds (or replaces) the path, dropping the least recently updated path if the state is full.
func (s *oliaSharedState) register(o *OLIACongestionControl, pathID protocol.PathID, st oliaPathState) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.paths == nil {
		s.paths = make(map[protocol.PathID]oliaPathEntry)
	}
	if _, ok := s.paths[pathID]; !ok && len(s.paths) >= oliaMaxPaths {
		var oldestID protocol.PathID
		oldestSeq := uint64(math.MaxUint64)
		for id, e := range s.paths {
			if e.seq < oldestSeq {
				oldestID, oldestSeq = id, e.seq
			}
		}
		delete(s.paths, oldestID)
	}
	s.seq++
	s.paths[pathID] = oliaPathEntry{owner: o, state: st, seq: s.seq}
}

// update stores the path's state, if the path is still registered by this controller.
func (s *oliaSharedState) update(o *OLIACongestionControl, pathID protocol.PathID, st oliaPathState) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.paths[pathID]
	if !ok || e.owner != o {
		return
	}
	s.seq++
	e.state = st
	e.seq = s.seq
	s.paths[pathID] = e
}

// unregister removes the path, if it is registered by this controller.
func (s *oliaSharedState) unregister(o *OLIACongestionControl, pathID protocol.PathID) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if e, ok := s.paths[pathID]; ok && e.owner == o {
		delete(s.paths, pathID)
	}
}

// snapshotOthers appends a copy of the state of all paths except the given one to buf[:0].
func (s *oliaSharedState) snapshotOthers(o *OLIACongestionControl, pathID protocol.PathID, buf []oliaPathState) []oliaPathState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	buf = buf[:0]
	for id, e := range s.paths {
		if id == pathID || e.owner == o {
			continue
		}
		buf = append(buf, e.state)
	}
	return buf
}

// NewOLIACongestionControl creates a new OLIA congestion controller for a path.
// The controller uses the RTT passed to UpdateRTT, and utils.DefaultInitialRTT until then.
// If sharedState is nil, the controller is not coupled to other paths and behaves like Reno.
func NewOLIACongestionControl(
	pathID protocol.PathID,
	sharedState *oliaSharedState,
	maxDatagramSize protocol.ByteCount,
) *OLIACongestionControl {
	return newOLIACongestionControl(pathID, sharedState, maxDatagramSize, nil)
}

// newOLIACongestionControl creates a new OLIA congestion controller for a path.
// If rttStats is not nil, the controller takes its RTT from it.
func newOLIACongestionControl(
	pathID protocol.PathID,
	sharedState *oliaSharedState,
	maxDatagramSize protocol.ByteCount,
	rttStats *utils.RTTStats,
) *OLIACongestionControl {
	if maxDatagramSize <= 0 {
		maxDatagramSize = protocol.InitialPacketSize
	}
	maxDatagramSize = min(maxDatagramSize, oliaMaxDatagramSize)
	if sharedState == nil {
		sharedState = NewOLIASharedState()
	}

	o := &OLIACongestionControl{
		pathID:                   pathID,
		sharedState:              sharedState,
		rttStats:                 rttStats,
		maxDatagramSize:          maxDatagramSize,
		initialWindow:            oliaInitialWindowPackets * maxDatagramSize,
		congestionWindow:         oliaInitialWindowPackets * maxDatagramSize,
		slowStartThreshold:       protocol.MaxByteCount,
		epsilonNum:               0,
		epsilonDen:               1,
		largestSentPacketNumber:  protocol.InvalidPacketNumber,
		largestAckedPacketNumber: protocol.InvalidPacketNumber,
		largestSentAtLastCutback: protocol.InvalidPacketNumber,
	}
	o.refreshRTTLocked()

	// Register this path with shared state.
	// o is not shared yet, so its fields can be read without holding o.mu.
	sharedState.register(o, pathID, o.pathStateLocked())

	return o
}

// CanSend returns whether a packet can be sent.
func (o *OLIACongestionControl) CanSend(bytesInFlight protocol.ByteCount) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return bytesInFlight < o.congestionWindow
}

// GetCongestionWindow returns the current congestion window.
func (o *OLIACongestionControl) GetCongestionWindow() protocol.ByteCount {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.congestionWindow
}

// OnPacketSent is called when a packet is sent.
func (o *OLIACongestionControl) OnPacketSent(
	sentTime time.Time,
	packetNumber protocol.PacketNumber,
	bytes protocol.ByteCount,
	isRetransmittable bool,
) {
	if !isRetransmittable {
		return
	}

	o.mu.Lock()
	defer o.mu.Unlock()
	o.largestSentPacketNumber = max(o.largestSentPacketNumber, packetNumber)
	o.hybridSlowStart.OnPacketSent(packetNumber)
}

// OnPacketAcked is called when a packet is acknowledged.
// bytesInFlight is the number of bytes in flight before the packet was acknowledged.
// The window only grows if the sender is (almost) limited by it.
func (o *OLIACongestionControl) OnPacketAcked(
	packetNumber protocol.PacketNumber,
	ackedBytes protocol.ByteCount,
	bytesInFlight protocol.ByteCount,
	eventTime time.Time,
) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.largestAckedPacketNumber = max(o.largestAckedPacketNumber, packetNumber)
	o.refreshRTTLocked()
	if ackedBytes > 0 {
		o.bytesSinceLoss = saturatingAddByteCount(o.bytesSinceLoss, ackedBytes)
	}
	defer o.publishLocked()

	if o.inRecoveryLocked() || ackedBytes <= 0 {
		return
	}
	if o.isCwndLimitedLocked(bytesInFlight) {
		if o.inSlowStartLocked() {
			// Exponential growth, up to the slow start threshold.
			if room := o.slowStartThreshold - o.congestionWindow; ackedBytes >= room {
				o.congestionWindow = o.slowStartThreshold
			} else {
				o.congestionWindow += ackedBytes
			}
			o.congestionWindow = min(o.congestionWindow, o.maxWindowLocked())
		} else {
			o.congestionAvoidanceLocked(ackedBytes)
		}
	}
	if o.inSlowStartLocked() {
		o.hybridSlowStart.OnPacketAcked(packetNumber)
	}
}

// congestionAvoidanceLocked applies the OLIA increase for ackedBytes acknowledged bytes.
func (o *OLIACongestionControl) congestionAvoidanceLocked(ackedBytes protocol.ByteCount) {
	o.others = o.sharedState.snapshotOthers(o, o.pathID, o.others)
	inc, epsNum, epsDen := oliaIncrease(o.pathStateLocked(), o.others)
	o.epsilonNum, o.epsilonDen = epsNum, epsDen
	o.applyWindowChangeLocked(inc * float64(ackedBytes))
	// A negative α can shrink the window. This must not restart slow start.
	o.slowStartThreshold = min(o.slowStartThreshold, o.congestionWindow)
}

// applyWindowChangeLocked changes the window by delta bytes (possibly negative or fractional),
// keeping it between the minimum and maximum window.
func (o *OLIACongestionControl) applyWindowChangeLocked(delta float64) {
	if math.IsNaN(delta) || math.IsInf(delta, 0) {
		return
	}
	o.cwndRemainder += delta
	whole := math.Trunc(o.cwndRemainder)
	if whole == 0 {
		return
	}
	o.cwndRemainder -= whole
	newWindow := float64(o.congestionWindow) + whole
	if minWindow := o.minWindowLocked(); newWindow <= float64(minWindow) {
		o.congestionWindow = minWindow
		o.cwndRemainder = 0
	} else if maxWindow := o.maxWindowLocked(); newWindow >= float64(maxWindow) {
		o.congestionWindow = maxWindow
		o.cwndRemainder = 0
	} else {
		o.congestionWindow = protocol.ByteCount(newWindow)
	}
}

// oliaIncrease computes the OLIA congestion avoidance increase of path self for each acknowledged
// byte, i.e. the window grows by inc*ackedBytes bytes. Equivalently, inc is the increase in packets
// per acknowledged packet:
//
//	inc = (w_self/rtt_self²) / (Σ_p w_p/rtt_p)² + α_self/w_self
//
// with windows w in packets. others are the other paths of the connection.
// α_self = epsNum/epsDen, computed as in draft-khalili-mptcp-congestion-control:
//
//   - max_w_paths are the paths with the largest window. As in Linux, windows are compared in whole
//     packets, so that paths whose windows differ by a fraction of a packet are treated as equal.
//   - best_paths are the paths with the largest ℓ_p/rtt_p², as in Linux:
//     the throughput of a Reno flow scales with √ℓ/rtt.
//   - collected_paths are the best paths that are not in max_w_paths.
//   - α_r = 1/(n·|collected_paths|) if r is in collected_paths,
//     α_r = -1/(n·|max_w_paths|) if r is in max_w_paths and collected_paths is not empty,
//     and α_r = 0 otherwise, where n is the number of paths.
//
// The result is finite and within [-1, 1].
func oliaIncrease(self oliaPathState, others []oliaPathState) (inc float64, epsNum int, epsDen uint32) {
	type pathValues struct {
		w        float64            // window, in packets
		wPackets protocol.ByteCount // window, in whole packets
		rtt      float64            // RTT, in seconds
		q        float64            // ℓ/rtt², to find the best paths
	}
	values := func(p oliaPathState) (pathValues, bool) {
		if p.cwnd <= 0 || p.mss <= 0 {
			return pathValues{}, false
		}
		rtt := p.rtt
		if rtt <= 0 {
			rtt = utils.DefaultInitialRTT
		}
		rttSec := max(rtt, oliaMinRTT).Seconds()
		ell := float64(max(p.ell, 0))
		return pathValues{
			w:        float64(p.cwnd) / float64(p.mss),
			wPackets: p.cwnd / p.mss,
			rtt:      rttSec,
			q:        ell / (rttSec * rttSec),
		}, true
	}

	var buf [8]pathValues
	paths := buf[:0]
	s, ok := values(self)
	if !ok {
		return 0, 0, 1
	}
	paths = append(paths, s)
	for _, p := range others {
		if v, ok := values(p); ok {
			paths = append(paths, v)
		}
	}

	// sum = rtt_self * Σ_p w_p/rtt_p. It is at least w_self > 0.
	var sum, bestQ float64
	var maxWPackets protocol.ByteCount
	for _, p := range paths {
		sum += p.w * (s.rtt / p.rtt)
		maxWPackets = max(maxWPackets, p.wPackets)
		bestQ = max(bestQ, p.q)
	}
	isBest := func(p pathValues) bool { return p.q >= bestQ*(1-oliaRelTolerance) }

	var numMaxW, numCollected int
	for _, p := range paths {
		if p.wPackets == maxWPackets {
			numMaxW++
		} else if isBest(p) {
			numCollected++
		}
	}
	selfMaxW := s.wPackets == maxWPackets
	selfCollected := !selfMaxW && isBest(s)
	n := len(paths)
	switch {
	case selfCollected:
		epsNum, epsDen = 1, uint32(n*numCollected)
	case selfMaxW && numCollected > 0:
		epsNum, epsDen = -1, uint32(n*numMaxW)
	default:
		epsNum, epsDen = 0, 1
	}

	inc = s.w/(sum*sum) + float64(epsNum)/(float64(epsDen)*s.w)
	if math.IsNaN(inc) || math.IsInf(inc, 0) {
		return 0, epsNum, epsDen
	}
	return min(max(inc, -1), 1), epsNum, epsDen
}

// OnCongestionEvent is called when congestion is detected (packet loss or ECN-CE).
// All congestion events for packets sent before the last window reduction belong to the same
// recovery epoch and are ignored.
func (o *OLIACongestionControl) OnCongestionEvent(
	packetNumber protocol.PacketNumber,
	lostBytes protocol.ByteCount,
	priorInFlight protocol.ByteCount,
) {
	o.mu.Lock()
	defer o.mu.Unlock()

	// TCP NewReno (RFC 6582): all losses of packets sent before the last cutback are one loss event.
	if packetNumber <= o.largestSentAtLastCutback {
		return
	}
	o.refreshRTTLocked()
	o.recordLossLocked()

	// Multiplicative decrease. This also ends slow start.
	o.congestionWindow = max(o.congestionWindow/2, o.minWindowLocked())
	o.slowStartThreshold = o.congestionWindow
	o.cwndRemainder = 0
	o.largestSentAtLastCutback = max(o.largestSentPacketNumber, packetNumber)
	o.publishLocked()
}

// OnPersistentCongestion is called when persistent congestion is established (section 7.6 of RFC 9002).
// The congestion window is reduced to the minimum window, and slow start begins again.
// The slow start threshold and the recovery period of the preceding congestion event are kept,
// so that losses of packets sent before that event don't reduce the window again.
func (o *OLIACongestionControl) OnPersistentCongestion() {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.hybridSlowStart.Restart()
	o.congestionWindow = o.minWindowLocked()
	o.cwndRemainder = 0
	o.publishLocked()
}

// recordLossLocked updates ℓ_r for a new loss event.
func (o *OLIACongestionControl) recordLossLocked() {
	// Like Linux, only start a new inter-loss interval if bytes were acknowledged since the last loss.
	if o.bytesSinceLoss > 0 {
		o.bytesBetweenLosses = o.bytesSinceLoss
		o.bytesSinceLoss = 0
	}
}

// MaybeExitSlowStart exits slow start if hybrid slow start detects an RTT increase.
// It is called when an ACK provides a new RTT sample.
func (o *OLIACongestionControl) MaybeExitSlowStart() {
	o.mu.Lock()
	defer o.mu.Unlock()

	if !o.inSlowStartLocked() {
		return
	}
	latestRTT, minRTT := o.rtt, o.minRTT
	if o.rttStats != nil {
		latestRTT, minRTT = o.rttStats.LatestRTT(), o.rttStats.MinRTT()
	}
	if latestRTT <= 0 || minRTT <= 0 {
		return
	}
	if o.hybridSlowStart.ShouldExitSlowStart(latestRTT, minRTT, o.congestionWindow/o.maxDatagramSize) {
		o.slowStartThreshold = o.congestionWindow
	}
}

// InSlowStart returns whether the connection is in slow start.
func (o *OLIACongestionControl) InSlowStart() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.inSlowStartLocked()
}

func (o *OLIACongestionControl) inSlowStartLocked() bool {
	return o.congestionWindow < o.slowStartThreshold
}

// InRecovery returns whether the connection is in recovery, i.e. whether no packet sent after
// the last window reduction has been acknowledged yet.
func (o *OLIACongestionControl) InRecovery() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.inRecoveryLocked()
}

func (o *OLIACongestionControl) inRecoveryLocked() bool {
	return o.largestSentAtLastCutback != protocol.InvalidPacketNumber &&
		(o.largestAckedPacketNumber == protocol.InvalidPacketNumber || o.largestAckedPacketNumber <= o.largestSentAtLastCutback)
}

// isCwndLimitedLocked returns whether the sender is (almost) limited by the congestion window.
func (o *OLIACongestionControl) isCwndLimitedLocked(bytesInFlight protocol.ByteCount) bool {
	if bytesInFlight >= o.congestionWindow {
		return true
	}
	availableBytes := o.congestionWindow - bytesInFlight
	slowStartLimited := o.inSlowStartLocked() && bytesInFlight > o.congestionWindow/2
	return slowStartLimited || availableBytes <= oliaMaxBurstPackets*o.maxDatagramSize
}

// OnPacketLost is called when a packet is declared lost.
func (o *OLIACongestionControl) OnPacketLost(
	packetNumber protocol.PacketNumber,
	lostBytes protocol.ByteCount,
	priorInFlight protocol.ByteCount,
) {
	// Delegate to OnCongestionEvent
	o.OnCongestionEvent(packetNumber, lostBytes, priorInFlight)
}

// OnRetransmissionTimeout is called on an retransmission timeout.
func (o *OLIACongestionControl) OnRetransmissionTimeout(packetsRetransmitted bool) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.largestSentAtLastCutback = protocol.InvalidPacketNumber
	if !packetsRetransmitted {
		return
	}
	o.hybridSlowStart.Restart()
	o.recordLossLocked()
	minWindow := o.minWindowLocked()
	o.slowStartThreshold = max(o.congestionWindow/2, minWindow)
	o.congestionWindow = minWindow
	o.cwndRemainder = 0
	o.publishLocked()
}

// SmoothedBytesBetweenLosses returns ℓ_r: the number of bytes acknowledged between the last two
// losses, or since the last loss if that is larger.
func (o *OLIACongestionControl) SmoothedBytesBetweenLosses() protocol.ByteCount {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.ellLocked()
}

func (o *OLIACongestionControl) ellLocked() protocol.ByteCount {
	return max(o.bytesBetweenLosses, o.bytesSinceLoss)
}

// UpdateRTT updates the RTT estimate for this path.
// Controllers created by NewOLIACongestionControlFactory read the RTT from the path's RTT statistics
// on every ACK and loss, which overrides values set here.
func (o *OLIACongestionControl) UpdateRTT(rtt, minRTT time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if rtt > 0 {
		o.rtt = rtt
	}
	if minRTT > 0 && (o.minRTT == 0 || minRTT < o.minRTT) {
		o.minRTT = minRTT
	}
	o.publishLocked()
}

// refreshRTTLocked reads the RTT from the RTT statistics, if set.
// It uses the smoothed RTT, or the latest RTT if there is no smoothed RTT.
func (o *OLIACongestionControl) refreshRTTLocked() {
	if o.rttStats == nil {
		return
	}
	rtt := o.rttStats.SmoothedRTT()
	if rtt <= 0 {
		rtt = o.rttStats.LatestRTT()
	}
	if rtt > 0 {
		o.rtt = rtt
	}
	if minRTT := o.rttStats.MinRTT(); minRTT > 0 {
		o.minRTT = minRTT
	}
}

// SetMaxDatagramSize updates the maximum datagram size.
func (o *OLIACongestionControl) SetMaxDatagramSize(size protocol.ByteCount) {
	if size <= 0 {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()

	cwndIsMinCwnd := o.congestionWindow == o.minWindowLocked()
	o.maxDatagramSize = min(size, oliaMaxDatagramSize)
	if cwndIsMinCwnd {
		o.congestionWindow = o.minWindowLocked()
	}
	o.congestionWindow = min(max(o.congestionWindow, o.minWindowLocked()), o.maxWindowLocked())
	o.publishLocked()
}

// takeOverState continues with the state of another congestion controller,
// e.g. the controller that path 0 used before IETF Multipath QUIC became active.
// A reduced congestion window and the recovery period are kept (section 7.3.2 of RFC 9002).
func (o *OLIACongestionControl) takeOverState(s congestion.State) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.congestionWindow = min(max(s.CongestionWindow, o.minWindowLocked()), o.maxWindowLocked())
	o.slowStartThreshold = s.SlowStartThreshold
	o.cwndRemainder = 0
	o.largestSentPacketNumber = s.LargestSentPacketNumber
	o.largestAckedPacketNumber = s.LargestAckedPacketNumber
	o.largestSentAtLastCutback = s.LargestSentAtLastCutback
	o.publishLocked()
}

// Reset resets the congestion control state. The RTT estimate is kept.
func (o *OLIACongestionControl) Reset() {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.congestionWindow = min(max(o.initialWindow, o.minWindowLocked()), o.maxWindowLocked())
	o.slowStartThreshold = protocol.MaxByteCount
	o.cwndRemainder = 0
	o.bytesBetweenLosses = 0
	o.bytesSinceLoss = 0
	o.epsilonNum = 0
	o.epsilonDen = 1
	o.largestSentPacketNumber = protocol.InvalidPacketNumber
	o.largestAckedPacketNumber = protocol.InvalidPacketNumber
	o.largestSentAtLastCutback = protocol.InvalidPacketNumber
	o.hybridSlowStart.Restart()
	o.publishLocked()
}

// Unregister removes this path from shared state.
// It should be called when the path is closed. It is safe to call it multiple times.
func (o *OLIACongestionControl) Unregister() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.sharedState.unregister(o, o.pathID)
}

// GetStatistics returns congestion control statistics.
func (o *OLIACongestionControl) GetStatistics() OLIAStatistics {
	o.mu.Lock()
	defer o.mu.Unlock()

	return OLIAStatistics{
		PathID:             o.pathID,
		CongestionWindow:   o.congestionWindow,
		SlowStartThreshold: o.slowStartThreshold,
		BytesInFlight:      0, // Would need to be tracked separately
		InSlowStart:        o.inSlowStartLocked(),
		InRecovery:         o.inRecoveryLocked(),
		EpsilonNum:         o.epsilonNum,
		EpsilonDen:         o.epsilonDen,
		RTT:                o.rtt,
	}
}

// pathStateLocked returns the path's state as seen by the other paths.
func (o *OLIACongestionControl) pathStateLocked() oliaPathState {
	rtt := o.rtt
	if rtt <= 0 {
		rtt = utils.DefaultInitialRTT
	}
	return oliaPathState{
		cwnd: o.congestionWindow,
		mss:  o.maxDatagramSize,
		rtt:  rtt,
		ell:  o.ellLocked(),
	}
}

// publishLocked copies the path's state to the shared state.
func (o *OLIACongestionControl) publishLocked() {
	o.sharedState.update(o, o.pathID, o.pathStateLocked())
}

func (o *OLIACongestionControl) minWindowLocked() protocol.ByteCount {
	return oliaMinWindowPackets * o.maxDatagramSize
}

func (o *OLIACongestionControl) maxWindowLocked() protocol.ByteCount {
	return oliaMaxWindowPackets * o.maxDatagramSize
}

// OLIAStatistics contains statistics for OLIA congestion control.
type OLIAStatistics struct {
	PathID             protocol.PathID
	CongestionWindow   protocol.ByteCount
	SlowStartThreshold protocol.ByteCount
	BytesInFlight      protocol.ByteCount
	InSlowStart        bool
	InRecovery         bool
	// α_r = EpsilonNum / EpsilonDen, from the last congestion avoidance update.
	EpsilonNum int
	EpsilonDen uint32
	RTT        time.Duration
}

func saturatingAddByteCount(a, b protocol.ByteCount) protocol.ByteCount {
	if b > protocol.MaxByteCount-a {
		return protocol.MaxByteCount
	}
	return a + b
}
