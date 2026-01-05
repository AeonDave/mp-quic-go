package quic

import (
	"sync"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
)

// OLIACongestionControl implements the OLIA (Opportunistic Linked-Increase Algorithm)
// congestion control for multipath connections. OLIA provides coupled congestion control
// across multiple paths to ensure fairness and performance.
//
// Reference: "MPTCP is not Pareto-optimal: performance issues and a possible solution"
// by R. Khalili et al., CoNEXT 2012
type OLIACongestionControl struct {
	pathID protocol.PathID

	// Shared state across all OLIA instances
	sharedState *oliaSharedState

	// Path-specific state
	mu sync.Mutex

	// Bytes acknowledged in current measurement period
	ackedBytes protocol.ByteCount

	// Bytes acknowledged between last two losses
	loss1 protocol.ByteCount
	loss2 protocol.ByteCount
	loss3 protocol.ByteCount

	// OLIA parameters
	epsilonNum int
	epsilonDen uint32
	sndCwndCnt int

	// Congestion window in bytes
	congestionWindow protocol.ByteCount

	// Slow start threshold
	slowStartThreshold protocol.ByteCount

	// RTT measurements
	rtt       time.Duration
	minRTT    time.Duration
	updateRTT bool

	// Packet tracking
	lastPacketNumber protocol.PacketNumber

	// Configuration
	maxDatagramSize     protocol.ByteCount
	initialWindow       protocol.ByteCount
	minCongestionWindow protocol.ByteCount
	maxCongestionWindow protocol.ByteCount
}

// oliaSharedState contains state shared across all OLIA instances in a multipath connection.
type oliaSharedState struct {
	mu       sync.RWMutex
	pathOLIA map[protocol.PathID]*OLIACongestionControl
}

const (
	oliaScale = 10
)

var (
	defaultOLIAInitialWindow = protocol.ByteCount(10 * protocol.InitialPacketSize)
	defaultOLIAMaxWindow     = protocol.ByteCount(1000 * protocol.InitialPacketSize)
	defaultOLIAMinWindow     = protocol.ByteCount(2 * protocol.InitialPacketSize)
)

// NewOLIASharedState creates shared state for OLIA congestion control.
func NewOLIASharedState() *oliaSharedState {
	return &oliaSharedState{
		pathOLIA: make(map[protocol.PathID]*OLIACongestionControl),
	}
}

// NewOLIACongestionControl creates a new OLIA congestion controller for a path.
func NewOLIACongestionControl(
	pathID protocol.PathID,
	sharedState *oliaSharedState,
	maxDatagramSize protocol.ByteCount,
) *OLIACongestionControl {
	if maxDatagramSize == 0 {
		maxDatagramSize = protocol.InitialPacketSize
	}

	o := &OLIACongestionControl{
		pathID:              pathID,
		sharedState:         sharedState,
		maxDatagramSize:     maxDatagramSize,
		initialWindow:       defaultOLIAInitialWindow,
		minCongestionWindow: defaultOLIAMinWindow,
		maxCongestionWindow: defaultOLIAMaxWindow,
		congestionWindow:    defaultOLIAInitialWindow,
		slowStartThreshold:  defaultOLIAMaxWindow,
		loss1:               0,
		loss2:               0,
		loss3:               0,
		epsilonNum:          0,
		epsilonDen:          1,
		sndCwndCnt:          0,
	}

	// Register this path with shared state
	sharedState.mu.Lock()
	sharedState.pathOLIA[pathID] = o
	sharedState.mu.Unlock()

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
	o.lastPacketNumber = packetNumber
}

// OnPacketAcked is called when a packet is acknowledged.
func (o *OLIACongestionControl) OnPacketAcked(
	packetNumber protocol.PacketNumber,
	ackedBytes protocol.ByteCount,
	bytesInFlight protocol.ByteCount,
	eventTime time.Time,
) {
	o.mu.Lock()
	defer o.mu.Unlock()

	// Update bytes acked since last loss
	o.loss3 += ackedBytes
	o.ackedBytes += ackedBytes

	if o.InSlowStart() {
		// Slow start: increase cwnd by acked bytes
		o.congestionWindow += ackedBytes
		if o.congestionWindow > o.maxCongestionWindow {
			o.congestionWindow = o.maxCongestionWindow
		}
	} else {
		// Congestion avoidance: use OLIA algorithm
		o.updateCongestionWindow(ackedBytes)
	}
}

// updateCongestionWindow updates the congestion window using OLIA algorithm.
func (o *OLIACongestionControl) updateCongestionWindow(ackedBytes protocol.ByteCount) {
	// Calculate OLIA epsilon parameter
	o.calculateEpsilon()

	// Get the best rate among all paths
	rate := o.getBestRate()
	if rate == 0 {
		rate = 1 // Avoid division by zero
	}

	// Calculate cwnd scaled
	cwndScaled := uint64(o.congestionWindow) / uint64(o.maxDatagramSize)

	// Calculate increment denominator
	incDen := uint64(o.epsilonDen) * cwndScaled * uint64(rate)
	if incDen == 0 {
		incDen = 1
	}

	// Calculate increment based on epsilon
	var increment int
	if o.epsilonNum == -1 {
		// Negative epsilon case
		if uint64(o.epsilonDen)*cwndScaled*cwndScaled < uint64(rate) {
			incNum := uint64(rate) - uint64(o.epsilonDen)*cwndScaled*cwndScaled
			increment = -int(oliaScale64(incNum, oliaScale) / incDen)
		} else {
			incNum := uint64(o.epsilonDen)*cwndScaled*cwndScaled - uint64(rate)
			increment = int(oliaScale64(incNum, oliaScale) / incDen)
		}
	} else {
		// Positive epsilon case
		incNum := uint64(o.epsilonNum)*uint64(rate) + uint64(o.epsilonDen)*cwndScaled*cwndScaled
		increment = int(oliaScale64(incNum, oliaScale) / incDen)
	}

	o.sndCwndCnt += increment

	// Update congestion window based on counter
	scaledThreshold := (1 << oliaScale) - 1
	if o.sndCwndCnt >= scaledThreshold {
		o.congestionWindow += o.maxDatagramSize
		if o.congestionWindow > o.maxCongestionWindow {
			o.congestionWindow = o.maxCongestionWindow
		}
		o.sndCwndCnt = 0
	} else if o.sndCwndCnt <= -scaledThreshold {
		if o.congestionWindow > o.minCongestionWindow+o.maxDatagramSize {
			o.congestionWindow -= o.maxDatagramSize
		}
		o.sndCwndCnt = 0
	}
}

// calculateEpsilon calculates the OLIA epsilon parameter for this path.
func (o *OLIACongestionControl) calculateEpsilon() {
	o.sharedState.mu.RLock()
	defer o.sharedState.mu.RUnlock()

	// Find maximum cwnd and best performing path
	var maxCwnd protocol.ByteCount
	var bestRTT time.Duration
	var bestBytes protocol.ByteCount

	for pathID, other := range o.sharedState.pathOLIA {
		var cwnd protocol.ByteCount
		var rtt time.Duration
		var bytes protocol.ByteCount

		if pathID == o.pathID {
			// Self - already have lock, read directly
			cwnd = o.congestionWindow
			rtt = o.rtt
			bytes = o.loss2 - o.loss1
			if o.loss3 > o.loss2 && o.loss3-o.loss2 > bytes {
				bytes = o.loss3 - o.loss2
			}
		} else {
			other.mu.Lock()
			cwnd = other.congestionWindow
			rtt = other.rtt
			bytes = other.loss2 - other.loss1
			if other.loss3 > other.loss2 && other.loss3-other.loss2 > bytes {
				bytes = other.loss3 - other.loss2
			}
			other.mu.Unlock()
		}

		if cwnd > maxCwnd {
			maxCwnd = cwnd
		}

		if rtt > 0 {
			tmpRTT := rtt * rtt
			if bestRTT == 0 || int64(bytes)*int64(bestRTT) < int64(bestBytes)*int64(tmpRTT) {
				bestRTT = tmpRTT
				bestBytes = bytes
			}
		}
	}

	// Count paths in set M (max cwnd) and BNotM (best but not max)
	var M, BNotM uint8
	for pathID, other := range o.sharedState.pathOLIA {
		var cwnd protocol.ByteCount
		var rtt time.Duration
		var bytes protocol.ByteCount

		if pathID == o.pathID {
			// Self - already have lock
			cwnd = o.congestionWindow
			rtt = o.rtt
			bytes = o.loss2 - o.loss1
			if o.loss3 > o.loss2 && o.loss3-o.loss2 > bytes {
				bytes = o.loss3 - o.loss2
			}
		} else {
			other.mu.Lock()
			cwnd = other.congestionWindow
			rtt = other.rtt
			bytes = other.loss2 - other.loss1
			if other.loss3 > other.loss2 && other.loss3-other.loss2 > bytes {
				bytes = other.loss3 - other.loss2
			}
			other.mu.Unlock()
		}

		if cwnd == maxCwnd {
			M++
		} else if rtt > 0 {
			tmpRTT := rtt * rtt
			if int64(bytes)*int64(bestRTT) >= int64(bestBytes)*int64(tmpRTT) {
				BNotM++
			}
		}
	}

	// Calculate epsilon for this path
	if BNotM == 0 {
		o.epsilonNum = 0
		o.epsilonDen = 1
	} else {
		rtt := o.rtt
		bytes := o.SmoothedBytesBetweenLosses()
		cwnd := o.congestionWindow

		if cwnd < maxCwnd && rtt > 0 {
			tmpRTT := rtt * rtt
			if int64(bytes)*int64(bestRTT) >= int64(bestBytes)*int64(tmpRTT) {
				// This path is in BNotM
				o.epsilonNum = 1
				o.epsilonDen = uint32(len(o.sharedState.pathOLIA)) * uint32(BNotM)
			} else {
				o.epsilonNum = -1
				o.epsilonDen = uint32(len(o.sharedState.pathOLIA)) * uint32(M)
			}
		} else if cwnd == maxCwnd {
			// This path is in M
			o.epsilonNum = -1
			o.epsilonDen = uint32(len(o.sharedState.pathOLIA)) * uint32(M)
		} else {
			o.epsilonNum = 0
			o.epsilonDen = 1
		}
	}
}

// getBestRate calculates the rate parameter used in OLIA.
func (o *OLIACongestionControl) getBestRate() protocol.ByteCount {
	o.sharedState.mu.RLock()
	defer o.sharedState.mu.RUnlock()

	var rate protocol.ByteCount = 1 // Minimum rate to avoid division by zero

	for pathID, other := range o.sharedState.pathOLIA {
		var cwnd protocol.ByteCount
		var rtt time.Duration

		if pathID == o.pathID {
			// Self - already have lock, read directly
			cwnd = o.congestionWindow
			rtt = o.rtt
		} else {
			other.mu.Lock()
			cwnd = other.congestionWindow
			rtt = other.rtt
			other.mu.Unlock()
		}

		if rtt > 0 {
			// rate += cwnd² / rtt
			scaledNum := oliaScale64(uint64(cwnd), oliaScale) * uint64(rtt.Nanoseconds())
			rate += protocol.ByteCount(scaledNum / uint64(rtt.Nanoseconds()))
		}
	}

	return rate * rate
}

// OnCongestionEvent is called when congestion is detected (packet loss).
func (o *OLIACongestionControl) OnCongestionEvent(
	packetNumber protocol.PacketNumber,
	lostBytes protocol.ByteCount,
	priorInFlight protocol.ByteCount,
) {
	o.mu.Lock()
	defer o.mu.Unlock()

	// Update loss measurements
	o.loss1 = o.loss2
	o.loss2 = o.loss3

	// Reduce congestion window (multiplicative decrease)
	o.congestionWindow = o.congestionWindow / 2
	if o.congestionWindow < o.minCongestionWindow {
		o.congestionWindow = o.minCongestionWindow
	}

	// Update slow start threshold
	o.slowStartThreshold = o.congestionWindow

	// Reset OLIA counter
	o.sndCwndCnt = 0
}

// InSlowStart returns whether the connection is in slow start.
func (o *OLIACongestionControl) InSlowStart() bool {
	return o.congestionWindow < o.slowStartThreshold
}

// InRecovery returns whether the connection is in recovery mode.
func (o *OLIACongestionControl) InRecovery() bool {
	// OLIA doesn't have explicit recovery state
	return false
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

	// Reduce window to minimum
	o.slowStartThreshold = o.congestionWindow / 2
	o.congestionWindow = o.minCongestionWindow
	o.sndCwndCnt = 0
}

// SmoothedBytesBetweenLosses returns smoothed bytes between losses.
func (o *OLIACongestionControl) SmoothedBytesBetweenLosses() protocol.ByteCount {
	if o.loss3 > o.loss2 && o.loss3-o.loss2 > o.loss2-o.loss1 {
		return o.loss3 - o.loss2
	}
	return o.loss2 - o.loss1
}

// UpdateRTT updates the RTT estimate for this path.
func (o *OLIACongestionControl) UpdateRTT(rtt, minRTT time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.rtt = rtt
	if minRTT > 0 && (o.minRTT == 0 || minRTT < o.minRTT) {
		o.minRTT = minRTT
	}
	o.updateRTT = true
}

// SetMaxDatagramSize updates the maximum datagram size.
func (o *OLIACongestionControl) SetMaxDatagramSize(size protocol.ByteCount) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.maxDatagramSize = size
}

// Reset resets the congestion control state.
func (o *OLIACongestionControl) Reset() {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.congestionWindow = o.initialWindow
	o.slowStartThreshold = o.maxCongestionWindow
	o.loss1 = 0
	o.loss2 = 0
	o.loss3 = 0
	o.epsilonNum = 0
	o.epsilonDen = 1
	o.sndCwndCnt = 0
	o.ackedBytes = 0
}

// Unregister removes this path from shared state.
func (o *OLIACongestionControl) Unregister() {
	o.sharedState.mu.Lock()
	defer o.sharedState.mu.Unlock()
	delete(o.sharedState.pathOLIA, o.pathID)
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
		InSlowStart:        o.InSlowStart(),
		EpsilonNum:         o.epsilonNum,
		EpsilonDen:         o.epsilonDen,
		RTT:                o.rtt,
	}
}

// OLIAStatistics contains statistics for OLIA congestion control.
type OLIAStatistics struct {
	PathID             protocol.PathID
	CongestionWindow   protocol.ByteCount
	SlowStartThreshold protocol.ByteCount
	BytesInFlight      protocol.ByteCount
	InSlowStart        bool
	EpsilonNum         int
	EpsilonDen         uint32
	RTT                time.Duration
}

// oliaScale64 scales a uint64 value by a given scale factor.
func oliaScale64(val uint64, scale uint) uint64 {
	return val << scale
}
