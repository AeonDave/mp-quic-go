package quic

import (
	"sync"
	"time"
)

const (
	minPathFailureTimeout    = 500 * time.Millisecond
	pathFailureRTTMultiplier = 4
)

// The pathFailureDetector detects paths that potentially failed:
// paths on which no acknowledgement was received for a packet sent longer than a timeout ago.
// It is owned by the connection, which uses it to schedule packets,
// and to signal the status of paths to the peer (section 3.3 of draft-ietf-quic-multipath-21).
type pathFailureDetector struct {
	mu    sync.Mutex
	paths map[PathID]*pathFailureState
}

type pathFailureState struct {
	// the send time of the first packet sent after the last acknowledgement
	firstUnackedSent  time.Time
	smoothedRTT       time.Duration
	potentiallyFailed bool
}

func newPathFailureDetector() *pathFailureDetector {
	return &pathFailureDetector{
		paths: make(map[PathID]*pathFailureState),
	}
}

// sent is called when an ack-eliciting packet is sent on a path.
// It returns if the path's state changed, and if the path potentially failed.
func (d *pathFailureDetector) sent(pathID PathID, now time.Time) (changed, failed bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	state := d.getOrCreate(pathID)
	if state.firstUnackedSent.IsZero() {
		state.firstUnackedSent = now
	}
	return d.evaluate(state, now)
}

// acked is called when a packet sent on a path is acknowledged.
// smoothedRTT is the path's smoothed RTT, or 0 if it is not known.
// It returns true if the path potentially failed before.
func (d *pathFailureDetector) acked(pathID PathID, smoothedRTT time.Duration) (recovered bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	state := d.getOrCreate(pathID)
	state.firstUnackedSent = time.Time{}
	if smoothedRTT > 0 {
		state.smoothedRTT = smoothedRTT
	}
	if state.potentiallyFailed {
		state.potentiallyFailed = false
		return true
	}
	return false
}

// check checks if a path potentially failed by now.
// It returns if the path's state changed, and if the path potentially failed.
func (d *pathFailureDetector) check(pathID PathID, now time.Time) (changed, failed bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	state, ok := d.paths[pathID]
	if !ok {
		return false, false
	}
	return d.evaluate(state, now)
}

// deadline returns the time at which a path will be considered potentially failed,
// unless an acknowledgement is received before.
// It returns the zero time if the path already potentially failed, or if no packet is awaiting an acknowledgement.
func (d *pathFailureDetector) deadline(pathID PathID) time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	state, ok := d.paths[pathID]
	if !ok || state.potentiallyFailed || state.firstUnackedSent.IsZero() {
		return time.Time{}
	}
	// The path is considered potentially failed once the timeout is exceeded.
	return state.firstUnackedSent.Add(state.timeout() + 1)
}

// potentiallyFailed says if a path potentially failed.
func (d *pathFailureDetector) potentiallyFailed(pathID PathID) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	state, ok := d.paths[pathID]
	return ok && state.potentiallyFailed
}

// remove removes the state of a path.
func (d *pathFailureDetector) remove(pathID PathID) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.paths, pathID)
}

func (d *pathFailureDetector) getOrCreate(pathID PathID) *pathFailureState {
	if state, ok := d.paths[pathID]; ok {
		return state
	}
	state := &pathFailureState{}
	d.paths[pathID] = state
	return state
}

func (s *pathFailureState) timeout() time.Duration {
	return max(minPathFailureTimeout, pathFailureRTTMultiplier*s.smoothedRTT)
}

// evaluate checks if a path has potentially failed:
// No acknowledgement was received for a packet sent longer than the timeout ago.
// Note that the time since the last acknowledgement can't be used, since a path might have been idle.
func (d *pathFailureDetector) evaluate(state *pathFailureState, now time.Time) (bool, bool) {
	if state.firstUnackedSent.IsZero() || now.IsZero() {
		return false, state.potentiallyFailed
	}
	if now.Sub(state.firstUnackedSent) > state.timeout() {
		if !state.potentiallyFailed {
			state.potentiallyFailed = true
			return true, true
		}
		return false, true
	}
	return false, state.potentiallyFailed
}
