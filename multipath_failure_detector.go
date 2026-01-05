package quic

import (
	"sync"
	"time"
)

const (
	minPathFailureTimeout    = 500 * time.Millisecond
	pathFailureRTTMultiplier = 4
)

type pathFailureDetector struct {
	mu    sync.Mutex
	paths map[PathID]*pathFailureState
}

type pathFailureState struct {
	lastSent          time.Time
	lastAck           time.Time
	smoothedRTT       time.Duration
	potentiallyFailed bool
}

func newPathFailureDetector() *pathFailureDetector {
	return &pathFailureDetector{
		paths: make(map[PathID]*pathFailureState),
	}
}

func (d *pathFailureDetector) onPacketSent(ev PathEvent) (bool, bool) {
	if ev.PathID == InvalidPathID {
		return false, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	state := d.getOrCreate(ev.PathID)
	now := ev.EventAt
	if now.IsZero() {
		now = ev.SentAt
	}
	if !now.IsZero() {
		state.lastSent = now
	}
	return d.evaluate(state, now)
}

func (d *pathFailureDetector) onPacketAcked(ev PathEvent) (bool, bool) {
	if ev.PathID == InvalidPathID {
		return false, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	state := d.getOrCreate(ev.PathID)
	if !ev.EventAt.IsZero() {
		state.lastAck = ev.EventAt
	}
	if ev.SmoothedRTT > 0 {
		state.smoothedRTT = ev.SmoothedRTT
	}
	if state.potentiallyFailed {
		state.potentiallyFailed = false
		return true, false
	}
	return false, false
}

func (d *pathFailureDetector) getOrCreate(pathID PathID) *pathFailureState {
	if state, ok := d.paths[pathID]; ok {
		return state
	}
	state := &pathFailureState{}
	d.paths[pathID] = state
	return state
}

func (d *pathFailureDetector) evaluate(state *pathFailureState, now time.Time) (bool, bool) {
	if state.lastAck.IsZero() || state.lastSent.IsZero() {
		return false, state.potentiallyFailed
	}
	if !state.lastSent.After(state.lastAck) {
		return false, state.potentiallyFailed
	}
	timeout := minPathFailureTimeout
	if state.smoothedRTT > 0 {
		candidate := time.Duration(pathFailureRTTMultiplier) * state.smoothedRTT
		if candidate > timeout {
			timeout = candidate
		}
	}
	if !now.IsZero() && now.Sub(state.lastAck) > timeout {
		if !state.potentiallyFailed {
			state.potentiallyFailed = true
			return true, true
		}
		return false, true
	}
	return false, state.potentiallyFailed
}
