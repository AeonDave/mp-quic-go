package quic

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPathFailureDetectorStateTransitions(t *testing.T) {
	detector := newPathFailureDetector()
	start := time.Unix(0, 0)

	changed, failed := detector.sent(1, start)
	require.False(t, changed)
	require.False(t, failed)
	require.False(t, detector.acked(1, 100*time.Millisecond))

	// The path was idle. This doesn't mean that it failed.
	changed, failed = detector.sent(1, start.Add(600*time.Millisecond))
	require.False(t, changed)
	require.False(t, failed)

	// No acknowledgement received for the packet sent at 600ms
	changed, failed = detector.sent(1, start.Add(1050*time.Millisecond))
	require.False(t, changed)
	require.False(t, failed)
	changed, failed = detector.sent(1, start.Add(1150*time.Millisecond))
	require.True(t, changed)
	require.True(t, failed)

	require.True(t, detector.acked(1, 0))
}

func TestPathFailureDetectorNeverAcknowledged(t *testing.T) {
	detector := newPathFailureDetector()
	start := time.Unix(0, 0)

	changed, failed := detector.sent(1, start)
	require.False(t, changed)
	require.False(t, failed)
	changed, failed = detector.sent(1, start.Add(time.Second))
	require.True(t, changed)
	require.True(t, failed)
}

// The connection checks the paths when the deadline returned by the detector expires.
func TestPathFailureDetectorDeadline(t *testing.T) {
	detector := newPathFailureDetector()
	start := time.Unix(1000, 0)
	require.Zero(t, detector.deadline(1))
	changed, failed := detector.check(1, start)
	require.False(t, changed)
	require.False(t, failed)

	changed, failed = detector.sent(1, start)
	require.False(t, changed)
	require.False(t, failed)
	deadline := start.Add(minPathFailureTimeout + 1)
	require.Equal(t, deadline, detector.deadline(1))
	// sending more packets doesn't move the deadline
	detector.sent(1, start.Add(100*time.Millisecond))
	require.Equal(t, deadline, detector.deadline(1))
	changed, _ = detector.check(1, deadline.Add(-1))
	require.False(t, changed)
	require.False(t, detector.potentiallyFailed(1))
	changed, failed = detector.check(1, deadline)
	require.True(t, changed)
	require.True(t, failed)
	require.True(t, detector.potentiallyFailed(1))
	require.Zero(t, detector.deadline(1))
	// path 2 is not affected
	require.False(t, detector.potentiallyFailed(2))

	// an acknowledgment restores the path, and updates the timeout
	require.True(t, detector.acked(1, time.Second))
	require.False(t, detector.potentiallyFailed(1))
	require.False(t, detector.acked(1, time.Second))
	detector.sent(1, start.Add(time.Hour))
	require.Equal(t, start.Add(time.Hour+4*time.Second+1), detector.deadline(1))

	detector.remove(1)
	require.Zero(t, detector.deadline(1))
}
