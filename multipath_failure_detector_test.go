package quic

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPathFailureDetector_StateTransitions(t *testing.T) {
	detector := newPathFailureDetector()
	start := time.Unix(0, 0)

	changed, failed := detector.onPacketSent(PathEvent{
		PathID:       1,
		AckEliciting: true,
		EventAt:      start,
	})
	require.False(t, changed)
	require.False(t, failed)

	changed, failed = detector.onPacketAcked(PathEvent{
		PathID:       1,
		AckEliciting: true,
		EventAt:      start.Add(10 * time.Millisecond),
		SmoothedRTT:  100 * time.Millisecond,
	})
	require.False(t, changed)
	require.False(t, failed)

	changed, failed = detector.onPacketSent(PathEvent{
		PathID:       1,
		AckEliciting: true,
		EventAt:      start.Add(600 * time.Millisecond),
	})
	require.True(t, changed)
	require.True(t, failed)

	changed, failed = detector.onPacketAcked(PathEvent{
		PathID:       1,
		AckEliciting: true,
		EventAt:      start.Add(650 * time.Millisecond),
	})
	require.True(t, changed)
	require.False(t, failed)
}
