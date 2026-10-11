package quic

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The scheduler wrapper selects one of the paths passed in the context, and returns its PathInfo.
func TestPathSchedulerWrapperSelectPathProvidesAddresses(t *testing.T) {
	scheduler := NewMultipathScheduler(SchedulingPolicyRoundRobin)
	scheduler.EnableMultipath()

	path := PathInfo{
		ID:         0,
		LocalAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
		RemoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4321},
	}
	_, ok := scheduler.SelectPath(PathSelectionContext{Now: time.Now()})
	require.False(t, ok)
	info, ok := scheduler.SelectPath(PathSelectionContext{Now: time.Now(), Paths: []PathInfo{path}})
	require.True(t, ok)
	require.Equal(t, path, info)
}

// The statistics of a path are collected once the path was registered, and removed when the path is removed.
func TestPathSchedulerWrapperPathStatistics(t *testing.T) {
	scheduler := NewMultipathScheduler(SchedulingPolicyMinRTT)
	scheduler.EnableMultipath()
	scheduler.OnPacketAcked(PathEvent{PathID: 1, AckEliciting: true, SmoothedRTT: time.Millisecond})
	require.Empty(t, scheduler.pathStats)

	scheduler.RegisterPath(PathInfo{ID: 1})
	scheduler.RegisterPath(PathInfo{ID: 2})
	scheduler.OnPacketSent(PathEvent{PathID: 1, PacketSize: 1000, AckEliciting: true})
	scheduler.OnPacketAcked(PathEvent{PathID: 1, AckEliciting: true, SmoothedRTT: 100 * time.Millisecond})
	scheduler.OnPacketAcked(PathEvent{PathID: 2, AckEliciting: true, SmoothedRTT: 10 * time.Millisecond})
	scheduler.OnPacketLost(PathEvent{PathID: 1, PacketSize: 1000, AckEliciting: true})
	require.Equal(t, &schedulerPathStats{smoothedRTT: 100 * time.Millisecond, packetsSent: 1, bytesSent: 1000, packetsLost: 1}, scheduler.pathStats[1])

	// the path with the lower RTT is selected
	paths := []PathInfo{{ID: 1}, {ID: 2}}
	info, ok := scheduler.SelectPath(PathSelectionContext{Now: time.Now(), Paths: paths})
	require.True(t, ok)
	require.Equal(t, PathID(2), info.ID)

	scheduler.RemovePath(2)
	require.NotContains(t, scheduler.pathStats, PathID(2))
}

// A scheduler wrapper used by another connection is cloned without its paths.
func TestPathSchedulerWrapperClone(t *testing.T) {
	scheduler := NewMultipathScheduler(SchedulingPolicyLowLatency)
	scheduler.RegisterPath(PathInfo{ID: 1})
	clone, ok := scheduler.cloneForConnection().(*PathSchedulerWrapper)
	require.True(t, ok)
	require.NotSame(t, scheduler, clone)
	require.Equal(t, SchedulingPolicyLowLatency, clone.policy)
	require.IsType(t, &LowLatencyScheduler{}, clone.scheduler)
	require.Empty(t, clone.pathStats)
}
