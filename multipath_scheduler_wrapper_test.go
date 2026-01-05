package quic

import (
	"net"
	"testing"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestPathSchedulerWrapper_SelectPathProvidesAddresses(t *testing.T) {
	pm := NewMultipathPathManager(protocol.PerspectiveClient)
	pm.EnableMultipath()

	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4321}
	pm.SetPrimaryPath(localAddr, remoteAddr)

	scheduler := NewMultipathScheduler(pm, SchedulingPolicyRoundRobin)
	scheduler.EnableMultipath()

	info, ok := scheduler.SelectPath(PathSelectionContext{Now: time.Now()})
	require.True(t, ok)
	require.Equal(t, PathID(0), info.ID)
	require.Equal(t, localAddr, info.LocalAddr)
	require.Equal(t, remoteAddr, info.RemoteAddr)
}

func TestPathSchedulerWrapper_RegisterPathEnablesMultipath(t *testing.T) {
	pm := NewMultipathPathManager(protocol.PerspectiveClient)
	pm.EnableMultipath()

	localAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 4444}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 2), Port: 5555}

	scheduler := NewMultipathScheduler(pm, SchedulingPolicyRoundRobin)
	scheduler.RegisterPath(PathInfo{
		ID:         0,
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
	})

	info, ok := scheduler.SelectPath(PathSelectionContext{Now: time.Now()})
	require.True(t, ok)
	require.Equal(t, PathID(0), info.ID)
	require.Equal(t, localAddr, info.LocalAddr)
	require.Equal(t, remoteAddr, info.RemoteAddr)
}
