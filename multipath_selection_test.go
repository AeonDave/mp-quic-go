package quic

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newSelectionTestPathInfo(id PathID, status, peerStatus PathStatus) PathInfo {
	return PathInfo{
		ID:         id,
		LocalAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000 + int(id)},
		RemoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 443},
		State:      PathStateActive,
		Status:     status,
		PeerStatus: peerStatus,
	}
}

type builtinTestController struct {
	name string
	ctrl MultipathController
}

// builtinTestControllers returns the built-in multipath controllers, with the paths 0 to 3 registered,
// as the connection registers them with IETF Multipath QUIC. Path 3 has the lowest RTT.
func builtinTestControllers(t *testing.T) []builtinTestController {
	t.Helper()
	var controllers []builtinTestController
	for _, scheduler := range []PathScheduler{NewRoundRobinScheduler(), NewLowLatencyScheduler(), NewMinRTTScheduler(1)} {
		controllers = append(controllers, builtinTestController{
			name: fmt.Sprintf("default controller, %T", scheduler),
			ctrl: NewDefaultMultipathController(scheduler),
		})
	}
	for _, policy := range []SchedulingPolicy{SchedulingPolicyRoundRobin, SchedulingPolicyLowLatency, SchedulingPolicyMinRTT} {
		controllers = append(controllers, builtinTestController{
			name: fmt.Sprintf("scheduler wrapper, policy %d", policy),
			ctrl: NewMultipathScheduler(policy),
		})
	}
	for _, c := range controllers {
		ctrl := c.ctrl
		if enabler, ok := ctrl.(multipathEnabler); ok {
			enabler.EnableMultipath()
		}
		for id := range PathID(4) {
			ctrl.(multipathPathRegistrar).RegisterPath(newSelectionTestPathInfo(id, PathStatusUnknown, PathStatusUnknown))
			if v, ok := ctrl.(multipathPathValidator); ok {
				v.ValidatePath(id)
			}
			rtt := 50 * time.Millisecond
			if id == 3 {
				rtt = 5 * time.Millisecond
			}
			switch c := ctrl.(type) {
			case *DefaultMultipathController:
				c.UpdatePathState(id, PathStateUpdate{SmoothedRTT: &rtt})
			case *PathSchedulerWrapper:
				c.OnPacketAcked(PathEvent{PathID: id, AckEliciting: true, SmoothedRTT: rtt})
			}
		}
	}
	return controllers
}

// notifySentTestPacket informs a controller about a packet sent on a path.
func notifySentTestPacket(ctrl MultipathController, id PathID) {
	switch c := ctrl.(type) {
	case *DefaultMultipathController:
		c.OnPacketSent(id, 1200)
	case MultipathObserver:
		c.OnPacketSent(PathEvent{PathID: id, PacketSize: 1200, AckEliciting: true})
	}
}

// With IETF Multipath QUIC, the built-in controllers select one of the paths passed in the PathSelectionContext,
// even if another path that they know about has a lower RTT. The PathInfo passed in the context is returned.
func TestBuiltinControllersSelectAmongContextPaths(t *testing.T) {
	for _, c := range builtinTestControllers(t) {
		ctrl := c.ctrl
		t.Run(c.name, func(t *testing.T) {
			paths := []PathInfo{
				newSelectionTestPathInfo(1, PathStatusUnknown, PathStatusUnknown),
				newSelectionTestPathInfo(2, PathStatusAvailable, PathStatusUnknown),
			}
			selected := make(map[PathID]int)
			for range 20 {
				info, ok := ctrl.SelectPath(PathSelectionContext{Now: time.Now(), Paths: paths})
				require.True(t, ok)
				require.Contains(t, paths, info)
				selected[info.ID]++
				notifySentTestPacket(ctrl, info.ID)
			}
			require.NotZero(t, selected[1]+selected[2])

			// a path that wasn't registered can be selected as well
			unknown := newSelectionTestPathInfo(5, PathStatusUnknown, PathStatusUnknown)
			info, ok := ctrl.SelectPath(PathSelectionContext{Now: time.Now(), Paths: []PathInfo{unknown}})
			require.True(t, ok)
			require.Equal(t, unknown, info)
		})
	}
}

// Backup paths are only selected if no available path can send (section 3.3 of draft-ietf-quic-multipath-21).
// A path is a backup path if the application or the peer marked it as such.
func TestBuiltinControllersSkipBackupPaths(t *testing.T) {
	for _, c := range builtinTestControllers(t) {
		ctrl := c.ctrl
		t.Run(c.name, func(t *testing.T) {
			// path 3 has the lowest RTT
			paths := []PathInfo{
				newSelectionTestPathInfo(1, PathStatusBackup, PathStatusUnknown),
				newSelectionTestPathInfo(2, PathStatusUnknown, PathStatusAvailable),
				newSelectionTestPathInfo(3, PathStatusAvailable, PathStatusBackup),
			}
			congested := make(map[PathID]bool)
			ctx := PathSelectionContext{
				Now:   time.Now(),
				Paths: paths,
				PathCongestion: func(id PathID) (ByteCount, ByteCount, bool) {
					if congested[id] {
						return 10000, 10000, true
					}
					return 10000, 0, true
				},
			}
			for range 10 {
				info, ok := ctrl.SelectPath(ctx)
				require.True(t, ok)
				require.Equal(t, PathID(2), info.ID)
				notifySentTestPacket(ctrl, info.ID)
			}

			// the available path is congestion limited
			congested[2] = true
			info, ok := ctrl.SelectPath(ctx)
			require.True(t, ok)
			require.Contains(t, []PathID{1, 3}, info.ID)
			// all paths are congestion limited
			congested[1] = true
			congested[3] = true
			_, ok = ctrl.SelectPath(ctx)
			require.False(t, ok)
			// retransmissions are still sent on the available path
			ctx.HasRetransmission = true
			info, ok = ctrl.SelectPath(ctx)
			require.True(t, ok)
			require.Equal(t, PathID(2), info.ID)
		})
	}
}
