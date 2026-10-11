package quic

import (
	"github.com/AeonDave/mp-quic-go/internal/protocol"
)

// This file informs the multipath controller about the paths of IETF Multipath QUIC.
// The connection opens, validates and abandons the paths. The controller is notified using its optional methods:
//   - EnableMultipath, when the extension becomes active (on completion of the handshake),
//   - RegisterPath and ValidatePath, when a path becomes active (path 0 when the extension becomes active),
//   - RemovePath, when an active path is abandoned,
//   - UpdatePathState, when a path potentially failed or recovered, and with the congestion state and RTT of a path
//     when packets are sent and acknowledged (unless the controller implements MultipathObserver),
//   - OnPacketSent, OnPacketAcked and OnPacketLost (or the methods of MultipathObserver), for every packet.

// notifyMultipathActive is called when IETF Multipath QUIC becomes active.
func (c *Conn) notifyMultipathActive() {
	c.pathCongestionFunc = c.pathCongestion
	if enabler, ok := c.multipathController.(multipathEnabler); ok {
		enabler.EnableMultipath()
	}
	// The connection detects paths that potentially failed (see pathFailureDetector).
	c.setupMultipathObservers()
	c.notifyPathActive(c.mp.paths[0])
}

// notifyPathActive is called when a path was validated.
func (c *Conn) notifyPathActive(path *mpPath) {
	path.registered = true
	if registrar, ok := c.multipathController.(multipathPathRegistrar); ok {
		registrar.RegisterPath(c.mpPathInfo(path))
	}
	if validator, ok := c.multipathController.(multipathPathValidator); ok {
		validator.ValidatePath(path.id)
	}
}

// notifyPathAbandoned is called when a path is abandoned.
func (c *Conn) notifyPathAbandoned(path *mpPath) {
	// Packets sent on the path are neither acknowledged nor declared lost anymore.
	if c.multipathReinjectionManager != nil {
		c.multipathReinjectionManager.forgetPath(path.id)
	}
	if !path.registered {
		return
	}
	path.registered = false
	if remover, ok := c.multipathController.(multipathPathRemover); ok {
		remover.RemovePath(path.id)
	}
}

// notifyPathFailureState is called when a path potentially failed, or when it recovered.
func (c *Conn) notifyPathFailureState(id protocol.PathID, failed bool) {
	if updater, ok := c.multipathController.(multipathPathStateUpdater); ok {
		updater.UpdatePathState(id, PathStateUpdate{PotentiallyFailed: &failed})
	}
}
