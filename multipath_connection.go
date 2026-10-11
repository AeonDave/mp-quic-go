package quic

import (
	"net"
	"net/netip"
	"reflect"
	"sync"
)

// A MultipathController keeps per-connection state (paths, addresses, statistics).
// A controller set in Config.MultipathController is therefore used by one connection at a time.
// If it is already in use, the built-in controllers are cloned (without their state),
// and multipath is disabled for connections using other controllers.
// Use Config.MultipathControllerFactory to create a controller per connection.
var multipathControllersInUse = struct {
	sync.Mutex
	m map[MultipathController]struct{}
}{m: make(map[MultipathController]struct{})}

// claimMultipathController marks a controller as used by a connection.
// It returns false if the controller is already used by another connection.
func claimMultipathController(ctrl MultipathController) bool {
	if !reflect.TypeOf(ctrl).Comparable() {
		return true // can't track it
	}
	multipathControllersInUse.Lock()
	defer multipathControllersInUse.Unlock()
	if _, ok := multipathControllersInUse.m[ctrl]; ok {
		return false
	}
	multipathControllersInUse.m[ctrl] = struct{}{}
	return true
}

func releaseMultipathController(ctrl MultipathController) {
	if !reflect.TypeOf(ctrl).Comparable() {
		return
	}
	multipathControllersInUse.Lock()
	defer multipathControllersInUse.Unlock()
	delete(multipathControllersInUse.m, ctrl)
}

// multipathControllerCloner is implemented by the built-in controllers.
// It creates a new controller with the same configuration, but without any paths.
type multipathControllerCloner interface {
	cloneForConnection() MultipathController
}

// cloneScheduler creates a new scheduler of the same type and configuration.
// It returns nil for unknown schedulers.
func cloneScheduler(s PathScheduler) PathScheduler {
	switch s := s.(type) {
	case *RoundRobinScheduler:
		return NewRoundRobinScheduler()
	case *LowLatencyScheduler:
		return NewLowLatencyScheduler()
	case *MinRTTScheduler:
		return NewMinRTTScheduler(s.rttBias)
	default:
		return nil
	}
}

// selectMultipathController selects the controller used by this connection.
func (c *Conn) selectMultipathController() MultipathController {
	if c.config.MultipathControllerFactory != nil {
		return c.config.MultipathControllerFactory()
	}
	ctrl := c.config.MultipathController
	if ctrl == nil {
		return nil
	}
	if claimMultipathController(ctrl) {
		c.releaseMultipathControllerOnClose = true
		return ctrl
	}
	if cloner, ok := ctrl.(multipathControllerCloner); ok {
		if clone := cloner.cloneForConnection(); clone != nil {
			return clone
		}
	}
	c.logger.Errorf("Multipath controller is already used by another connection. Disabling multipath for this connection. Use Config.MultipathControllerFactory to create a controller per connection.")
	return nil
}

func (c *Conn) releaseMultipath() {
	if c.releaseMultipathControllerOnClose {
		c.releaseMultipathControllerOnClose = false
		releaseMultipathController(c.multipathController)
	}
}

// MultipathController returns the multipath controller used by this connection.
// It is nil if multipath is not configured.
// When Config.MultipathController is used by multiple connections at the same time,
// the built-in controllers are cloned, so this might not be the controller set in the Config.
func (c *Conn) MultipathController() MultipathController {
	return c.multipathController
}

// multipathPathRemover is implemented by controllers that need to know when a path was abandoned.
type multipathPathRemover interface {
	RemovePath(PathID)
}

// peerAddrsEqual reports whether a and b are the same address of the peer.
// IPv4-mapped IPv6 addresses are equal to the corresponding IPv4 addresses.
func peerAddrsEqual(a, b net.Addr) bool {
	if udpAddr, ok := b.(*net.UDPAddr); ok {
		return multipathRemoteAddrEqual(a, udpAddr)
	}
	return addrsEqual(a, b)
}

// multipathRemoteAddrEqual reports whether addr is the UDP address udpAddr.
// IPv4-mapped IPv6 addresses are equal to the corresponding IPv4 addresses.
func multipathRemoteAddrEqual(addr net.Addr, udpAddr *net.UDPAddr) bool {
	if addr == nil || udpAddr == nil {
		return false
	}
	var ap netip.AddrPort
	switch a := addr.(type) {
	case *net.UDPAddr:
		if a == nil {
			return false
		}
		ap = a.AddrPort()
	default:
		var err error
		if ap, err = netip.ParseAddrPort(addr.String()); err != nil {
			return false
		}
	}
	bp := udpAddr.AddrPort()
	return ap.Port() == bp.Port() && ap.Addr().Unmap() == bp.Addr().Unmap()
}

// pathCongestion returns the congestion window and bytes in flight of a path.
func (c *Conn) pathCongestion(pathID PathID) (cwnd, bytesInFlight ByteCount, ok bool) {
	return c.sentPacketHandler.PathCongestionState(pathID)
}
