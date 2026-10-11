package quic

import (
	"net"
	"net/netip"
	"slices"
	"sync"

	"github.com/AeonDave/mp-quic-go/internal/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/internal/wire"
)

// maxObservationProbes is the maximum number of 4-tuples of a path that OBSERVED_ADDRESS frames sent in probe packets
// are kept track of. The path managers validate up to 3 other paths (maxPaths) or 4-tuples (maxTuplesPerPath) at the
// same time.
const maxObservationProbes = 4

// addressDiscovery is the state of QUIC Address Discovery (draft-ietf-quic-address-discovery-01).
// It is created when the peer's transport parameters are received, if both endpoints sent the address_discovery
// transport parameter, and at least one of them provides address observations that the other one requested.
//
// An endpoint that provides address observations sends an OBSERVED_ADDRESS frame on every path, including the path
// used for the handshake, as early as possible (section 5 of the draft). Without IETF Multipath QUIC, the connection
// uses a single path (path 0), which changes when the connection migrates (section 9 of RFC 9000).
// With IETF Multipath QUIC, every path has its own frames, and a path can migrate to another 4-tuple as well.
// A frame is sent on the 4-tuple that a path uses, and when a path (or the connection, without multipath) probes
// another 4-tuple, a frame is sent in the probe packet (section 5 of the draft). When the path switches to that
// 4-tuple, the frame sent in the probe packet is the frame of the path, unless it was lost.
// Probing new 4-tuples is limited by the path managers, which protects against the spoofed packets attack described
// in section 6.2 of the draft.
//
// The frames are only sent in 1-RTT packets. A lost frame is not retransmitted itself: if the path still uses the
// same 4-tuple, a new frame with the current address is sent on the same path (section 4.1 of the draft).
// The sequence numbers of the frames sent increase monotonically across all paths.
type addressDiscovery struct {
	// We send OBSERVED_ADDRESS frames: we offered to provide address observations, and the peer requested them.
	send bool
	// We accept OBSERVED_ADDRESS frames: we requested address observations, and the peer offered to provide them.
	receive bool

	// the sequence number of the next OBSERVED_ADDRESS frame sent
	nextSeq uint64
	// The OBSERVED_ADDRESS frames sent on the paths.
	// Only used on the connection's run loop.
	paths map[protocol.PathID]*observedAddrPath
	// returns the remote address of a path
	remoteAddr      func(protocol.PathID) (netip.AddrPort, bool)
	scheduleSending func()

	mx sync.Mutex
	// the last OBSERVED_ADDRESS frame received on each path
	observed map[protocol.PathID]*wire.ObservedAddressFrame
}

// observedAddrPath are the OBSERVED_ADDRESS frames sent on a path.
type observedAddrPath struct {
	// The frame sent on the 4-tuple that the path uses.
	// If it is nil or lost, a new frame needs to be sent.
	current *sentObservation
	// the frames sent in probe packets to other 4-tuples of the path, the most recent one last
	probes []*sentObservation
}

// A sentObservation is an OBSERVED_ADDRESS frame that was sent.
type sentObservation struct {
	tuple observationTuple
	lost  bool
}

// observationTuple identifies the 4-tuple that an OBSERVED_ADDRESS frame was sent on.
// The local address is only set if it distinguishes the 4-tuples of a path.
type observationTuple struct {
	local, remote netip.AddrPort
}

func newAddressDiscovery(
	send, receive bool,
	remoteAddr func(protocol.PathID) (netip.AddrPort, bool),
	scheduleSending func(),
) *addressDiscovery {
	a := &addressDiscovery{
		send:            send,
		receive:         receive,
		paths:           make(map[protocol.PathID]*observedAddrPath),
		remoteAddr:      remoteAddr,
		scheduleSending: scheduleSending,
		observed:        make(map[protocol.PathID]*wire.ObservedAddressFrame),
	}
	// The path used for the handshake.
	a.addPath(0)
	return a
}

// addPath is called when a new path is opened.
func (a *addressDiscovery) addPath(id protocol.PathID) {
	if !a.send {
		return
	}
	a.paths[id] = &observedAddrPath{}
	a.scheduleSending()
}

// removePath is called when a path is abandoned.
// No frames are sent on the path anymore. The frame received on the path is removed by forgetPath.
func (a *addressDiscovery) removePath(id protocol.PathID) {
	delete(a.paths, id)
}

// forgetPath removes the frame received on a path, once the path is closed.
func (a *addressDiscovery) forgetPath(id protocol.PathID) {
	a.mx.Lock()
	defer a.mx.Unlock()

	delete(a.observed, id)
}

// HasObservedAddress says if an OBSERVED_ADDRESS frame needs to be sent on the 4-tuple that a path uses.
func (a *addressDiscovery) HasObservedAddress(id protocol.PathID) bool {
	p, ok := a.paths[id]
	return ok && (p.current == nil || p.current.lost)
}

// AppendObservedAddress appends the OBSERVED_ADDRESS frame that needs to be sent on the 4-tuple that a path uses,
// if it fits into maxLen.
func (a *addressDiscovery) AppendObservedAddress(frames []ackhandler.Frame, id protocol.PathID, maxLen protocol.ByteCount, v protocol.Version) ([]ackhandler.Frame, protocol.ByteCount) {
	if !a.HasObservedAddress(id) {
		return frames, 0
	}
	addr, ok := a.remoteAddr(id)
	if !ok {
		return frames, 0
	}
	f := &wire.ObservedAddressFrame{SequenceNumber: a.nextSeq, Address: addr}
	l := f.Length(v)
	if l > maxLen {
		return frames, 0
	}
	a.nextSeq++
	obs := &sentObservation{tuple: observationTuple{remote: addr}}
	a.paths[id].current = obs
	return append(frames, ackhandler.Frame{Frame: f, Handler: &observedAddrHandler{a: a, pathID: id, obs: obs}}), l
}

// probeFrame returns the OBSERVED_ADDRESS frame that is sent in a probe packet to another 4-tuple of a path.
// It returns false if no frame needs to be sent: if a frame was already sent to this 4-tuple, and it wasn't lost.
func (a *addressDiscovery) probeFrame(id protocol.PathID, tuple observationTuple) (ackhandler.Frame, bool) {
	p, ok := a.paths[id]
	if !ok || !tuple.remote.IsValid() {
		return ackhandler.Frame{}, false
	}
	for _, obs := range p.probes {
		if obs.tuple == tuple && !obs.lost {
			return ackhandler.Frame{}, false
		}
	}
	if len(p.probes) >= maxObservationProbes {
		p.probes = p.probes[1:]
	}
	obs := &sentObservation{tuple: tuple}
	p.probes = append(p.probes, obs)
	f := &wire.ObservedAddressFrame{SequenceNumber: a.nextSeq, Address: tuple.remote}
	a.nextSeq++
	return ackhandler.Frame{Frame: f, Handler: &observedAddrHandler{a: a, pathID: id, obs: obs}}, true
}

// switchPath is called when a path (or the connection, without IETF Multipath QUIC) switched to another 4-tuple.
// If a frame was sent to that 4-tuple in a probe packet, and it wasn't lost, no new frame is needed.
// Otherwise, a frame is sent on the new 4-tuple.
func (a *addressDiscovery) switchPath(id protocol.PathID, tuple observationTuple) {
	p, ok := a.paths[id]
	if !ok {
		return
	}
	p.current = nil
	for i, obs := range p.probes {
		if obs.tuple == tuple {
			if !obs.lost {
				p.current = obs
			}
			p.probes = append(p.probes[:i], p.probes[i+1:]...)
			break
		}
	}
	if p.current == nil {
		a.scheduleSending()
	}
}

// receivedFrame handles an OBSERVED_ADDRESS frame received on a path.
// It returns false if the frame was ignored, because a frame with an equal or higher sequence number was received
// on the path before (section 4.1 of the draft).
func (a *addressDiscovery) receivedFrame(id protocol.PathID, f *wire.ObservedAddressFrame) bool {
	a.mx.Lock()
	defer a.mx.Unlock()

	if prev, ok := a.observed[id]; ok && f.SequenceNumber <= prev.SequenceNumber {
		return false
	}
	a.observed[id] = &wire.ObservedAddressFrame{
		SequenceNumber: f.SequenceNumber,
		// IPv4-mapped IPv6 addresses are reported as IPv4 addresses.
		Address: netip.AddrPortFrom(f.Address.Addr().Unmap(), f.Address.Port()),
	}
	return true
}

// observedAddr returns the address that the peer reported for a path.
func (a *addressDiscovery) observedAddr(id protocol.PathID) (netip.AddrPort, bool) {
	a.mx.Lock()
	defer a.mx.Unlock()

	f, ok := a.observed[id]
	if !ok {
		return netip.AddrPort{}, false
	}
	return f.Address, true
}

// observedAddrHandler handles the loss of an OBSERVED_ADDRESS frame.
// If the path still uses the 4-tuple of the frame, a new frame is sent on the path.
type observedAddrHandler struct {
	a      *addressDiscovery
	pathID protocol.PathID
	obs    *sentObservation
}

var _ ackhandler.FrameHandler = &observedAddrHandler{}

func (h *observedAddrHandler) OnAcked(wire.Frame) {}

func (h *observedAddrHandler) OnLost(wire.Frame) {
	h.obs.lost = true
	if p, ok := h.a.paths[h.pathID]; ok && p.current == h.obs {
		h.a.scheduleSending()
	}
}

// rfc9000ObservationTuple returns the 4-tuple of the path of a connection that doesn't use IETF Multipath QUIC.
// The server only distinguishes paths by the client's address (see pathManager), the client distinguishes them by
// the local address of the Transport used (see Conn.AddPath).
func rfc9000ObservationTuple(localAddr, remoteAddr net.Addr) observationTuple {
	var tuple observationTuple
	tuple.remote, _ = netAddrToAddrPort(remoteAddr)
	if localAddr != nil {
		tuple.local, _ = netAddrToAddrPort(localAddr)
	}
	return tuple
}

// multipathObservationTuple returns the 4-tuple of a path of IETF Multipath QUIC that a packet was received on
// (server only). The local address is the address in the packet info, without a port.
func multipathObservationTuple(remoteAddr net.Addr, info packetInfo) observationTuple {
	var tuple observationTuple
	tuple.remote, _ = netAddrToAddrPort(remoteAddr)
	if info.addr.IsValid() {
		tuple.local = netip.AddrPortFrom(info.addr.Unmap(), 0)
	}
	return tuple
}

// netAddrToAddrPort converts a UDP address. IPv4-mapped IPv6 addresses are converted to IPv4 addresses.
func netAddrToAddrPort(addr net.Addr) (netip.AddrPort, bool) {
	var ap netip.AddrPort
	switch a := addr.(type) {
	case *net.UDPAddr:
		if a == nil {
			return netip.AddrPort{}, false
		}
		ap = a.AddrPort()
	case nil:
		return netip.AddrPort{}, false
	default:
		var err error
		ap, err = netip.ParseAddrPort(a.String())
		if err != nil {
			return netip.AddrPort{}, false
		}
	}
	if !ap.Addr().IsValid() {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

// maybeAdvertiseAddressDiscovery adds the address_discovery transport parameter, if QUIC Address Discovery is enabled
// (see Config.RequestObservedAddress and Config.ProvideObservedAddress).
// From now on, OBSERVED_ADDRESS frames are a PROTOCOL_VIOLATION in Initial and Handshake packets.
func (c *Conn) maybeAdvertiseAddressDiscovery(params *wire.TransportParameters) {
	switch {
	case c.config.RequestObservedAddress && c.config.ProvideObservedAddress:
		params.AddressDiscovery = wire.AddressDiscoveryProvideAndReceive
	case c.config.RequestObservedAddress:
		params.AddressDiscovery = wire.AddressDiscoveryReceive
	case c.config.ProvideObservedAddress:
		params.AddressDiscovery = wire.AddressDiscoveryProvide
	default:
		return
	}
	c.advertisedAddressDiscovery = params.AddressDiscovery
	c.frameParser.EnableObservedAddress()
}

// maybeNegotiateAddressDiscovery is called when the peer's transport parameters are received.
// If both endpoints sent the address_discovery transport parameter, OBSERVED_ADDRESS frames are sent if the peer
// requested them and we provide them, and accepted if we requested them and the peer provides them.
func (c *Conn) maybeNegotiateAddressDiscovery(params *wire.TransportParameters) {
	local, peer := c.advertisedAddressDiscovery, params.AddressDiscovery
	send := local.Provides() && peer.Receives()
	receive := local.Receives() && peer.Provides()
	if !send && !receive {
		return
	}
	c.addrDisc = newAddressDiscovery(send, receive, c.pathRemoteAddr, c.scheduleSending)
	if send {
		// OBSERVED_ADDRESS frames are only sent in 1-RTT packets.
		c.packer.EnableAddressDiscovery(c.addrDisc)
	}
}

// pathRemoteAddr returns the remote address of a path.
// Without IETF Multipath QUIC, this is the remote address of the connection.
func (c *Conn) pathRemoteAddr(id protocol.PathID) (netip.AddrPort, bool) {
	conn := c.conn
	if c.mp != nil {
		path, ok := c.mp.paths[id]
		if !ok || path.state == mpPathAbandoned {
			return netip.AddrPort{}, false
		}
		conn = c.pathSendConn(path)
	} else if id != 0 {
		return netip.AddrPort{}, false
	}
	return netAddrToAddrPort(conn.RemoteAddr())
}

// addressDiscoveryState returns the state of QUIC Address Discovery.
// It can be called from any goroutine. It returns nil if the handshake is not complete yet.
func (c *Conn) addressDiscoveryState() *addressDiscovery {
	select {
	case <-c.handshakeCompleteChan:
		// The extension is negotiated before the handshake completes, c.addrDisc is not changed afterwards.
		return c.addrDisc
	default:
		return nil
	}
}

// ObservedAddr returns the address that the peer observed for this endpoint on the primary path, i.e. the path
// that LocalAddr and RemoteAddr refer to, using QUIC Address Discovery (see Config.RequestObservedAddress).
// This is the reflexive transport address: if this endpoint is behind a NAT, it is the address that the NAT
// translates the local address to.
// Without IETF Multipath QUIC, it is the address reported last by the peer, which might be an address observed
// on a path that the connection probes (see Path.Probe). With IETF Multipath QUIC, Conn.Paths returns the address
// observed on every path.
//
// It returns false if the peer didn't report an address (yet), if the extension is not used, or if the handshake
// is not complete. Peers can report a wrong address (see section 6.1 of draft-ietf-quic-address-discovery-01).
func (c *Conn) ObservedAddr() (netip.AddrPort, bool) {
	a := c.addressDiscoveryState()
	if a == nil {
		return netip.AddrPort{}, false
	}
	var id protocol.PathID
	if p := c.primaryPath.Load(); p != nil {
		id = p.id
	}
	return a.observedAddr(id)
}

// handleObservedAddressFrame handles an OBSERVED_ADDRESS frame received on a path.
func (c *Conn) handleObservedAddressFrame(f *wire.ObservedAddressFrame, pathID protocol.PathID) error {
	// Section 4.1 of draft-ietf-quic-address-discovery-01: an endpoint that didn't request address observations
	// closes the connection with a PROTOCOL_VIOLATION. The same applies if the peer didn't offer to provide them.
	if c.addrDisc == nil || !c.addrDisc.receive {
		frameType := wire.FrameTypeObservedAddressIPv6
		if f.Address.Addr().Is4() {
			frameType = wire.FrameTypeObservedAddressIPv4
		}
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			FrameType:    uint64(frameType),
			ErrorMessage: "unexpected OBSERVED_ADDRESS frame",
		}
	}
	if c.addrDisc.receivedFrame(pathID, f) && c.logger.Debug() {
		c.logger.Debugf("Peer observed address %s on path %d.", f.Address, pathID)
	}
	return nil
}

// observedAddrDue says if an OBSERVED_ADDRESS frame needs to be sent on the 4-tuple that a path uses.
func (c *Conn) observedAddrDue(id protocol.PathID) bool {
	return c.addrDisc != nil && c.addrDisc.HasObservedAddress(id)
}

// observedAddrProbeFrame appends the OBSERVED_ADDRESS frame to the frames of a probe packet sent to another 4-tuple
// of a path, if a frame needs to be sent. The frame is only sent together with a PATH_CHALLENGE frame, which validates
// the 4-tuple (section 5 of draft-ietf-quic-address-discovery-01).
func (c *Conn) observedAddrProbeFrame(frames []ackhandler.Frame, id protocol.PathID, tuple observationTuple) []ackhandler.Frame {
	if c.addrDisc == nil || !slices.ContainsFunc(frames, func(f ackhandler.Frame) bool {
		_, ok := f.Frame.(*wire.PathChallengeFrame)
		return ok
	}) {
		return frames
	}
	if f, ok := c.addrDisc.probeFrame(id, tuple); ok {
		frames = append(frames, f)
	}
	return frames
}

// observedAddrPathSwitched is called when a path switched to another 4-tuple.
func (c *Conn) observedAddrPathSwitched(id protocol.PathID, tuple observationTuple) {
	if c.addrDisc != nil {
		c.addrDisc.switchPath(id, tuple)
	}
}
