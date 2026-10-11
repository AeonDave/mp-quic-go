package quic

import (
	"cmp"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/internal/wire"
)

// usablePeerAddress reports whether a peer-advertised address may be used as a new path.
// It rejects port 0, unspecified, multicast and broadcast addresses, and loopback or link-local
// addresses unless the primary path's remote address is of the same kind (e.g. in tests on 127.0.0.1).
func usablePeerAddress(addr *net.UDPAddr, primaryRemote net.Addr) bool {
	if addr == nil || addr.Port <= 0 || addr.Port > 0xffff {
		return false
	}
	ip, ok := netip.AddrFromSlice(addr.IP)
	if !ok {
		return false
	}
	ip = ip.Unmap()
	if ip.IsUnspecified() || ip.IsMulticast() || ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return false
	}
	if !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
		return true
	}

	// Loopback and link-local addresses are only reachable from the peer's own host or link.
	// Only accept them if the connection itself runs over such an address.
	var primaryIP net.IP
	switch a := primaryRemote.(type) {
	case *net.UDPAddr:
		if a != nil {
			primaryIP = a.IP
		}
	case *net.IPAddr:
		if a != nil {
			primaryIP = a.IP
		}
	case *net.TCPAddr:
		if a != nil {
			primaryIP = a.IP
		}
	case nil:
	default:
		if ap, err := netip.ParseAddrPort(a.String()); err == nil {
			primaryIP = ap.Addr().AsSlice()
		}
	}
	primary, ok := netip.AddrFromSlice(primaryIP)
	if !ok {
		return false
	}
	primary = primary.Unmap()
	if ip.IsLoopback() {
		return primary.IsLoopback()
	}
	return primary.IsLinkLocalUnicast()
}

var (
	// ErrAddressAdvertisementNotNegotiated is returned by Conn.AdvertiseAddress if the address advertisement
	// extension is not used on the connection (see Config.EnableAddressAdvertisement).
	ErrAddressAdvertisementNotNegotiated = errors.New("address advertisement extension not negotiated")
	// ErrTooManyAdvertisedAddresses is returned by Conn.AdvertiseAddress if the maximum number of addresses
	// was already advertised.
	ErrTooManyAdvertisedAddresses = errors.New("too many advertised addresses")
)

// addressAdvertisement is the state of the address advertisement extension of this module (ADD_ADDRESS frames).
// It is created when both endpoints advertised the extension, and IETF Multipath QUIC is used.
// The extension is negotiated using the add_address transport parameter, which has an empty value.
//
// An ADD_ADDRESS frame announces an address of the sender, identified by an address ID. The frame is only sent and
// accepted in 1-RTT packets. The receiver uses the frame with the largest sequence number of an address ID.
// Every endpoint advertises up to protocol.MaxAdvertisedAddresses addresses, and keeps track of as many addresses
// advertised by the peer. Addresses that can't be used for a path are ignored (see usablePeerAddress).
// Only clients open paths (section 9 of RFC 9000): a client can open paths to the addresses advertised by the server,
// a server only records the addresses advertised by the client.
type addressAdvertisement struct {
	mx sync.Mutex
	// the addresses we advertised, the index is the address ID
	advertised []netip.AddrPort
	// the addresses advertised by the peer, in ascending order of their address IDs
	peer []peerAdvertisedAddress
}

type peerAdvertisedAddress struct {
	AdvertisedAddress
	seq uint64
}

// advertise returns the ADD_ADDRESS frame advertising an address.
// It returns nil if the address was advertised before.
func (a *addressAdvertisement) advertise(addr netip.AddrPort) (*wire.AddAddressFrame, error) {
	a.mx.Lock()
	defer a.mx.Unlock()

	if slices.Contains(a.advertised, addr) {
		return nil, nil
	}
	if len(a.advertised) >= protocol.MaxAdvertisedAddresses {
		return nil, ErrTooManyAdvertisedAddresses
	}
	id := uint64(len(a.advertised))
	a.advertised = append(a.advertised, addr)
	f := &wire.AddAddressFrame{AddressID: id, Port: addr.Port()}
	if addr.Addr().Is4() {
		ip := addr.Addr().As4()
		f.IPVersion = 4
		f.Address = ip[:]
	} else {
		ip := addr.Addr().As16()
		f.IPVersion = 6
		f.Address = ip[:]
	}
	return f, nil
}

// addPeerAddress records an address advertised by the peer.
// It returns false if the address doesn't change the advertised addresses: if the frame is older than the frame
// received last for the address ID, if the address was already advertised (for any address ID), or if the maximum
// number of addresses is reached.
func (a *addressAdvertisement) addPeerAddress(id, seq uint64, addr netip.AddrPort) (AdvertisedAddress, bool) {
	a.mx.Lock()
	defer a.mx.Unlock()

	idx, found := slices.BinarySearchFunc(a.peer, id, func(p peerAdvertisedAddress, id uint64) int {
		return cmp.Compare(p.ID, id)
	})
	if found && seq <= a.peer[idx].seq {
		return AdvertisedAddress{}, false
	}
	if slices.ContainsFunc(a.peer, func(p peerAdvertisedAddress) bool { return p.Addr == addr }) {
		if found && a.peer[idx].Addr == addr {
			a.peer[idx].seq = seq
		}
		return AdvertisedAddress{}, false
	}
	adv := AdvertisedAddress{ID: id, Addr: addr}
	if found {
		a.peer[idx] = peerAdvertisedAddress{AdvertisedAddress: adv, seq: seq}
		return adv, true
	}
	if len(a.peer) >= protocol.MaxAdvertisedAddresses {
		return AdvertisedAddress{}, false
	}
	a.peer = slices.Insert(a.peer, idx, peerAdvertisedAddress{AdvertisedAddress: adv, seq: seq})
	return adv, true
}

func (a *addressAdvertisement) peerAddresses() []AdvertisedAddress {
	a.mx.Lock()
	defer a.mx.Unlock()

	addrs := make([]AdvertisedAddress, 0, len(a.peer))
	for _, p := range a.peer {
		addrs = append(addrs, p.AdvertisedAddress)
	}
	return addrs
}

// maybeAdvertiseAddressAdvertisement adds the add_address transport parameter, if the extension is enabled.
// It is only sent together with the initial_max_path_id transport parameter.
func (c *Conn) maybeAdvertiseAddressAdvertisement(params *wire.TransportParameters) {
	if !c.advertisedMultipath || !c.config.EnableAddressAdvertisement {
		return
	}
	c.advertisedAddAddress = true
	params.EnableAddAddress = true
}

// maybeNegotiateAddressAdvertisement is called when the peer's transport parameters are received, after
// maybeNegotiateMultipath. The extension is used if both endpoints advertised it, and IETF Multipath QUIC is used.
// From now on, ADD_ADDRESS frames are accepted in 1-RTT packets. In all other packets, they are a PROTOCOL_VIOLATION.
// Without the extension, the frame type is unknown.
func (c *Conn) maybeNegotiateAddressAdvertisement(params *wire.TransportParameters) {
	if c.mp == nil || !c.advertisedAddAddress || !params.EnableAddAddress {
		return
	}
	c.addrAdv = &addressAdvertisement{}
	c.frameParser.EnableAddAddress()
}

// addressAdvertisementState returns the state of the address advertisement extension.
// It can be called from any goroutine. It returns nil if the handshake is not complete yet.
func (c *Conn) addressAdvertisementState() *addressAdvertisement {
	select {
	case <-c.handshakeCompleteChan:
		// The extension is negotiated before the handshake completes, c.addrAdv is not changed afterwards.
		return c.addrAdv
	default:
		return nil
	}
}

// AdvertiseAddress advertises an address of this endpoint to the peer, using the address advertisement extension
// (see Config.EnableAddressAdvertisement). The application needs to make sure that the connection receives the packets
// sent to this address, e.g. by binding the socket to an unspecified address.
// A client can open paths to the addresses advertised by the server. A server only records the addresses advertised
// by the client: only clients open paths.
//
// It can only be called after completion of the handshake. It returns ErrAddressAdvertisementNotNegotiated if the
// extension is not used, and ErrTooManyAdvertisedAddresses if the maximum number of addresses was advertised already.
// Unspecified, multicast and broadcast addresses, and port 0, are rejected. Advertising an address again is a no-op.
func (c *Conn) AdvertiseAddress(addr netip.AddrPort) error {
	addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
	if !advertisableAddress(addr) {
		return fmt.Errorf("invalid address: %s", addr)
	}
	select {
	case <-c.handshakeCompleteChan:
	default:
		return errors.New("handshake not complete")
	}
	return c.advertiseAddress(addr)
}

// advertiseAddress queues an ADD_ADDRESS frame. It can be called from any goroutine once the handshake completed.
func (c *Conn) advertiseAddress(addr netip.AddrPort) error {
	if c.addrAdv == nil {
		return ErrAddressAdvertisementNotNegotiated
	}
	f, err := c.addrAdv.advertise(addr)
	if err != nil || f == nil {
		return err
	}
	// IETF Multipath QUIC is active once the handshake completed, so the frame is sent in a 1-RTT packet.
	// Lost frames are retransmitted.
	c.framer.QueueControlFrame(f)
	c.scheduleSending()
	return nil
}

// PeerAdvertisedAddresses returns the addresses that the peer advertised using the address advertisement extension
// (see Config.EnableAddressAdvertisement), in ascending order of their address IDs.
// Addresses that can't be used for a path are ignored: unspecified, multicast and broadcast addresses, port 0,
// and loopback and link-local addresses unless the connection itself uses such an address.
// Up to 16 addresses are recorded. It returns nil if the extension is not used, or if the handshake is not complete.
func (c *Conn) PeerAdvertisedAddresses() []AdvertisedAddress {
	a := c.addressAdvertisementState()
	if a == nil {
		return nil
	}
	return a.peerAddresses()
}

func (c *Conn) handleAddAddressFrame(f *wire.AddAddressFrame) error {
	if c.addrAdv == nil {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			FrameType:    uint64(wire.FrameTypeAddAddress),
			ErrorMessage: "address advertisement extension not negotiated",
		}
	}
	// The frame parser checks that the length of the address matches the IP version.
	ip, ok := netip.AddrFromSlice(f.Address)
	if !ok {
		return nil
	}
	addr := netip.AddrPortFrom(ip.Unmap(), f.Port)
	if !usablePeerAddress(net.UDPAddrFromAddrPort(addr), c.primarySendConn().RemoteAddr()) {
		if c.logger.Debug() {
			c.logger.Debugf("Ignoring address %s advertised by the peer.", addr)
		}
		return nil
	}
	adv, ok := c.addrAdv.addPeerAddress(f.AddressID, f.SequenceNumber, addr)
	if !ok {
		return nil
	}
	if c.logger.Debug() {
		c.logger.Debugf("Peer advertised address %s (address ID %d).", addr, f.AddressID)
	}
	if observer, ok := c.multipathController.(MultipathAddressObserver); ok {
		observer.OnAddressAdvertised(adv)
	}
	if c.perspective == protocol.PerspectiveClient {
		c.maybeOpenPathToAdvertisedAddr(addr)
	}
	return nil
}

// maybeOpenPathToAdvertisedAddr opens a path to an address advertised by the server (client only),
// if Config.MultipathAutoPaths is set. Paths are only opened to addresses of the address family of the server address
// of path 0, from the local address of path 0, and if no path to the address exists yet.
// Like the paths opened from the local addresses (see maybeOpenAutoPaths), up to Config.MaxPaths-1 paths are opened.
func (c *Conn) maybeOpenPathToAdvertisedAddr(addr netip.AddrPort) {
	if !c.config.MultipathAutoPaths || c.autoPathsOpened >= int(localInitialMaxPathID(c.config)) {
		return
	}
	remote := net.UDPAddrFromAddrPort(addr)
	if udpAddr, ok := c.conn.RemoteAddr().(*net.UDPAddr); ok && udpAddr.IP != nil && (udpAddr.IP.To4() != nil) != addr.Addr().Is4() {
		return
	}
	// The server's handshake address is the address of path 0.
	// Paths to it are opened from the local addresses, unless the server disabled active migration.
	if peerAddrsEqual(c.peerHandshakeAddr, remote) || c.autoAdvertisedPaths[addr] {
		return
	}
	for _, path := range c.mp.paths {
		if path.state != mpPathAbandoned && peerAddrsEqual(c.pathSendConn(path).RemoteAddr(), remote) {
			return
		}
	}
	if c.autoAdvertisedPaths == nil {
		c.autoAdvertisedPaths = make(map[netip.AddrPort]bool)
	}
	c.autoAdvertisedPaths[addr] = true
	c.autoPathsOpened++
	h := newMPPathHandle(c, func() sendConn { return c.conn.newPathConn(remote, packetInfo{}) })
	h.state = mpPathHandleProbing
	if c.logger.Debug() {
		c.logger.Debugf("Opening a path to %s.", addr)
	}
	// The path is opened when a path ID can be used, see maybeOpenPaths.
	c.mp.pendingOpens = append(c.mp.pendingOpens, h)
	c.scheduleSending()
}

// maybeAdvertiseLocalAddrs advertises the local addresses using ADD_ADDRESS frames (server only),
// if Config.MultipathAutoAdvertise is set and the address advertisement extension is used.
// It is called when the handshake completes. The local addresses are the addresses in Config.MultipathAutoAddrs,
// or the addresses of the local interfaces of the address family used by the client.
// The local address used during the handshake is not advertised.
// The addresses are advertised with the port of the socket. This requires a socket bound to an unspecified address:
// a socket bound to a specific address doesn't receive packets sent to other addresses, and the sockets of a
// MultiSocketManager use different ports.
func (c *Conn) maybeAdvertiseLocalAddrs() {
	if c.addrAdv == nil || !c.config.MultipathAutoAdvertise || c.perspective != protocol.PerspectiveServer {
		return
	}
	// The local address of the connection is the address that the client sent its packets to,
	// if the socket is bound to an unspecified address (see newSendConn).
	socketAddr := c.conn.LocalAddr()
	if sc, ok := c.conn.(*sconn); ok {
		socketAddr = sc.rawConn.LocalAddr()
	}
	localPort, ok := udpPortFromAddr(socketAddr)
	if !ok || normalizeAutoIP(ipFromAddr(socketAddr)) != nil || c.hasMultipleSockets() {
		c.logger.Debugf("Not advertising local addresses: the socket is not bound to an unspecified address.")
		return
	}
	primaryIP := normalizeAutoIP(c.primaryLocalIP)
	localAddrs := c.autoPathAddrs()
	if c.config.MultipathAutoAddrs == nil {
		localAddrs = filterIPFamily(localAddrs, c.conn.RemoteAddr())
	}
	for _, ip := range localAddrs {
		addr := normalizeAutoIP(ip)
		if addr == nil || (primaryIP != nil && addr.Equal(primaryIP)) {
			continue
		}
		netAddr, ok := netip.AddrFromSlice(addr)
		if !ok {
			continue
		}
		addrPort := netip.AddrPortFrom(netAddr.Unmap(), uint16(localPort))
		if !advertisableAddress(addrPort) {
			continue
		}
		if err := c.advertiseAddress(addrPort); err != nil {
			c.logger.Debugf("Not advertising %s: %s", addrPort, err)
			return
		}
	}
}

// advertisableAddress says if an address can be advertised using an ADD_ADDRESS frame.
// The peer ignores port 0, unspecified, multicast and broadcast addresses (see usablePeerAddress).
func advertisableAddress(addr netip.AddrPort) bool {
	ip := addr.Addr().Unmap()
	return addr.IsValid() && addr.Port() != 0 && !ip.IsUnspecified() && !ip.IsMulticast() &&
		ip != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}
