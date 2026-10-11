package quic

import (
	"net"
	"net/netip"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
)

// maybeStartAutoPaths opens paths from the local addresses once IETF Multipath QUIC is active,
// if Config.MultipathAutoPaths is set (see maybeOpenAutoPaths).
func (c *Conn) maybeStartAutoPaths() {
	// The server address that paths are opened to is known once the validation of the server's preferred
	// address completed.
	if c.mp != nil && !c.prefAddrMigration.inProgress() {
		c.maybeOpenAutoPaths()
	}
}

// maybeOpenAutoPaths opens paths of IETF Multipath QUIC from the local addresses (client only):
// from the addresses in Config.MultipathAutoAddrs, or the addresses of the local interfaces, of the address family
// used by path 0, except for the local address of path 0. Up to Config.MaxPaths-1 paths are opened, to the server
// address of path 0, including the paths opened to addresses advertised by the server (see
// maybeOpenPathToAdvertisedAddr). Paths can only be opened once the handshake is confirmed (section 9 of RFC 9000).
// The paths are opened like paths opened by the application using AddPathFromAddr and Path.Probe.
// If the server sent the disable_active_migration transport parameter, no paths to its handshake address are opened
// (section 2.2 of draft-ietf-quic-multipath-21).
func (c *Conn) maybeOpenAutoPaths() {
	if c.autoPathsStarted || !c.config.MultipathAutoPaths || c.perspective != protocol.PerspectiveClient ||
		!c.mp.active || !c.handshakeConfirmed {
		return
	}
	c.autoPathsStarted = true

	remoteAddr := c.conn.RemoteAddr()
	if c.peerParams.DisableActiveMigration && peerAddrsEqual(remoteAddr, c.peerHandshakeAddr) {
		c.logger.Debugf("Not opening paths: the server disabled active migration to its handshake address.")
		return
	}
	localPort, ok := udpPortFromAddr(c.conn.LocalAddr())
	if !ok {
		return
	}
	primaryIP := normalizeAutoIP(ipFromAddr(c.conn.LocalAddr()))
	if primaryIP != nil && !c.hasMultipleSockets() {
		// The socket is bound to a specific address. It doesn't receive packets sent to other local addresses.
		return
	}
	if primaryIP == nil {
		// The socket is bound to an unspecified address.
		// Use the address that the peer sent packets to.
		primaryIP = normalizeAutoIP(c.primaryLocalIP)
	}
	// Paths can only be opened from addresses of the address family of the server address.
	localAddrs := filterIPFamily(c.autoPathAddrs(), remoteAddr)
	maxPaths := int(localInitialMaxPathID(c.config))
	for _, ip := range localAddrs {
		if c.autoPathsOpened >= maxPaths {
			break
		}
		addr := normalizeAutoIP(ip)
		if addr == nil || (primaryIP != nil && addr.Equal(primaryIP)) {
			continue
		}
		key := addr.String()
		if c.autoAddedPaths[key] {
			continue
		}
		if c.autoAddedPaths == nil {
			c.autoAddedPaths = make(map[string]bool)
		}
		c.autoAddedPaths[key] = true
		c.autoPathsOpened++

		info := packetInfoFromPathInfo(PathInfo{LocalAddr: &net.UDPAddr{IP: addr, Port: localPort}})
		h := newMPPathHandle(c, func() sendConn { return c.conn.newPathConn(remoteAddr, info) })
		h.state = mpPathHandleProbing
		if c.logger.Debug() {
			c.logger.Debugf("Opening a path from %s.", addr)
		}
		// The path is opened when a path ID can be used, see maybeOpenPaths.
		c.mp.pendingOpens = append(c.mp.pendingOpens, h)
	}
	c.scheduleSending()
}

// hasMultipleSockets says if the connection sends from multiple sockets, i.e. if it uses a MultiSocketManager.
func (c *Conn) hasMultipleSockets() bool {
	if sc, ok := c.conn.(*sconn); ok {
		_, ok := sc.rawConn.(interface{ LocalAddrs() []net.IP })
		return ok
	}
	return false
}

func (c *Conn) autoPathAddrs() []net.IP {
	if len(c.config.MultipathAutoAddrs) > 0 {
		return append([]net.IP(nil), c.config.MultipathAutoAddrs...)
	}
	if sc, ok := c.conn.(*sconn); ok {
		if provider, ok := sc.rawConn.(interface {
			LocalAddrs() []net.IP
		}); ok {
			return provider.LocalAddrs()
		}
	}
	allowIPv6 := false
	if localIP := ipFromAddr(c.conn.LocalAddr()); localIP != nil && localIP.To4() == nil {
		allowIPv6 = true
	}
	addrs, err := interfaceAddrs(false, allowIPv6)
	if err != nil {
		return nil
	}
	return addrs
}

func normalizeAutoIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return nil
	}
	addr = addr.Unmap()
	if addr.IsUnspecified() {
		return nil
	}
	return addr.AsSlice()
}

func ipFromAddr(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP
	case *net.IPAddr:
		return a.IP
	default:
		return nil
	}
}

func udpPortFromAddr(addr net.Addr) (int, bool) {
	udp, ok := addr.(*net.UDPAddr)
	if !ok || udp.Port <= 0 {
		return 0, false
	}
	return udp.Port, true
}

func filterIPFamily(addrs []net.IP, remote net.Addr) []net.IP {
	udp, ok := remote.(*net.UDPAddr)
	if !ok || udp.IP == nil {
		return addrs
	}
	remoteV4 := udp.IP.To4() != nil
	filtered := make([]net.IP, 0, len(addrs))
	for _, ip := range addrs {
		if ip == nil {
			continue
		}
		if (ip.To4() != nil) == remoteV4 {
			filtered = append(filtered, ip)
		}
	}
	return filtered
}
