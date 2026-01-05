package quic

import (
	"net"
	"net/netip"

	"github.com/AeonDave/mp-quic-go/internal/wire"
)

func (c *Conn) maybeStartAutoPaths() {
	if c.autoPathsStarted || c.multipathController == nil || !c.multipathEnabled {
		return
	}
	if !c.config.MultipathAutoPaths && !c.config.MultipathAutoAdvertise {
		return
	}
	c.autoPathsStarted = true

	localAddrs := c.autoPathAddrs()
	if len(localAddrs) == 0 {
		return
	}
	localPort, ok := udpPortFromAddr(c.conn.LocalAddr())
	if !ok {
		return
	}
	remoteAddr := c.conn.RemoteAddr()
	if remoteAddr == nil {
		return
	}
	primaryIP := normalizeAutoIP(ipFromAddr(c.conn.LocalAddr()))
	if c.config.MultipathAutoAddrs == nil {
		localAddrs = filterIPFamily(localAddrs, remoteAddr)
	}
	if c.nextAddAddressID == 0 {
		c.nextAddAddressID = 1
	}

	for _, ip := range localAddrs {
		addr := normalizeAutoIP(ip)
		if addr == nil {
			continue
		}
		if primaryIP != nil && addr.Equal(primaryIP) {
			continue
		}

		key := addr.String()
		if c.config.MultipathAutoAdvertise {
			if c.autoAdvertisedAddrs == nil {
				c.autoAdvertisedAddrs = make(map[string]bool)
			}
			if !c.autoAdvertisedAddrs[key] {
				c.queueControlFrame(newAddAddressFrame(addr, localPort, c.nextAddAddressID))
				c.autoAdvertisedAddrs[key] = true
				c.nextAddAddressID++
			}
		}

		if c.config.MultipathAutoPaths {
			if c.autoAddedPaths == nil {
				c.autoAddedPaths = make(map[string]bool)
			}
			if c.autoAddedPaths[key] {
				continue
			}
			localAddr := &net.UDPAddr{IP: addr, Port: localPort}
			pathInfo := PathInfo{
				ID:         InvalidPathID,
				LocalAddr:  localAddr,
				RemoteAddr: remoteAddr,
			}
			pathID, ok := c.addAutoPath(pathInfo)
			if ok {
				c.autoAddedPaths[key] = true
				if validator, ok := c.multipathController.(multipathPathValidator); ok {
					if pathID != InvalidPathID {
						validator.ValidatePath(pathID)
					}
				}
			}
		}
	}
}

func (c *Conn) addAutoPath(info PathInfo) (PathID, bool) {
	if creator, ok := c.multipathController.(multipathPathCreator); ok {
		pathID, ok := creator.AddPath(info)
		return pathID, ok
	}
	if registrar, ok := c.multipathController.(multipathPathRegistrar); ok {
		if c.nextAutoPathID == 0 {
			c.nextAutoPathID = 1
		}
		info.ID = PathID(c.nextAutoPathID)
		c.nextAutoPathID++
		registrar.RegisterPath(info)
		return info.ID, true
	}
	return InvalidPathID, false
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

func newAddAddressFrame(ip net.IP, port int, id uint64) *wire.AddAddressFrame {
	ipVersion := uint8(6)
	if v4 := ip.To4(); v4 != nil {
		ipVersion = 4
		ip = v4
	} else {
		ip = ip.To16()
	}
	return &wire.AddAddressFrame{
		AddressID:      id,
		SequenceNumber: id,
		IPVersion:      ipVersion,
		Address:        append([]byte(nil), ip...),
		Port:           uint16(port),
	}
}
