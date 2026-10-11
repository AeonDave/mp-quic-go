package quic

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/utils"
	"github.com/AeonDave/mp-quic-go/internal/wire"
)

// A PreferredAddress is an address that a server asks its clients to migrate connections to,
// once the handshake is confirmed (section 9.6 of RFC 9000).
// A typical use is a server that accepts connections on an address shared by multiple servers,
// e.g. an anycast address, and prefers its clients to use an address of its own.
//
// The server sends the preferred_address transport parameter on every connection, together with a connection ID
// and a stateless reset token. A client validates the preferred address of the address family of the server address
// it connected to (or of the other address family, if it can send to it), and migrates the connection there if the
// validation succeeds. Otherwise, it keeps using the original address.
//
// The server recognizes the packets sent to the preferred address by their local IP address.
// The preferred IP addresses therefore need to be different from the addresses that clients connect to.
// If a client connected to the preferred IP address of an address family, the preferred address of this
// address family is not sent to this client.
type PreferredAddress struct {
	// IPv4 is the preferred IPv4 address.
	// It is not set if the server doesn't have a preferred IPv4 address.
	IPv4 netip.AddrPort
	// IPv4Transport is the Transport that receives the packets sent to the IPv4 address.
	//
	// If it is nil, the Transport of the listener receives them. Its connection needs to receive the packets sent to
	// this address, and to report the local address of every packet received, for example a [net.UDPConn] bound to
	// the unspecified address and the port of the preferred address (on platforms that support reading the packet
	// info, like Linux, macOS and FreeBSD), or a [MultiSocketManager] with a socket bound to the preferred address.
	//
	// Otherwise, the Transport needs to use the same connection ID length and the same StatelessResetKey as the
	// Transport of the listener. It must not be closed before the listener's Transport:
	// closing it closes the connections of the listener.
	IPv4Transport *Transport

	// IPv6 is the preferred IPv6 address.
	// It is not set if the server doesn't have a preferred IPv6 address.
	IPv6 netip.AddrPort
	// IPv6Transport is the Transport that receives the packets sent to the IPv6 address,
	// see IPv4Transport. It can be the same Transport as IPv4Transport.
	IPv6Transport *Transport
}

// serverPreferredAddr is the preferred address used by a listener.
type serverPreferredAddr struct {
	ipv4, ipv6 netip.AddrPort
	// The Transports, other than the listener's Transport, that receive the packets sent to the preferred address.
	transports []preferredAddrTransport
}

// A preferredAddrTransport is a Transport that receives the packets sent to the preferred address of one or both
// address families.
type preferredAddrTransport struct {
	tr *Transport
	// the preferred addresses that the Transport receives packets for, invalid if it doesn't
	ipv4, ipv6 netip.Addr
}

// setup validates the preferred address of the listener's Transport t.
// It initializes the other Transports used for the preferred address,
// and returns the connection that the listener's connections send on.
func (pa *PreferredAddress) setup(t *Transport) (*serverPreferredAddr, rawConn, error) {
	if !pa.IPv4.IsValid() && !pa.IPv6.IsValid() {
		return nil, nil, errors.New("quic: preferred address without an IPv4 and an IPv6 address")
	}
	if pa.IPv4.IsValid() {
		if err := validatePreferredAddr(pa.IPv4, true); err != nil {
			return nil, nil, err
		}
	} else if pa.IPv4Transport != nil {
		return nil, nil, errors.New("quic: preferred address: IPv4 Transport without IPv4 address")
	}
	if pa.IPv6.IsValid() {
		if err := validatePreferredAddr(pa.IPv6, false); err != nil {
			return nil, nil, err
		}
	} else if pa.IPv6Transport != nil {
		return nil, nil, errors.New("quic: preferred address: IPv6 Transport without IPv6 address")
	}
	// A server that uses zero-length connection IDs must not send a preferred address (section 18.2 of RFC 9000).
	if t.connIDLen == 0 {
		return nil, nil, errors.New("quic: preferred address requires connection IDs of non-zero length")
	}
	spa := &serverPreferredAddr{
		ipv4: netip.AddrPortFrom(pa.IPv4.Addr().Unmap(), pa.IPv4.Port()),
		ipv6: pa.IPv6,
	}
	conns := make(map[netip.Addr]rawConn, 2)
	for _, a := range []struct {
		addr netip.AddrPort
		tr   *Transport
	}{{spa.ipv4, pa.IPv4Transport}, {spa.ipv6, pa.IPv6Transport}} {
		if !a.addr.IsValid() {
			continue
		}
		if a.tr == nil {
			if err := checkListenerReceives(t.conn, a.addr); err != nil {
				return nil, nil, err
			}
			continue
		}
		ip := a.addr.Addr()
		if a.tr == t {
			return nil, nil, errors.New("quic: preferred address: Transport is the listener's Transport")
		}
		if err := a.tr.init(false); err != nil {
			return nil, nil, err
		}
		// Packets are routed by their connection ID, which is parsed with the Transport's connection ID length.
		if a.tr.connIDLen != t.connIDLen {
			return nil, nil, errors.New("quic: preferred address: Transport uses a different connection ID length")
		}
		// The stateless reset token sent in the preferred_address transport parameter is generated by the
		// listener's Transport, and the other Transport sends the stateless resets for the connection ID.
		if (a.tr.StatelessResetKey == nil) != (t.StatelessResetKey == nil) ||
			(t.StatelessResetKey != nil && *a.tr.StatelessResetKey != *t.StatelessResetKey) {
			return nil, nil, errors.New("quic: preferred address: Transport uses a different stateless reset key")
		}
		conns[ip] = a.tr.conn
		idx := slices.IndexFunc(spa.transports, func(pt preferredAddrTransport) bool { return pt.tr == a.tr })
		if idx == -1 {
			idx = len(spa.transports)
			spa.transports = append(spa.transports, preferredAddrTransport{tr: a.tr})
		}
		if ip.Is4() {
			spa.transports[idx].ipv4 = ip
		} else {
			spa.transports[idx].ipv6 = ip
		}
	}
	if len(conns) == 0 {
		return spa, t.conn, nil
	}
	return spa, &preferredAddrConn{rawConn: t.conn, conns: conns}, nil
}

// checkListenerReceives checks that the listener's connection can receive the packets sent to the preferred address:
// a socket bound to the unspecified address and the port of the preferred address, or a MultiSocketManager.
func checkListenerReceives(conn rawConn, addr netip.AddrPort) error {
	if _, ok := conn.(*MultiSocketManager); ok {
		return nil
	}
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil
	}
	// A socket bound to 0.0.0.0 only receives IPv4 packets.
	if !local.IP.IsUnspecified() || local.Port != int(addr.Port()) || (local.IP.To4() != nil && !addr.Addr().Is4()) {
		return fmt.Errorf("quic: preferred address: the listener's socket (%s) doesn't receive the packets sent to %s", local, addr)
	}
	return nil
}

func validatePreferredAddr(addr netip.AddrPort, ipv4 bool) error {
	ip := addr.Addr()
	if ipv4 {
		ip = ip.Unmap()
		if !ip.Is4() {
			return errors.New("quic: preferred address: invalid IPv4 address")
		}
	} else if !ip.Is6() || ip.Is4In6() {
		return errors.New("quic: preferred address: invalid IPv6 address")
	}
	if ip.IsUnspecified() || ip.IsMulticast() || addr.Port() == 0 {
		return errors.New("quic: preferred address: invalid address")
	}
	return nil
}

// A preferredAddrConn is the connection that the connections of a listener send on,
// if the packets sent to the preferred address are received by another Transport (see PreferredAddress).
// Packets sent from the preferred address, i.e. with the preferred address in the packet info,
// are sent on that Transport's connection.
type preferredAddrConn struct {
	rawConn // the connection of the listener's Transport

	conns map[netip.Addr]rawConn
}

var (
	_ packetInfoWriter  = &preferredAddrConn{}
	_ localAddrSelector = &preferredAddrConn{}
)

func (c *preferredAddrConn) connFor(info packetInfo) rawConn {
	if conn, ok := c.conns[info.addr.Unmap()]; ok && info.addr.IsValid() {
		return conn
	}
	return c.rawConn
}

func (c *preferredAddrConn) WritePacketWithInfo(b []byte, addr net.Addr, info packetInfo, gsoSize uint16, ecn protocol.ECN) (int, error) {
	conn := c.connFor(info)
	if w, ok := conn.(packetInfoWriter); ok {
		return w.WritePacketWithInfo(b, addr, info, gsoSize, ecn)
	}
	return conn.WritePacket(b, addr, info.OOB(), gsoSize, ecn)
}

func (c *preferredAddrConn) localAddrFor(info packetInfo) net.Addr {
	return sendLocalAddr(c.connFor(info), info)
}

// capabilities returns the capabilities that all connections have.
func (c *preferredAddrConn) capabilities() connCapabilities {
	capabilities := c.rawConn.capabilities()
	for _, conn := range c.conns {
		cc := conn.capabilities()
		capabilities.DF = capabilities.DF && cc.DF
		capabilities.GSO = capabilities.GSO && cc.GSO
		capabilities.ECN = capabilities.ECN && cc.ECN
	}
	return capabilities
}

// A preferredAddrPacketHandler passes the packets received by a Transport used for the preferred address
// (see PreferredAddress) to a connection. The connection recognizes them by the preferred address in the packet info.
type preferredAddrPacketHandler struct {
	*Conn

	// the preferred addresses that the Transport receives packets for, invalid if it doesn't
	ipv4, ipv6 netip.Addr
}

func (h *preferredAddrPacketHandler) handlePacket(p receivedPacket) {
	// A Transport used for both address families receives packets from clients of both address families.
	ip := h.ipv4
	if a, ok := netAddrToAddrPort(p.remoteAddr); !ip.IsValid() || (ok && !a.Addr().Is4() && h.ipv6.IsValid()) {
		ip = h.ipv6
	}
	p.info.addr = ip
	h.Conn.handlePacket(p)
}

// preferredAddrServer is the state of a server connection that sent the preferred_address transport parameter.
type preferredAddrServer struct {
	// the IP addresses sent in the transport parameter, invalid if not sent
	ipv4, ipv6 netip.Addr
	// The local address of path 0: the preferred address that path 0 migrated to,
	// or the invalid address if it uses the original address.
	current netip.Addr
}

// localAddr returns the preferred address that a packet was received on,
// or the invalid address if it was received on another address.
func (s *preferredAddrServer) localAddr(info packetInfo) netip.Addr {
	if s == nil || !info.addr.IsValid() {
		return netip.Addr{}
	}
	addr := info.addr.Unmap()
	if addr == s.ipv4 || addr == s.ipv6 {
		return addr
	}
	return netip.Addr{}
}

// currentLocalAddr returns the local address of path 0, see current.
func (s *preferredAddrServer) currentLocalAddr() netip.Addr {
	if s == nil {
		return netip.Addr{}
	}
	return s.current
}

// isMigration says if a packet received on path id would make the path migrate to a preferred address.
func (s *preferredAddrServer) isMigration(id protocol.PathID, info packetInfo) bool {
	if s == nil || id != 0 {
		return false
	}
	local := s.localAddr(info)
	return local.IsValid() && local != s.current
}

// migrated is called when path 0 migrated to the preferred address local.
func (s *preferredAddrServer) migrated(local netip.Addr) {
	s.current = local
}

// dropsPacket says if a packet received on path id is dropped: after path 0 migrated to the preferred address,
// packets received on the original address are dropped (section 9.6.2 of RFC 9000).
// Newer packets SHOULD be dropped. Delayed packets are dropped as well: processing them would require responding
// to PATH_CHALLENGE frames on the original address.
func (s *preferredAddrServer) dropsPacket(id protocol.PathID, info packetInfo) bool {
	return s != nil && id == 0 && s.current.IsValid() && !s.localAddr(info).IsValid()
}

// maybeAdvertisePreferredAddress adds the preferred_address transport parameter (server only).
// The preferred address of the address family that the client connected to is not sent if the client connected
// to it.
// The connection IDs of the connection and the client's stateless reset tokens are added to the Transports that
// receive packets sent to the preferred address.
func (c *Conn) maybeAdvertisePreferredAddress(params *wire.TransportParameters, conf *serverPreferredAddr) {
	if conf == nil || c.srcConnIDLen == 0 {
		return
	}
	var localIP netip.Addr
	if ip, ok := netip.AddrFromSlice(ipFromAddr(c.conn.LocalAddr())); ok {
		localIP = ip.Unmap()
	}
	pa := &wire.PreferredAddress{}
	if conf.ipv4.IsValid() && conf.ipv4.Addr() != localIP {
		pa.IPv4 = conf.ipv4
	}
	if conf.ipv6.IsValid() && conf.ipv6.Addr() != localIP {
		pa.IPv6 = conf.ipv6
	}
	if !pa.IPv4.IsValid() && !pa.IPv6.IsValid() {
		return
	}
	connID, token, err := c.connIDGenerator.IssuePreferredAddressConnID()
	if err != nil {
		c.logger.Debugf("Not sending a preferred address: generating the connection ID failed: %s", err)
		return
	}
	pa.ConnectionID = connID
	pa.StatelessResetToken = token
	params.PreferredAddress = pa
	c.prefAddr = &preferredAddrServer{ipv4: pa.IPv4.Addr(), ipv6: pa.IPv6.Addr()}

	for _, t := range conf.transports {
		runner := (*packetHandlerMap)(t.tr)
		h := &preferredAddrPacketHandler{Conn: c, ipv4: t.ipv4, ipv6: t.ipv6}
		c.connIDGenerator.AddConnRunner(
			runner,
			connRunnerCallbacks{
				AddConnectionID:    func(connID protocol.ConnectionID) { runner.Add(connID, h) },
				RemoveConnectionID: runner.Remove,
				ReplaceWithClosed:  runner.ReplaceWithClosed,
			},
		)
		// A client that lost its state sends stateless resets to the address it sends to (section 10.3.1 of RFC 9000).
		c.resetTokenRunners.AddRunner(runner, h)
	}
}

// preferredAddrPathID identifies the connection ID that the client uses for the preferred address,
// see connIDManager.GetConnIDForPath.
const preferredAddrPathID pathID = -2

type preferredAddrMigrationState uint8

const (
	// the client validates the preferred address once the handshake is confirmed
	preferredAddrPending preferredAddrMigrationState = iota
	preferredAddrValidating
	preferredAddrMigrated
	preferredAddrFailed
)

// preferredAddrMigration is the client's migration to the server's preferred address (section 9.6 of RFC 9000).
type preferredAddrMigration struct {
	addr  *net.UDPAddr
	state preferredAddrMigrationState
	// The data of the PATH_CHALLENGE frames sent to the preferred address.
	// They are kept after the validation, so that late PATH_RESPONSE frames are recognized.
	challenges [][8]byte
	// The PATH_CHALLENGE frames sent before the validation started again from a new local address
	// (see startPreferredAddrValidation) don't validate the preferred address.
	firstValidChallenge int
	// When the next PATH_CHALLENGE frame is sent, and the interval to the one after that (exponential backoff).
	nextProbe     monotime.Time
	probeInterval time.Duration
	// The validation fails if it doesn't succeed by then.
	deadline monotime.Time
}

// validating says if the client is validating the preferred address.
func (m *preferredAddrMigration) validating() bool {
	return m != nil && m.state == preferredAddrValidating
}

// inProgress says if the client didn't finish the migration to the preferred address yet.
func (m *preferredAddrMigration) inProgress() bool {
	return m != nil && (m.state == preferredAddrPending || m.state == preferredAddrValidating)
}

// timeout returns the time when a PATH_CHALLENGE needs to be sent, or when the validation fails.
func (m *preferredAddrMigration) timeout() monotime.Time {
	if !m.validating() {
		return 0
	}
	if m.nextProbe.Before(m.deadline) {
		return m.nextProbe
	}
	return m.deadline
}

// choosePreferredAddr chooses the server's preferred address that the client migrates to:
// the address of the address family of the server's current address, or, if the server didn't send one,
// the address of the other address family, if the client can send to it from its local address.
// It returns nil if there's no such address.
func choosePreferredAddr(pa *wire.PreferredAddress, localAddr, remoteAddr net.Addr) *net.UDPAddr {
	remote, ok := netAddrToAddrPort(remoteAddr)
	if !ok {
		return nil
	}
	var addr netip.AddrPort
	switch {
	case remote.Addr().Is4() && pa.IPv4.IsValid():
		addr = pa.IPv4
	case remote.Addr().Is6() && pa.IPv6.IsValid():
		addr = pa.IPv6
	default:
		local, ok := netAddrToAddrPort(localAddr)
		if !ok {
			return nil
		}
		switch {
		// An IPv6 socket bound to the unspecified address can send to IPv4 addresses, unless it's IPv6-only.
		// If it is, sending fails, and the validation fails.
		case pa.IPv4.IsValid() && (local.Addr().Is4() || local.Addr() == netip.IPv6Unspecified()):
			addr = pa.IPv4
		case pa.IPv6.IsValid() && local.Addr().Is6():
			addr = pa.IPv6
		default:
			return nil
		}
	}
	if addr == remote {
		return nil
	}
	// Don't migrate to a loopback address offered by a server that isn't reached over a loopback address
	// (section 21.5.6 of RFC 9000).
	if addr.Addr().Unmap().IsLoopback() && !remote.Addr().Unmap().IsLoopback() {
		return nil
	}
	return net.UDPAddrFromAddrPort(addr)
}

// handlePreferredAddress handles the preferred_address transport parameter (client only).
// If the client can migrate to one of the addresses, the connection ID is kept for the migration,
// which starts once the handshake is confirmed (see maybeMigrateToPreferredAddr).
func (c *Conn) handlePreferredAddress(pa *wire.PreferredAddress) {
	conn := c.conn
	if c.mp != nil && c.mp.active {
		if path := c.mp.paths[0]; path != nil {
			conn = c.pathSendConn(path)
		}
	}
	addr := choosePreferredAddr(pa, conn.LocalAddr(), conn.RemoteAddr())
	if addr == nil {
		c.connIDManager.AddFromPreferredAddress(pa.ConnectionID, pa.StatelessResetToken)
		return
	}
	c.connIDManager.AddFromPreferredAddressForPath(preferredAddrPathID, pa.ConnectionID, pa.StatelessResetToken)
	c.prefAddrMigration = &preferredAddrMigration{addr: addr}
}

// maybeMigrateToPreferredAddr starts the validation of the server's preferred address,
// when the handshake is confirmed (client only).
func (c *Conn) maybeMigrateToPreferredAddr(now monotime.Time) {
	m := c.prefAddrMigration
	if m == nil || m.state != preferredAddrPending {
		return
	}
	if c.mp != nil && c.mp.active {
		if !c.preferredAddrPathUsable() {
			c.preferredAddrValidationFailed()
			return
		}
		// The server responds from the preferred address.
		c.mp.allowServerAddr(0, m.addr)
	}
	if c.logger.Debug() {
		c.logger.Debugf("Validating the server's preferred address %s.", m.addr)
	}
	c.startPreferredAddrValidation(now)
}

// startPreferredAddrValidation starts the validation of the preferred address, or starts it again,
// after the client migrated to a new local address (section 9.6.3 of RFC 9000).
// PATH_CHALLENGE frames are sent with exponential backoff, starting at the PTO, and the validation fails after three
// times the larger one of the current PTO and the PTO of a new path (section 8.2.4 of RFC 9000).
func (c *Conn) startPreferredAddrValidation(now monotime.Time) {
	m := c.prefAddrMigration
	m.state = preferredAddrValidating
	m.firstValidChallenge = len(m.challenges)
	m.nextProbe = now
	pto := c.rttStats.PTO(true)
	m.probeInterval = pto
	m.deadline = now.Add(3 * max(pto, utils.NewRTTStats().PTO(true)))
}

// handlePreferredAddrTimers sends the PATH_CHALLENGE frames that validate the preferred address,
// and stops the validation if it failed (client only).
func (c *Conn) handlePreferredAddrTimers(now monotime.Time) error {
	m := c.prefAddrMigration
	if !m.validating() {
		return nil
	}
	// With IETF Multipath QUIC, path 0 migrates. The validation fails if path 0 was abandoned.
	if !now.Before(m.deadline) || (c.mp != nil && c.mp.active && !c.preferredAddrPathUsable()) {
		c.preferredAddrValidationFailed()
		return nil
	}
	if now.Before(m.nextProbe) {
		return nil
	}
	m.nextProbe = now.Add(m.probeInterval)
	m.probeInterval *= 2
	// The connection ID is used for the preferred address only (section 9.5 of RFC 9000).
	// If the server didn't provide an unused connection ID yet, the PATH_CHALLENGE is sent later.
	connID, ok := c.connIDManager.GetConnIDForPath(preferredAddrPathID)
	if !ok {
		c.logger.Debugf("Not validating the preferred address yet: no connection ID available.")
		return nil
	}
	challenge := newPathChallenge()
	m.challenges = append(m.challenges, challenge.Data)
	return c.sendPreferredAddrProbe(connID, []ackhandler.Frame{{Frame: challenge, Handler: emptyHandler{}}}, now)
}

// sendPreferredAddrProbe sends a packet containing PATH_CHALLENGE or PATH_RESPONSE frames to the preferred address
// (client only). The datagram is expanded to 1200 bytes (section 8.2 of RFC 9000).
func (c *Conn) sendPreferredAddrProbe(connID protocol.ConnectionID, frames []ackhandler.Frame, now monotime.Time) error {
	m := c.prefAddrMigration
	conn := c.conn
	var info packetInfo
	if c.mp != nil && c.mp.active {
		if !c.preferredAddrPathUsable() {
			return nil
		}
		path := c.mp.paths[0]
		conn = c.pathSendConn(path)
		info = path.info
	}
	frames = c.observedAddrProbeFrame(frames, 0, rfc9000ObservationTuple(conn.LocalAddr(), m.addr))
	probe, buf, err := c.packer.PackPathProbePacket(connID, frames, protocol.MinInitialPacketSize, c.version, 0)
	if err == errNothingToPack {
		c.logger.Debugf("Not sending a path probe packet to the preferred address: frames too large.")
		return nil
	}
	if err != nil {
		return err
	}
	if c.logger.Debug() {
		c.logger.Debugf("Sending a path probe packet to the preferred address %s.", m.addr)
	}
	c.logShortHeaderPacket(probe, protocol.ECNNon, buf.Len())
	c.registerPackedShortHeaderPacket(probe, protocol.ECNNon, now)
	// Failing to send the packet (e.g. because the preferred address is unreachable)
	// doesn't close the connection. The validation fails.
	if err := conn.WriteTo(buf.Data, m.addr, info); err != nil {
		c.logger.Debugf("Failed to send path probe packet to the preferred address: %s", err)
	}
	buf.Release()
	return nil
}

// isProbePath says if a packet received on path id from remoteAddr was received on the path from the
// preferred address, while the client validates it.
func (m *preferredAddrMigration) isProbePath(id protocol.PathID, remoteAddr net.Addr) bool {
	return m.validating() && id == 0 && peerAddrsEqual(remoteAddr, m.addr)
}

// respondOnPreferredAddrPath responds to the PATH_CHALLENGE frames that the server sent from the preferred
// address, while the client validates it (client only), see isProbePath.
// The PATH_RESPONSE frames are sent to the preferred address, i.e. on the path that the PATH_CHALLENGE frames were
// received on, in a datagram expanded to 1200 bytes (section 8.2.2 of RFC 9000).
func (c *Conn) respondOnPreferredAddrPath(challenges []*wire.PathChallengeFrame, now monotime.Time) error {
	if len(challenges) == 0 {
		return nil
	}
	var connID protocol.ConnectionID
	if c.prefAddrMigration.validating() {
		var ok bool
		connID, ok = c.connIDManager.GetConnIDForPath(preferredAddrPathID)
		if !ok {
			return nil
		}
	} else {
		// The packet completed the validation. The connection uses the preferred address now.
		connID = c.connIDManager.Get()
	}
	frames := make([]ackhandler.Frame, 0, len(challenges))
	for _, ch := range challenges {
		frames = append(frames, ackhandler.Frame{Frame: &wire.PathResponseFrame{Data: ch.Data}, Handler: emptyHandler{}})
	}
	return c.sendPreferredAddrProbe(connID, frames, now)
}

// handlePreferredAddrPathResponse handles a PATH_RESPONSE frame for a PATH_CHALLENGE frame sent to the preferred
// address (client only). The client migrates to the preferred address.
// It returns false if the PATH_RESPONSE frame doesn't belong to such a PATH_CHALLENGE frame.
func (c *Conn) handlePreferredAddrPathResponse(f *wire.PathResponseFrame, now monotime.Time) bool {
	m := c.prefAddrMigration
	if m == nil {
		return false
	}
	idx := slices.Index(m.challenges, f.Data)
	if idx == -1 {
		return false
	}
	if m.state == preferredAddrValidating && idx >= m.firstValidChallenge {
		c.migrateToPreferredAddr(now)
	}
	return true
}

// migrateToPreferredAddr migrates the connection to the validated preferred address (client only).
// From now on, packets are sent to the preferred address, using the connection ID used for validating it
// (section 9.6.1 of RFC 9000). The congestion controller and the RTT estimate are reset (section 9.4 of RFC 9000).
// With IETF Multipath QUIC, path 0 migrates (section 2.2 of draft-ietf-quic-multipath-21).
func (c *Conn) migrateToPreferredAddr(now monotime.Time) {
	m := c.prefAddrMigration
	if c.mp != nil && c.mp.active {
		if !c.preferredAddrPathUsable() {
			c.preferredAddrValidationFailed()
			return
		}
		path := c.mp.paths[0]
		m.state = preferredAddrMigrated
		prevAddr := c.pathSendConn(path).RemoteAddr()
		c.peerConnIDs.UseConnIDForTuple(0, preferredAddrPathID, invalidPathID)
		// Packets that the server sent from its original address might still arrive.
		c.mp.allowServerAddr(0, prevAddr)
		c.migrateMultipathPath(path, m.addr, path.info, now)
	} else {
		m.state = preferredAddrMigrated
		c.connIDManager.UseConnIDForPath(preferredAddrPathID, invalidPathID)
		c.conn.ChangeRemoteAddr(m.addr, packetInfo{})
		initialPacketSize := protocol.ByteCount(c.config.InitialPacketSize)
		c.sentPacketHandler.MigratedPath(now, initialPacketSize)
		if c.mtuDiscoverer != nil {
			c.mtuDiscoverer.Reset(now, initialPacketSize, c.peerMaxUDPPayloadSize())
		}
		c.observedAddrPathSwitched(0, rfc9000ObservationTuple(c.conn.LocalAddr(), m.addr))
	}
	c.migratedToPreferredAddr.Store(true)
	if c.logger.Debug() {
		c.logger.Debugf("Migrated to the server's preferred address %s.", m.addr)
	}
	c.maybeStartAutoPaths()
	c.scheduleSending()
}

// preferredAddrPathUsable says if path 0, which migrates to the preferred address with IETF Multipath QUIC,
// can be used.
func (c *Conn) preferredAddrPathUsable() bool {
	path, ok := c.mp.paths[0]
	return ok && path.usable()
}

// preferredAddrValidationFailed is called when the validation of the preferred address failed.
// The client keeps using the server's original address (section 9.6.1 of RFC 9000).
func (c *Conn) preferredAddrValidationFailed() {
	c.prefAddrMigration.state = preferredAddrFailed
	c.connIDManager.RetireConnIDForPath(preferredAddrPathID)
	if c.logger.Debug() {
		c.logger.Debugf("Validation of the server's preferred address %s failed.", c.prefAddrMigration.addr)
	}
	c.maybeStartAutoPaths()
}
