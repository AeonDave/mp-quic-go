package quic

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/utils"
)

// MultiSocketManager manages multiple UDP sockets for multipath and hot-plug scenarios.
// It implements both net.PacketConn and rawConn, and can be used as Transport.Conn.
type MultiSocketManager struct {
	mu sync.RWMutex

	baseConn    net.PacketConn
	baseRawConn rawConn
	createdBase bool

	listenPort int

	conns map[string]*managedSocket

	recvPackets chan receivedPacket
	readErrs    chan error

	closeOnce sync.Once
	closeCh   chan struct{}
	closedCh  chan struct{}

	refreshInterval time.Duration
	includeLoopback bool
	allowIPv6       bool

	logger utils.Logger
}

type managedSocket struct {
	conn      net.PacketConn
	rawConn   rawConn
	localIP   netip.Addr
	localAddr *net.UDPAddr
}

// MultiSocketManagerConfig controls MultiSocketManager behavior.
type MultiSocketManagerConfig struct {
	// BaseConn is the primary socket. If nil, a UDP socket is opened on 0.0.0.0:0.
	BaseConn net.PacketConn
	// ListenPort is the port to bind new sockets to. 0 uses an ephemeral port.
	ListenPort int
	// LocalAddrs are the local IPs to bind new sockets to.
	LocalAddrs []net.IP
	// RefreshInterval enables periodic interface refresh. 0 disables it.
	RefreshInterval time.Duration
	// IncludeLoopback enables loopback interface addresses in refresh.
	IncludeLoopback bool
	// AllowIPv6 enables IPv6 addresses in refresh.
	AllowIPv6 bool
	// Logger defaults to utils.DefaultLogger if nil.
	Logger utils.Logger
}

// NewMultiSocketManager creates a MultiSocketManager.
func NewMultiSocketManager(cfg MultiSocketManagerConfig) (*MultiSocketManager, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = utils.DefaultLogger
	}

	base := cfg.BaseConn
	created := false
	if base == nil {
		udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			return nil, err
		}
		base = udp
		created = true
	}

	raw, err := wrapConn(base)
	if err != nil {
		if created {
			_ = base.Close()
		}
		return nil, err
	}

	m := &MultiSocketManager{
		baseConn:        base,
		baseRawConn:     raw,
		createdBase:     created,
		listenPort:      cfg.ListenPort,
		conns:           make(map[string]*managedSocket),
		recvPackets:     make(chan receivedPacket, 32),
		readErrs:        make(chan error, 4),
		closeCh:         make(chan struct{}),
		closedCh:        make(chan struct{}),
		refreshInterval: cfg.RefreshInterval,
		includeLoopback: cfg.IncludeLoopback,
		allowIPv6:       cfg.AllowIPv6,
		logger:          logger,
	}

	m.startReader(raw, m.baseConn.LocalAddr())

	if len(cfg.LocalAddrs) > 0 {
		if err := m.SetLocalAddrs(cfg.LocalAddrs); err != nil {
			_ = m.Close()
			return nil, err
		}
	}

	if cfg.RefreshInterval > 0 {
		go m.refreshLoop(cfg.RefreshInterval)
	}

	return m, nil
}

// AddLocalAddr adds a new UDP socket bound to the given local IP.
func (m *MultiSocketManager) AddLocalAddr(ip net.IP) (*net.UDPAddr, error) {
	addr, ok := normalizeIP(ip, m.allowIPv6)
	if !ok {
		return nil, errors.New("invalid local IP")
	}
	key := addr.String()

	m.mu.Lock()
	if _, exists := m.conns[key]; exists {
		existing := m.conns[key].localAddr
		m.mu.Unlock()
		return existing, nil
	}
	m.mu.Unlock()

	udpAddr := &net.UDPAddr{IP: addr.AsSlice(), Port: m.listenPort}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	raw, err := wrapConn(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	local := conn.LocalAddr().(*net.UDPAddr)
	socket := &managedSocket{
		conn:      conn,
		rawConn:   raw,
		localIP:   addr,
		localAddr: local,
	}

	m.mu.Lock()
	m.conns[key] = socket
	m.mu.Unlock()

	m.startReader(raw, local)
	return local, nil
}

// RemoveLocalAddr removes and closes a socket bound to the given local IP.
func (m *MultiSocketManager) RemoveLocalAddr(ip net.IP) bool {
	addr, ok := normalizeIP(ip, m.allowIPv6)
	if !ok {
		return false
	}
	key := addr.String()

	m.mu.Lock()
	socket, exists := m.conns[key]
	if exists {
		delete(m.conns, key)
	}
	m.mu.Unlock()

	if !exists {
		return false
	}
	_ = socket.conn.Close()
	return true
}

// SetLocalAddrs synchronizes the managed sockets with the provided IP list.
func (m *MultiSocketManager) SetLocalAddrs(addrs []net.IP) error {
	want := make(map[string]net.IP, len(addrs))
	for _, ip := range addrs {
		addr, ok := normalizeIP(ip, m.allowIPv6)
		if !ok {
			continue
		}
		want[addr.String()] = addr.AsSlice()
	}

	var toRemove []net.IP
	m.mu.RLock()
	for key, socket := range m.conns {
		if _, ok := want[key]; !ok {
			toRemove = append(toRemove, socket.localIP.AsSlice())
		}
	}
	m.mu.RUnlock()

	for key, ip := range want {
		m.mu.RLock()
		_, exists := m.conns[key]
		m.mu.RUnlock()
		if !exists {
			if _, err := m.AddLocalAddr(ip); err != nil {
				return err
			}
		}
	}
	for _, ip := range toRemove {
		m.RemoveLocalAddr(ip)
	}
	return nil
}

// LocalAddrs returns the list of managed local IPs.
func (m *MultiSocketManager) LocalAddrs() []net.IP {
	m.mu.RLock()
	defer m.mu.RUnlock()
	addrs := make([]net.IP, 0, len(m.conns))
	for _, socket := range m.conns {
		addrs = append(addrs, socket.localIP.AsSlice())
	}
	return addrs
}

// RefreshInterfaces scans system interfaces and syncs sockets.
func (m *MultiSocketManager) RefreshInterfaces() error {
	addrs, err := interfaceAddrs(m.includeLoopback, m.allowIPv6)
	if err != nil {
		return err
	}
	return m.SetLocalAddrs(addrs)
}

func (m *MultiSocketManager) refreshLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := m.RefreshInterfaces(); err != nil {
				m.logger.Debugf("multi-socket refresh error: %s", err)
			}
		case <-m.closeCh:
			return
		}
	}
}

func (m *MultiSocketManager) startReader(conn rawConn, local net.Addr) {
	go func() {
		for {
			p, err := conn.ReadPacket()
			if err != nil {
				select {
				case m.readErrs <- err:
				default:
				}
				return
			}
			if !p.info.addr.IsValid() {
				if udp, ok := local.(*net.UDPAddr); ok {
					if addr, ok := netip.AddrFromSlice(udp.IP); ok {
						p.info.addr = addr
					}
				}
			}
			select {
			case m.recvPackets <- p:
			case <-m.closeCh:
				if p.buffer != nil {
					p.buffer.MaybeRelease()
				}
				return
			}
		}
	}()
}

func (m *MultiSocketManager) ReadPacket() (receivedPacket, error) {
	select {
	case p := <-m.recvPackets:
		return p, nil
	case err := <-m.readErrs:
		return receivedPacket{}, err
	case <-m.closedCh:
		return receivedPacket{}, net.ErrClosed
	}
}

func (m *MultiSocketManager) WritePacket(b []byte, addr net.Addr, packetInfoOOB []byte, gsoSize uint16, ecn protocol.ECN) (int, error) {
	// If no explicit packet info is provided, try to derive it from the destination address.
	// This is important for multipath: the MultiSocketManager selects the socket to send from
	// based on the packetInfo.addr.
	if len(packetInfoOOB) == 0 {
		if udp, ok := addr.(*net.UDPAddr); ok {
			var info packetInfo
			if parsed, ok := netip.AddrFromSlice(udp.IP); ok {
				info.addr = parsed.Unmap()
				packetInfoOOB = info.OOB()
			}
		}
	}
	return m.baseRawConn.WritePacket(b, addr, packetInfoOOB, gsoSize, ecn)
}

func (m *MultiSocketManager) WritePacketWithInfo(b []byte, addr net.Addr, info packetInfo, gsoSize uint16, ecn protocol.ECN) (int, error) {
	if info.addr.IsValid() {
		key := info.addr.String()
		m.mu.RLock()
		socket := m.conns[key]
		m.mu.RUnlock()
		if socket != nil {
			return socket.rawConn.WritePacket(b, addr, info.OOB(), gsoSize, ecn)
		}
	}
	return m.baseRawConn.WritePacket(b, addr, info.OOB(), gsoSize, ecn)
}

func (m *MultiSocketManager) LocalAddr() net.Addr { return m.baseConn.LocalAddr() }

func (m *MultiSocketManager) SetReadDeadline(t time.Time) error {
	err := m.baseConn.SetReadDeadline(t)
	m.mu.RLock()
	for _, socket := range m.conns {
		if e := socket.conn.SetReadDeadline(t); e != nil && err == nil {
			err = e
		}
	}
	m.mu.RUnlock()
	return err
}

func (m *MultiSocketManager) Close() error {
	var err error
	m.closeOnce.Do(func() {
		close(m.closeCh)
		if e := m.baseConn.Close(); e != nil {
			err = e
		}
		m.mu.RLock()
		for _, socket := range m.conns {
			_ = socket.conn.Close()
		}
		m.mu.RUnlock()
		close(m.closedCh)
	})
	return err
}

func (m *MultiSocketManager) capabilities() connCapabilities {
	return m.baseRawConn.capabilities()
}

// net.PacketConn compatibility.
func (m *MultiSocketManager) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	p, err := m.ReadPacket()
	if err != nil {
		return 0, nil, err
	}
	n = copy(b, p.data)
	addr = p.remoteAddr
	if p.buffer != nil {
		p.buffer.Release()
	}
	return n, addr, nil
}

func (m *MultiSocketManager) WriteTo(b []byte, addr net.Addr) (int, error) {
	// Prefer going through WritePacket so we can apply the same destination-based
	// packetInfo selection logic (important for multipath / multi-socket setups).
	return m.WritePacket(b, addr, nil, 0, protocol.ECNUnsupported)
}

func (m *MultiSocketManager) SetDeadline(t time.Time) error {
	if err := m.SetReadDeadline(t); err != nil {
		return err
	}
	return m.baseConn.SetWriteDeadline(t)
}

func (m *MultiSocketManager) SetWriteDeadline(t time.Time) error {
	return m.baseConn.SetWriteDeadline(t)
}

func normalizeIP(ip net.IP, allowIPv6 bool) (netip.Addr, bool) {
	if ip == nil {
		return netip.Addr{}, false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	addr = addr.Unmap()
	if addr.Is6() && !allowIPv6 {
		return netip.Addr{}, false
	}
	return addr, true
}

func interfaceAddrs(includeLoopback bool, allowIPv6 bool) ([]net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var addrs []net.IP
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if !includeLoopback && iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		ifAddrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range ifAddrs {
			var ip net.IP
			switch a := addr.(type) {
			case *net.IPNet:
				ip = a.IP
			case *net.IPAddr:
				ip = a.IP
			}
			if ip == nil {
				continue
			}
			parsed, ok := normalizeIP(ip, allowIPv6)
			if !ok {
				continue
			}
			if parsed.IsUnspecified() {
				continue
			}
			addrs = append(addrs, parsed.AsSlice())
		}
	}
	return addrs, nil
}
