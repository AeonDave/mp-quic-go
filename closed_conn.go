package quic

import (
	"math/bits"
	"net"
	"sync"
	"sync/atomic"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/utils"
)

// A closedLocalConn is a connection that we closed locally.
// When receiving packets for such a connection, we need to retransmit the packet containing the CONNECTION_CLOSE frame,
// with an exponential backoff.
// The keys of the connection are dropped, so the received packets can't be authenticated. To avoid being used for an
// amplification attack, the packets sent to an address are limited to 3 times the size of the packets received from
// that address (section 10.2.1 of RFC 9000).
type closedLocalConn struct {
	counter atomic.Uint32
	logger  utils.Logger

	packetSize protocol.ByteCount

	mx    sync.Mutex
	addrs map[string]*closedConnAddr

	sendPacket func(net.Addr, packetInfo)
}

// closedConnAddr counts the bytes received from and sent to an address.
type closedConnAddr struct {
	received, sent protocol.ByteCount
}

// maxClosedConnAddrs is the number of addresses that a closedLocalConn answers.
// Packets from further addresses are dropped.
const maxClosedConnAddrs = 8

var _ packetHandler = &closedLocalConn{}

// newClosedLocalConn creates a new closedLocalConn and runs it.
// packetSize is the size of the packet containing the CONNECTION_CLOSE frame.
func newClosedLocalConn(sendPacket func(net.Addr, packetInfo), packetSize protocol.ByteCount, logger utils.Logger) packetHandler {
	return &closedLocalConn{
		sendPacket: sendPacket,
		packetSize: packetSize,
		addrs:      make(map[string]*closedConnAddr),
		logger:     logger,
	}
}

func (c *closedLocalConn) handlePacket(p receivedPacket) {
	n := c.counter.Add(1)

	c.mx.Lock()
	key := p.remoteAddr.String()
	addr, ok := c.addrs[key]
	if !ok {
		if len(c.addrs) >= maxClosedConnAddrs {
			c.mx.Unlock()
			return
		}
		addr = &closedConnAddr{}
		c.addrs[key] = addr
	}
	addr.received += p.Size()
	// exponential backoff
	// only send a CONNECTION_CLOSE for the 1st, 2nd, 4th, 8th, 16th, ... packet arriving
	if bits.OnesCount32(n) != 1 || addr.sent+c.packetSize > 3*addr.received {
		c.mx.Unlock()
		return
	}
	addr.sent += c.packetSize
	c.mx.Unlock()

	c.logger.Debugf("Received %d packets after sending CONNECTION_CLOSE. Retransmitting.", n)
	c.sendPacket(p.remoteAddr, p.info)
}

func (c *closedLocalConn) destroy(error)                              {}
func (c *closedLocalConn) closeWithTransportError(TransportErrorCode) {}

// A closedRemoteConn is a connection that was closed remotely.
// For such a connection, we might receive reordered packets that were sent before the CONNECTION_CLOSE.
// We can just ignore those packets.
type closedRemoteConn struct{}

var _ packetHandler = &closedRemoteConn{}

func newClosedRemoteConn() packetHandler {
	return &closedRemoteConn{}
}

func (c *closedRemoteConn) handlePacket(receivedPacket)                {}
func (c *closedRemoteConn) destroy(error)                              {}
func (c *closedRemoteConn) closeWithTransportError(TransportErrorCode) {}

// A greasedQUICBitClosedConn is a closed connection that sent the grease_quic_bit transport parameter (RFC 9287).
// It handles the packets with the QUIC Bit set to 0 as well.
type greasedQUICBitClosedConn struct {
	packetHandler
}

var _ greasedQUICBitAcceptor = &greasedQUICBitClosedConn{}

func (c *greasedQUICBitClosedConn) acceptsGreasedQUICBit() bool { return true }
