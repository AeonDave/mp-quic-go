package quic

import (
	"net"
	"testing"

	"github.com/AeonDave/mp-quic-go/internal/utils"

	"github.com/stretchr/testify/require"
)

func TestClosedLocalConnection(t *testing.T) {
	written := make(chan net.Addr, 1)
	conn := newClosedLocalConn(func(addr net.Addr, _ packetInfo) { written <- addr }, 100, utils.DefaultLogger)
	addr := &net.UDPAddr{IP: net.IPv4(127, 1, 2, 3), Port: 1337}
	for i := 1; i <= 20; i++ {
		conn.handlePacket(receivedPacket{remoteAddr: addr, data: make([]byte, 100)})
		if i == 1 || i == 2 || i == 4 || i == 8 || i == 16 {
			select {
			case gotAddr := <-written:
				require.Equal(t, addr, gotAddr) // receive the CONNECTION_CLOSE
			default:
				t.Fatal("expected to receive address")
			}
		} else {
			select {
			case gotAddr := <-written:
				t.Fatalf("unexpected address received: %v", gotAddr)
			default:
				// Nothing received, which is expected
			}
		}
	}
}

// The packets sent to an address are limited to 3 times the size of the packets received from that address
// (section 10.2.1 of RFC 9000).
func TestClosedLocalConnectionAmplificationLimit(t *testing.T) {
	var written []net.Addr
	conn := newClosedLocalConn(func(addr net.Addr, _ packetInfo) { written = append(written, addr) }, 100, utils.DefaultLogger)
	addr1 := &net.UDPAddr{IP: net.IPv4(127, 1, 2, 3), Port: 1337}
	addr2 := &net.UDPAddr{IP: net.IPv4(127, 1, 2, 3), Port: 1338}

	// packets 1 and 2 are not answered: 3 times 10 and 20 bytes is less than 100 bytes
	for range 2 {
		conn.handlePacket(receivedPacket{remoteAddr: addr1, data: make([]byte, 10)})
	}
	require.Empty(t, written)
	// packet 4 is answered: 3 times 40 bytes allow sending 100 bytes
	conn.handlePacket(receivedPacket{remoteAddr: addr1, data: make([]byte, 10)})
	require.Empty(t, written)
	conn.handlePacket(receivedPacket{remoteAddr: addr1, data: make([]byte, 10)})
	require.Equal(t, []net.Addr{addr1}, written)
	written = written[:0]

	// Packet 8 is answered, if the budget of its address allows it.
	// The bytes received from addr1 don't count for addr2.
	for range 3 {
		conn.handlePacket(receivedPacket{remoteAddr: addr1, data: make([]byte, 10)})
	}
	conn.handlePacket(receivedPacket{remoteAddr: addr2, data: make([]byte, 10)})
	require.Empty(t, written)
	for range 7 {
		conn.handlePacket(receivedPacket{remoteAddr: addr2, data: make([]byte, 50)})
	}
	// packet 16 is sent to addr2: 3 times 410 bytes allow sending 100 bytes
	conn.handlePacket(receivedPacket{remoteAddr: addr2, data: make([]byte, 50)})
	require.Equal(t, []net.Addr{addr2}, written)
}

func TestClosedLocalConnectionMaxAddrs(t *testing.T) {
	var written []net.Addr
	conn := newClosedLocalConn(func(addr net.Addr, _ packetInfo) { written = append(written, addr) }, 10, utils.DefaultLogger)
	for i := range maxClosedConnAddrs {
		conn.handlePacket(receivedPacket{
			remoteAddr: &net.UDPAddr{IP: net.IPv4(127, 1, 2, 3), Port: 1000 + i},
			data:       make([]byte, 100),
		})
	}
	// only the 1st, 2nd, 4th and 8th packets are answered
	require.Len(t, written, 4)

	// packets from further addresses are dropped
	written = written[:0]
	for range 8 {
		conn.handlePacket(receivedPacket{
			remoteAddr: &net.UDPAddr{IP: net.IPv4(127, 1, 2, 3), Port: 2000},
			data:       make([]byte, 100),
		})
	}
	require.Empty(t, written)
}
