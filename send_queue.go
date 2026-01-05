package quic

import (
	"fmt"
	"net"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
)

type sender interface {
	Send(p *packetBuffer, gsoSize uint16, ecn protocol.ECN)
	SendProbe(*packetBuffer, net.Addr)
	Run() error
	WouldBlock() bool
	Available() <-chan struct{}
	Close()
}

type pathSender interface {
	WritePath(b []byte, gsoSize uint16, ecn protocol.ECN, addr net.Addr, info packetInfo) error
}

type queueEntry struct {
	buf     *packetBuffer
	gsoSize uint16
	ecn     protocol.ECN
	addr    net.Addr
	info    packetInfo
}

type sendQueue struct {
	queue       chan queueEntry
	closeCalled chan struct{} // runStopped when Close() is called
	runStopped  chan struct{} // runStopped when the run loop returns
	available   chan struct{}
	conn        sendConn
}

var _ sender = &sendQueue{}

const sendQueueCapacity = 8

func newSendQueue(conn sendConn) sender {
	return &sendQueue{
		conn:        conn,
		runStopped:  make(chan struct{}),
		closeCalled: make(chan struct{}),
		available:   make(chan struct{}, 1),
		queue:       make(chan queueEntry, sendQueueCapacity),
	}
}

// Send sends out a packet. It's guaranteed to not block.
// Callers need to make sure that there's actually space in the send queue by calling WouldBlock.
// Otherwise Send will panic.
func (h *sendQueue) Send(p *packetBuffer, gsoSize uint16, ecn protocol.ECN) {
	h.SendPath(p, gsoSize, ecn, nil, packetInfo{})
}

// SendPath sends out a packet on a specific path. It's guaranteed to not block.
// Callers need to make sure that there's actually space in the send queue by calling WouldBlock.
// Otherwise SendPath will panic.
func (h *sendQueue) SendPath(p *packetBuffer, gsoSize uint16, ecn protocol.ECN, addr net.Addr, info packetInfo) {
	select {
	case h.queue <- queueEntry{buf: p, gsoSize: gsoSize, ecn: ecn, addr: addr, info: info}:
		// clear available channel if we've reached capacity
		if len(h.queue) == sendQueueCapacity {
			select {
			case <-h.available:
			default:
			}
		}
	case <-h.runStopped:
	default:
		panic("sendQueue.Send would have blocked")
	}
}

func (h *sendQueue) SendProbe(p *packetBuffer, addr net.Addr) {
	h.conn.WriteTo(p.Data, addr)
}

func (h *sendQueue) WouldBlock() bool {
	return len(h.queue) == sendQueueCapacity
}

func (h *sendQueue) Available() <-chan struct{} {
	return h.available
}

func (h *sendQueue) Run() error {
	defer close(h.runStopped)
	var shouldClose bool
	for {
		if shouldClose && len(h.queue) == 0 {
			return nil
		}
		select {
		case <-h.closeCalled:
			h.closeCalled = nil // prevent this case from being selected again
			// make sure that all queued packets are actually sent out
			shouldClose = true
		case e := <-h.queue:
			var err error
			if e.addr != nil {
				if ps, ok := h.conn.(pathSender); ok {
					err = ps.WritePath(e.buf.Data, e.gsoSize, e.ecn, e.addr, e.info)
				} else if e.gsoSize == 0 && (e.ecn == protocol.ECNNon || e.ecn == protocol.ECNUnsupported) {
					err = h.conn.WriteTo(e.buf.Data, e.addr)
				} else {
					err = fmt.Errorf("sendQueue: path send unsupported")
				}
			} else {
				err = h.conn.Write(e.buf.Data, e.gsoSize, e.ecn)
			}
			if err != nil {
				// This additional check enables:
				// 1. Checking for "datagram too large" message from the kernel, as such,
				// 2. Path MTU discovery,and
				// 3. Eventual detection of loss PingFrame.
				if !isSendMsgSizeErr(err) {
					return err
				}
			}
			e.buf.Release()
			select {
			case h.available <- struct{}{}:
			default:
			}
		}
	}
}

func (h *sendQueue) Close() {
	close(h.closeCalled)
	// wait until the run loop returned
	<-h.runStopped
}
