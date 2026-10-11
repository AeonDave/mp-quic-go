package quic

import (
	"net"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
)

type sender interface {
	Send(p *packetBuffer, gsoSize uint16, ecn protocol.ECN)
	// SendOnConn sends a packet using a different sendConn than the one the queue was created with.
	// It is used for the paths of IETF Multipath QUIC.
	SendOnConn(p *packetBuffer, gsoSize uint16, ecn protocol.ECN, conn sendConn)
	SendProbe(*packetBuffer, net.Addr, packetInfo)
	Run() error
	WouldBlock() bool
	Available() <-chan struct{}
	Close()
}

type queueEntry struct {
	buf     *packetBuffer
	gsoSize uint16
	ecn     protocol.ECN
	conn    sendConn // if nil, the queue's sendConn is used
}

type sendQueue struct {
	queue       chan queueEntry
	closeCalled chan struct{} // runStopped when Close() is called
	runStopped  chan struct{} // runStopped when the run loop returns
	available   chan struct{}
	conn        sendConn
	// Called when writing a packet passed to SendOnConn fails.
	// If nil, such errors are handled like errors on the queue's sendConn.
	onConnError func(sendConn, error)
}

var _ sender = &sendQueue{}

const sendQueueCapacity = 8

// newSendQueue creates a new send queue.
// Errors when writing to conn stop the queue: they are returned by Run.
// Errors when writing to another sendConn (see SendOnConn) are passed to onConnError, if set.
func newSendQueue(conn sendConn, onConnError func(sendConn, error)) sender {
	return &sendQueue{
		conn:        conn,
		onConnError: onConnError,
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
	h.enqueue(queueEntry{buf: p, gsoSize: gsoSize, ecn: ecn})
}

// SendOnConn sends out a packet using conn. It's guaranteed to not block.
// Callers need to make sure that there's actually space in the send queue by calling WouldBlock.
// Otherwise SendOnConn will panic.
func (h *sendQueue) SendOnConn(p *packetBuffer, gsoSize uint16, ecn protocol.ECN, conn sendConn) {
	h.enqueue(queueEntry{buf: p, gsoSize: gsoSize, ecn: ecn, conn: conn})
}

func (h *sendQueue) enqueue(e queueEntry) {
	select {
	case h.queue <- e:
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

func (h *sendQueue) SendProbe(p *packetBuffer, addr net.Addr, info packetInfo) {
	h.conn.WriteTo(p.Data, addr, info)
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
			if e.conn != nil {
				err = e.conn.Write(e.buf.Data, e.gsoSize, e.ecn)
				// Errors on another sendConn don't stop the queue.
				if err != nil && !isSendMsgSizeErr(err) && h.onConnError != nil {
					h.onConnError(e.conn, err)
					err = nil
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
