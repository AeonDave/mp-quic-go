package quic

import (
	"sync"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/handshake"
)

// DefaultZeroRTTReplayWindow is the window used by the ZeroRTTReplayCache of a Transport that doesn't configure one.
// A session ticket can only be used for 0-RTT during this time after it was issued.
const DefaultZeroRTTReplayWindow = 24 * time.Hour

// DefaultZeroRTTReplayCacheSize is the number of session tickets that the ZeroRTTReplayCache of a Transport that
// doesn't configure one keeps track of. Its IDs use less than 64 MB of memory.
// A server that accepts more than about 12 0-RTT handshakes per second on average over DefaultZeroRTTReplayWindow
// reaches this limit, and then rejects 0-RTT until older IDs are dropped. Such a server should configure a cache
// with a shorter window or a larger size.
const DefaultZeroRTTReplayCacheSize = 1 << 20

// A SessionTicketID identifies a session ticket issued by a server.
type SessionTicketID = handshake.SessionTicketID

// A ZeroRTTReplayCache protects a server against the replay of 0-RTT data (section 9.2 of RFC 9001):
// 0-RTT is accepted at most once for every session ticket (section 8.1 of RFC 8446).
//
// Every session ticket issued by the server contains a random ID and the time it was issued.
// When a client uses a session ticket for 0-RTT, UseTicket is called before 0-RTT is accepted.
// If UseTicket returns false, the server rejects 0-RTT, and the handshake continues as a 1-RTT handshake.
// The client then sends the data again in 1-RTT packets.
//
// The cache built into the Transport (see NewZeroRTTReplayCache) only protects the server using that Transport.
// An attacker can replay a ClientHello to every server that can decrypt the session ticket, i.e. all servers that
// share the session ticket keys of the tls.Config. Deployments with several servers should therefore use a cache
// shared by these servers.
type ZeroRTTReplayCache interface {
	// UseTicket records that the session ticket with this ID is used for 0-RTT.
	// It returns true if 0-RTT can be accepted, which must only happen once for every ID.
	// issued is the time the ticket was issued, with microsecond precision.
	// It is called concurrently by all connections of a server.
	UseTicket(id SessionTicketID, issued time.Time) bool
}

// NewZeroRTTReplayCache returns a ZeroRTTReplayCache that keeps the IDs of the session tickets used for 0-RTT in
// memory. A session ticket can be used for 0-RTT within the window after it was issued. Older session tickets
// can still be used for session resumption, but 0-RTT is rejected. IDs are kept for at least window, and at most
// 2 times the window. 0-RTT is rejected if maxTickets IDs are kept, which limits the memory used.
//
// Session tickets issued before the cache was created are not used for 0-RTT, since they might have been used for
// 0-RTT before, e.g. before the server was restarted.
func NewZeroRTTReplayCache(window time.Duration, maxTickets int) ZeroRTTReplayCache {
	return newZeroRTTReplayCache(window, maxTickets, time.Now)
}

// The zeroRTTReplayCache keeps the IDs in two generations. Every window, the current generation becomes the
// previous generation, and the previous generation is dropped. An ID is therefore kept for at least the window after
// it was recorded, and a session ticket can only be used for 0-RTT within the window after it was issued.
type zeroRTTReplayCache struct {
	window     time.Duration
	maxTickets int
	now        func() time.Time

	mx sync.Mutex
	// Tickets issued before this time are not used for 0-RTT.
	// The issue time of a ticket only has microsecond precision, so this is the creation time rounded up.
	earliestIssued time.Time
	rotated        time.Time // when the current generation was started
	current        map[SessionTicketID]struct{}
	previous       map[SessionTicketID]struct{}
	numTicket      int // the number of IDs in both generations
}

var _ ZeroRTTReplayCache = &zeroRTTReplayCache{}

func newZeroRTTReplayCache(window time.Duration, maxTickets int, now func() time.Time) *zeroRTTReplayCache {
	t := now()
	earliestIssued := t.Truncate(time.Microsecond)
	if earliestIssued.Before(t) {
		earliestIssued = earliestIssued.Add(time.Microsecond)
	}
	return &zeroRTTReplayCache{
		window:         window,
		maxTickets:     maxTickets,
		now:            now,
		earliestIssued: earliestIssued,
		rotated:        t,
		current:        make(map[SessionTicketID]struct{}),
	}
}

func (c *zeroRTTReplayCache) UseTicket(id SessionTicketID, issued time.Time) bool {
	c.mx.Lock()
	defer c.mx.Unlock()

	now := c.now()
	if issued.Before(c.earliestIssued) || issued.After(now) || now.Sub(issued) > c.window {
		return false
	}
	if d := now.Sub(c.rotated); d >= 2*c.window {
		clear(c.current)
		c.previous = nil
		c.numTicket = 0
		c.rotated = now
	} else if d >= c.window {
		c.previous = c.current
		c.current = make(map[SessionTicketID]struct{})
		c.numTicket = len(c.previous)
		c.rotated = now
	}
	if _, ok := c.current[id]; ok {
		return false
	}
	if _, ok := c.previous[id]; ok {
		return false
	}
	if c.numTicket >= c.maxTickets {
		return false
	}
	c.current[id] = struct{}{}
	c.numTicket++
	return true
}
