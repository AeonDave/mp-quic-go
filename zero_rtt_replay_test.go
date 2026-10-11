package quic

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type testClock struct{ t time.Time }

func (c *testClock) now() time.Time { return c.t }

func newTestZeroRTTReplayCache(window time.Duration, maxTickets int) (*zeroRTTReplayCache, *testClock) {
	clock := &testClock{t: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
	return newZeroRTTReplayCache(window, maxTickets, clock.now), clock
}

func ticketID(i int) SessionTicketID {
	var id SessionTicketID
	id[0], id[1], id[2] = byte(i), byte(i>>8), byte(i>>16)
	return id
}

// 0-RTT is accepted only once for every session ticket.
func TestZeroRTTReplayCacheSingleUse(t *testing.T) {
	c, clock := newTestZeroRTTReplayCache(time.Hour, 100)
	issued := clock.t
	clock.t = clock.t.Add(time.Minute)
	require.True(t, c.UseTicket(ticketID(1), issued))
	require.False(t, c.UseTicket(ticketID(1), issued))
	// the issue time doesn't matter
	require.False(t, c.UseTicket(ticketID(1), issued.Add(time.Second)))
	require.True(t, c.UseTicket(ticketID(2), issued))
}

// A session ticket can only be used for 0-RTT within the window after it was issued.
func TestZeroRTTReplayCacheWindow(t *testing.T) {
	c, clock := newTestZeroRTTReplayCache(time.Hour, 100)
	issued := clock.t
	clock.t = clock.t.Add(time.Hour + time.Millisecond)
	require.False(t, c.UseTicket(ticketID(1), issued))
	require.True(t, c.UseTicket(ticketID(2), clock.t.Add(-time.Hour)))
	// tickets issued in the future
	require.False(t, c.UseTicket(ticketID(3), clock.t.Add(time.Millisecond)))
	require.True(t, c.UseTicket(ticketID(4), clock.t))
}

// Tickets issued before the cache was created might have been used for 0-RTT before.
func TestZeroRTTReplayCacheTicketsIssuedBeforeCreation(t *testing.T) {
	c, clock := newTestZeroRTTReplayCache(time.Hour, 100)
	created := clock.t
	clock.t = clock.t.Add(time.Minute)
	require.False(t, c.UseTicket(ticketID(1), created.Add(-time.Millisecond)))
	require.True(t, c.UseTicket(ticketID(2), created))

	// The issue time only has microsecond precision.
	// A ticket issued in the microsecond that the cache was created in might have been issued before.
	clock.t = created.Add(500 * time.Nanosecond)
	c = newZeroRTTReplayCache(time.Hour, 100, clock.now)
	clock.t = clock.t.Add(time.Minute)
	require.False(t, c.UseTicket(ticketID(1), created))
	require.True(t, c.UseTicket(ticketID(2), created.Add(time.Microsecond)))
}

// IDs are kept as long as their tickets can be used for 0-RTT, and are then dropped.
func TestZeroRTTReplayCacheExpiry(t *testing.T) {
	const window = time.Hour
	c, clock := newTestZeroRTTReplayCache(window, 1000)
	// all tickets are issued after the cache was created
	start := clock.t.Add(window)

	// Every step, a ticket that was issued half a window ago is used for 0-RTT.
	// Replays of all tickets that are not too old are detected.
	issueTime := func(i int) time.Time { return start.Add(time.Duration(i)*window/25 - window/2) }
	var replaysChecked int
	for i := range 100 {
		clock.t = start.Add(time.Duration(i) * window / 25)
		require.True(t, c.UseTicket(ticketID(i), issueTime(i)), "ticket %d", i)
		for j := 0; j <= i; j++ {
			if clock.t.Sub(issueTime(j)) > window {
				continue
			}
			replaysChecked++
			require.False(t, c.UseTicket(ticketID(j), issueTime(j)), "replay of ticket %d", j)
		}
		// IDs are kept for at most 2 windows
		require.LessOrEqual(t, c.numTicket, 2*25+1)
		require.Equal(t, len(c.current)+len(c.previous), c.numTicket)
	}
	require.Greater(t, replaysChecked, 1000)

	// once no tickets are used for 2 windows, all IDs are dropped
	clock.t = clock.t.Add(2 * window)
	require.True(t, c.UseTicket(ticketID(1000), clock.t))
	require.Equal(t, 1, c.numTicket)
	require.Len(t, c.current, 1)
	require.Empty(t, c.previous)
}

// The number of IDs kept is limited. Once the limit is reached, 0-RTT is rejected.
func TestZeroRTTReplayCacheLimit(t *testing.T) {
	const window = time.Hour
	c, clock := newTestZeroRTTReplayCache(window, 10)
	issued := clock.t
	for i := range 10 {
		require.True(t, c.UseTicket(ticketID(i), issued))
	}
	require.False(t, c.UseTicket(ticketID(10), issued))

	// after one window, the IDs are still kept
	clock.t = clock.t.Add(window)
	require.False(t, c.UseTicket(ticketID(11), clock.t))
	// after two windows, they are dropped
	clock.t = clock.t.Add(window)
	require.True(t, c.UseTicket(ticketID(12), clock.t))
}

func TestZeroRTTReplayCacheConcurrentUse(t *testing.T) {
	c, clock := newTestZeroRTTReplayCache(time.Hour, 1000)
	issued := clock.t
	clock.t = clock.t.Add(time.Second)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if c.UseTicket(ticketID(42), issued) {
				accepted.Add(1)
			}
		})
	}
	wg.Wait()
	require.Equal(t, int32(1), accepted.Load())
}

// Listeners that don't configure a cache use the default cache of their Transport.
func TestTransportDefaultZeroRTTReplayCache(t *testing.T) {
	tr := &Transport{Conn: newUDPConnLocalhost(t)}
	defer tr.Close()
	ln, err := tr.ListenEarly(generateTLSConfig(), &Config{Allow0RTT: true})
	require.NoError(t, err)
	cache := ln.baseServer.config.zeroRTTReplayCache
	require.NotNil(t, cache)
	require.NoError(t, ln.Close())
	ln, err = tr.ListenEarly(generateTLSConfig(), &Config{Allow0RTT: true})
	require.NoError(t, err)
	defer ln.Close()
	require.Same(t, cache, ln.baseServer.config.zeroRTTReplayCache)

	// a configured cache is used
	cache2 := NewZeroRTTReplayCache(time.Minute, 10)
	tr2 := &Transport{Conn: newUDPConnLocalhost(t)}
	defer tr2.Close()
	ln2, err := tr2.ListenEarly(generateTLSConfig(), &Config{Allow0RTT: true, ZeroRTTReplayCache: cache2})
	require.NoError(t, err)
	defer ln2.Close()
	require.Same(t, cache2, ln2.baseServer.config.zeroRTTReplayCache)
}
