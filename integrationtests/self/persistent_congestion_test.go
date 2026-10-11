package self_test

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	quic "github.com/AeonDave/mp-quic-go"
	"github.com/AeonDave/mp-quic-go/internal/wire"
	"github.com/AeonDave/mp-quic-go/qlog"
	"github.com/AeonDave/mp-quic-go/testutils/events"
	"github.com/AeonDave/mp-quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
)

// When all packets are lost for a long time, the sender establishes persistent congestion
// (section 7.6 of RFC 9002), and reduces its congestion window to the minimum window.
// A short loss episode doesn't establish persistent congestion.
func TestPersistentCongestion(t *testing.T) {
	t.Run("outage", func(t *testing.T) {
		testPersistentCongestion(t, time.Second, true)
	})
	t.Run("short loss episode", func(t *testing.T) {
		testPersistentCongestion(t, 5*time.Millisecond, false)
	})
}

func testPersistentCongestion(t *testing.T, dropDuration time.Duration, expectPersistentCongestion bool) {
	synctest.Test(t, func(t *testing.T) {
		const rtt = 10 * time.Millisecond
		const numMessages = 300
		const messageSize = 4 << 10
		const messageInterval = 10 * time.Millisecond

		// The packets in both directions are dropped for dropDuration, once the transfer is underway.
		var dropStart atomic.Int64
		var numDropped atomic.Int32
		router := &droppingRouter{Drop: func(p simnet.Packet) bool {
			if wire.IsLongHeaderPacket(p.Data[0]) { // don't interfere with the handshake
				return false
			}
			start := dropStart.Load()
			if start == 0 {
				return false
			}
			now := time.Now().UnixNano()
			drop := now >= start && now < start+int64(dropDuration)
			if drop {
				numDropped.Add(1)
			}
			return drop
		}}
		clientPacketConn, serverPacketConn, closeFn := newSimnetLinkWithRouter(t, rtt, router)
		defer closeFn(t)

		var serverEvents events.Recorder
		ln, err := quic.Listen(serverPacketConn, getTLSConfig(), getQuicConfig(&quic.Config{Tracer: newTracer(&serverEvents)}))
		require.NoError(t, err)
		defer ln.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := quic.Dial(ctx, clientPacketConn, serverPacketConn.LocalAddr().(*net.UDPAddr), getTLSClientConfig(), getQuicConfig(nil))
		require.NoError(t, err)
		defer conn.CloseWithError(0, "")
		serverConn, err := ln.Accept(ctx)
		require.NoError(t, err)
		defer serverConn.CloseWithError(0, "")

		// The server sends a message at regular intervals, as an application would.
		data := GeneratePRData(numMessages * messageSize)
		errChan := make(chan error, 1)
		go func() {
			str, err := serverConn.OpenUniStream()
			if err != nil {
				errChan <- err
				return
			}
			for i := range numMessages {
				if i == numMessages/4 {
					dropStart.Store(time.Now().UnixNano())
				}
				if _, err := str.Write(data[i*messageSize : (i+1)*messageSize]); err != nil {
					errChan <- err
					return
				}
				time.Sleep(messageInterval)
			}
			errChan <- str.Close()
		}()

		str, err := conn.AcceptUniStream(ctx)
		require.NoError(t, err)
		received, err := io.ReadAll(str)
		require.NoError(t, err)
		require.Equal(t, data, received)
		require.NoError(t, <-errChan)
		require.NotZero(t, numDropped.Load())
		t.Logf("dropped %d packets", numDropped.Load())

		require.NotEmpty(t, serverEvents.Events(qlog.PacketLost{}))
		var persistentCongestion int
		for _, ev := range serverEvents.Events(qlog.CongestionStateUpdated{}) {
			if ev.(qlog.CongestionStateUpdated).Trigger == qlog.CongestionStateTriggerPersistentCongestion {
				persistentCongestion++
			}
		}
		if expectPersistentCongestion {
			require.Equal(t, 1, persistentCongestion)
		} else {
			require.Zero(t, persistentCongestion)
		}
	})
}
