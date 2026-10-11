package self_test

import (
	"context"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	quic "github.com/AeonDave/mp-quic-go"

	"github.com/stretchr/testify/require"
)

// Stream Resets with Partial Delivery (draft-ietf-quic-reliable-stream-reset-11):
// the data written before SetReliableBoundary is delivered, even though the stream is reset.
func TestResetStreamAt(t *testing.T) {
	t.Run("reliable data in flight", func(t *testing.T) {
		testResetStreamAt(t, nil, 10_000, 6_000)
	})
	// The final size of the RESET_STREAM_AT frame is subject to flow control (section 4 of the draft):
	// the reliable data that wasn't sent yet needs to fit into the flow control windows of the receiver.
	t.Run("stream flow control", func(t *testing.T) {
		testResetStreamAt(t, &quic.Config{InitialStreamReceiveWindow: 500}, 1_200, 1_200)
	})
	t.Run("connection flow control", func(t *testing.T) {
		testResetStreamAt(t, &quic.Config{InitialConnectionReceiveWindow: 500}, 1_200, 1_200)
	})
}

func testResetStreamAt(t *testing.T, serverConf *quic.Config, dataLen, reliableSize int) {
	synctest.Test(t, func(t *testing.T) {
		clientPacketConn, serverPacketConn, closeFn := newSimnetLink(t, 10*time.Millisecond)
		defer closeFn(t)

		if serverConf == nil {
			serverConf = &quic.Config{}
		}
		serverConf.EnableStreamResetPartialDelivery = true
		ln, err := quic.Listen(serverPacketConn, getTLSConfig(), getQuicConfig(serverConf))
		require.NoError(t, err)
		defer ln.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := quic.Dial(
			ctx,
			clientPacketConn,
			serverPacketConn.LocalAddr().(*net.UDPAddr),
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{EnableStreamResetPartialDelivery: true}),
		)
		require.NoError(t, err)
		defer conn.CloseWithError(0, "")
		serverConn, err := ln.Accept(ctx)
		require.NoError(t, err)
		defer serverConn.CloseWithError(0, "")

		require.True(t, conn.ConnectionState().SupportsStreamResetPartialDelivery.Local)
		require.True(t, conn.ConnectionState().SupportsStreamResetPartialDelivery.Remote)
		require.True(t, serverConn.ConnectionState().SupportsStreamResetPartialDelivery.Local)
		require.True(t, serverConn.ConnectionState().SupportsStreamResetPartialDelivery.Remote)

		data := GeneratePRData(dataLen)
		str, err := conn.OpenUniStream()
		require.NoError(t, err)
		errChan := make(chan error, 1)
		go func() {
			if _, err := str.Write(data[:reliableSize]); err != nil {
				errChan <- err
				return
			}
			str.SetReliableBoundary()
			if _, err := str.Write(data[reliableSize:]); err != nil {
				errChan <- err
				return
			}
			str.CancelWrite(42)
			errChan <- nil
		}()

		serverStr, err := serverConn.AcceptUniStream(ctx)
		require.NoError(t, err)
		received, err := io.ReadAll(serverStr)
		require.ErrorIs(t, err, &quic.StreamError{StreamID: str.StreamID(), ErrorCode: 42, Remote: true})
		require.GreaterOrEqual(t, len(received), reliableSize)
		require.Equal(t, data[:len(received)], received)
		require.NoError(t, <-errChan)

		// the connection is still alive
		select {
		case <-conn.Context().Done():
			t.Fatalf("connection closed: %v", context.Cause(conn.Context()))
		case <-serverConn.Context().Done():
			t.Fatalf("connection closed: %v", context.Cause(serverConn.Context()))
		default:
		}
	})
}
