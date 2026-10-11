package self_test

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	quic "github.com/AeonDave/mp-quic-go"
	"github.com/AeonDave/mp-quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
)

// quicBitCounter counts the datagrams sent in each direction, and the datagrams whose first packet has the QUIC Bit
// set to 0.
type quicBitCounter struct {
	mx sync.Mutex

	clientAddr net.Addr
	// the first byte of the first datagram sent by the client
	firstClientByte    byte
	toServer, toClient int
	greasedToServer    int
	greasedToClient    int
}

func (c *quicBitCounter) record(p simnet.Packet) {
	c.mx.Lock()
	defer c.mx.Unlock()

	greased := p.Data[0]&0x40 == 0
	if p.From.String() == c.clientAddr.String() {
		if c.toServer == 0 {
			c.firstClientByte = p.Data[0]
		}
		c.toServer++
		if greased {
			c.greasedToServer++
		}
		return
	}
	c.toClient++
	if greased {
		c.greasedToClient++
	}
}

// Greasing the QUIC Bit (RFC 9287): the QUIC Bit is set to a random value in the packets sent once both endpoints
// sent the grease_quic_bit transport parameter. Otherwise, it is always set.
func TestGreaseQUICBit(t *testing.T) {
	for _, tc := range []struct {
		name                           string
		clientGreasing, serverGreasing bool
		zeroLengthClientConnID         bool
	}{
		{name: "both endpoints", clientGreasing: true, serverGreasing: true},
		{name: "both endpoints, zero-length connection ID", clientGreasing: true, serverGreasing: true, zeroLengthClientConnID: true},
		{name: "only the client", clientGreasing: true},
		{name: "only the server", serverGreasing: true},
		{name: "neither endpoint"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testGreaseQUICBit(t, tc.clientGreasing, tc.serverGreasing, tc.zeroLengthClientConnID)
		})
	}
}

func testGreaseQUICBit(t *testing.T, clientGreasing, serverGreasing, zeroLengthClientConnID bool) {
	synctest.Test(t, func(t *testing.T) {
		counter := &quicBitCounter{}
		router := &callbackRouter{Router: &simnet.PerfectRouter{}, OnSendPacket: counter.record}
		clientPacketConn, serverPacketConn, closeFn := newSimnetLinkWithRouter(t, 10*time.Millisecond, router)
		defer closeFn(t)
		counter.clientAddr = clientPacketConn.LocalAddr()

		ln, err := quic.Listen(serverPacketConn, getTLSConfig(), getQuicConfig(&quic.Config{EnableQUICBitGreasing: serverGreasing}))
		require.NoError(t, err)
		defer ln.Close()

		tr := &quic.Transport{Conn: clientPacketConn}
		if zeroLengthClientConnID {
			tr.ConnectionIDLength = 0
		} else {
			tr.ConnectionIDLength = 8
		}
		defer tr.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := tr.Dial(
			ctx,
			serverPacketConn.LocalAddr(),
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{EnableQUICBitGreasing: clientGreasing}),
		)
		require.NoError(t, err)
		defer conn.CloseWithError(0, "")
		serverConn, err := ln.Accept(ctx)
		require.NoError(t, err)
		defer serverConn.CloseWithError(0, "")

		require.Equal(t, clientGreasing, conn.ConnectionState().SupportsQUICBitGreasing.Local)
		require.Equal(t, serverGreasing, conn.ConnectionState().SupportsQUICBitGreasing.Remote)
		require.Equal(t, serverGreasing, serverConn.ConnectionState().SupportsQUICBitGreasing.Local)
		require.Equal(t, clientGreasing, serverConn.ConnectionState().SupportsQUICBitGreasing.Remote)

		// transfer data in both directions
		data := GeneratePRData(50 << 10)
		errChan := make(chan error, 2)
		go func() {
			str, err := conn.OpenUniStream()
			if err != nil {
				errChan <- err
				return
			}
			if _, err := str.Write(data); err != nil {
				errChan <- err
				return
			}
			errChan <- str.Close()
		}()
		go func() {
			str, err := serverConn.OpenUniStream()
			if err != nil {
				errChan <- err
				return
			}
			if _, err := str.Write(data); err != nil {
				errChan <- err
				return
			}
			errChan <- str.Close()
		}()
		serverStr, err := serverConn.AcceptUniStream(ctx)
		require.NoError(t, err)
		received, err := io.ReadAll(serverStr)
		require.NoError(t, err)
		require.Equal(t, data, received)
		clientStr, err := conn.AcceptUniStream(ctx)
		require.NoError(t, err)
		received, err = io.ReadAll(clientStr)
		require.NoError(t, err)
		require.Equal(t, data, received)
		require.NoError(t, <-errChan)
		require.NoError(t, <-errChan)
		// No packet was lost: the endpoints accepted all packets with the QUIC Bit set to 0.
		require.Zero(t, conn.ConnectionStats().PacketsLost)
		require.Zero(t, serverConn.ConnectionStats().PacketsLost)

		counter.mx.Lock()
		defer counter.mx.Unlock()
		t.Logf("to server: %d datagrams (%d greased), to client: %d datagrams (%d greased)",
			counter.toServer, counter.greasedToServer, counter.toClient, counter.greasedToClient)
		// The client doesn't grease its first Initial packet: it hasn't received the server's transport parameters.
		require.NotZero(t, counter.firstClientByte&0x40)
		if clientGreasing && serverGreasing {
			require.NotZero(t, counter.greasedToServer)
			require.Less(t, counter.greasedToServer, counter.toServer)
			require.NotZero(t, counter.greasedToClient)
			require.Less(t, counter.greasedToClient, counter.toClient)
		} else {
			require.Zero(t, counter.greasedToServer)
			require.Zero(t, counter.greasedToClient)
		}
	})
}
