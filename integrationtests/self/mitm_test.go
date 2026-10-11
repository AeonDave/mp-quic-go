package self_test

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"math"
	mrand "math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/AeonDave/mp-quic-go"
	quicproxy "github.com/AeonDave/mp-quic-go/integrationtests/tools/proxy"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/wire"
	"github.com/AeonDave/mp-quic-go/testutils"

	"github.com/stretchr/testify/require"
)

const mitmTestConnIDLen = 6

// A mitmInjector injects packets into a connection established through a proxy.
// The client discards packets from server addresses other than the one it sends its packets to (section 9 of
// RFC 9000), so packets towards the client are sent from the proxy's socket. Packets towards the server that
// would make the server migrate to the client's address are sent through the proxy as well.
type mitmInjector struct {
	// the proxy's socket, which the client sends its packets to
	proxyConn *net.UDPConn
	// packets sent through the proxy, which the proxy's callbacks forward unchanged
	injected sync.Map
}

func newMITMInjector(t *testing.T) *mitmInjector {
	return &mitmInjector{proxyConn: newUDPConnLocalhost(t)}
}

// toClient sends a packet to the client, from the address that the client sends its packets to.
func (m *mitmInjector) toClient(b []byte, clientTransport *quic.Transport) error {
	_, err := m.proxyConn.WriteTo(b, clientTransport.Conn.LocalAddr())
	return err
}

// toServerViaProxy sends a packet from the client's address to the proxy, which forwards it to the server.
func (m *mitmInjector) toServerViaProxy(b []byte, clientTransport *quic.Transport) {
	m.injected.Store(string(b), struct{}{})
	clientTransport.WriteTo(b, m.proxyConn.LocalAddr())
}

// wasInjected says if a packet seen by the proxy was sent by toServerViaProxy.
func (m *mitmInjector) wasInjected(b []byte) bool {
	_, ok := m.injected.LoadAndDelete(string(b))
	return ok
}

func getTransportsForMITMTest(t *testing.T) (serverTransport, clientTransport *quic.Transport) {
	serverTransport = &quic.Transport{
		Conn:               newUDPConnLocalhost(t),
		ConnectionIDLength: mitmTestConnIDLen,
	}
	addTracer(serverTransport)
	t.Cleanup(func() { serverTransport.Close() })

	clientTransport = &quic.Transport{
		Conn:               newUDPConnLocalhost(t),
		ConnectionIDLength: mitmTestConnIDLen,
	}
	addTracer(clientTransport)
	t.Cleanup(func() { clientTransport.Close() })

	return serverTransport, clientTransport
}

func TestMITMInjectRandomPackets(t *testing.T) {
	t.Run("towards the server", func(t *testing.T) {
		testMITMInjectRandomPackets(t, quicproxy.DirectionIncoming)
	})

	t.Run("towards the client", func(t *testing.T) {
		testMITMInjectRandomPackets(t, quicproxy.DirectionOutgoing)
	})
}

func TestMITMDuplicatePackets(t *testing.T) {
	t.Run("towards the server", func(t *testing.T) {
		testMITMDuplicatePackets(t, quicproxy.DirectionIncoming)
	})

	t.Run("towards the client", func(t *testing.T) {
		testMITMDuplicatePackets(t, quicproxy.DirectionOutgoing)
	})
}

func TestMITCorruptPackets(t *testing.T) {
	t.Run("towards the server", func(t *testing.T) {
		testMITMCorruptPackets(t, quicproxy.DirectionIncoming)
	})

	t.Run("towards the client", func(t *testing.T) {
		testMITMCorruptPackets(t, quicproxy.DirectionOutgoing)
	})
}

func testMITMInjectRandomPackets(t *testing.T, direction quicproxy.Direction) {
	createRandomPacketOfSameType := func(b []byte) []byte {
		if wire.IsLongHeaderPacket(b[0]) {
			hdr, _, _, err := wire.ParsePacket(b)
			if err != nil {
				return nil
			}
			replyHdr := &wire.ExtendedHeader{
				Header: wire.Header{
					DestConnectionID: hdr.DestConnectionID,
					SrcConnectionID:  hdr.SrcConnectionID,
					Type:             hdr.Type,
					Version:          hdr.Version,
				},
				PacketNumber:    protocol.PacketNumber(mrand.Int32N(math.MaxInt32 / 4)),
				PacketNumberLen: protocol.PacketNumberLen(mrand.IntN(4) + 1),
			}
			payloadLen := mrand.IntN(100)
			replyHdr.Length = protocol.ByteCount(mrand.IntN(payloadLen + 1))
			data, err := replyHdr.Append(nil, hdr.Version)
			if err != nil {
				panic("failed to append header: " + err.Error())
			}
			r := make([]byte, payloadLen)
			rand.Read(r)
			return append(data, r...)
		}
		// short header packet
		connID, err := wire.ParseConnectionID(b, mitmTestConnIDLen)
		if err != nil {
			return nil
		}
		_, pn, pnLen, _, err := wire.ParseShortHeader(b, mitmTestConnIDLen)
		if err != nil && !errors.Is(err, wire.ErrInvalidReservedBits) { // normally, ParseShortHeader is called after decrypting the header
			panic("failed to parse short header: " + err.Error())
		}
		data, err := wire.AppendShortHeader(nil, connID, pn, pnLen, protocol.KeyPhaseBit(mrand.IntN(2)))
		if err != nil {
			return nil
		}
		payloadLen := mrand.IntN(100)
		r := make([]byte, payloadLen)
		rand.Read(r)
		return append(data, r...)
	}

	rtt := scaleDuration(10 * time.Millisecond)
	serverTransport, clientTransport := getTransportsForMITMTest(t)
	injector := newMITMInjector(t)

	dropCallback := func(dir quicproxy.Direction, _, _ net.Addr, b []byte) bool {
		if dir != direction {
			return false
		}
		go func() {
			ticker := time.NewTicker(rtt / 10)
			defer ticker.Stop()
			for range 10 {
				switch direction {
				case quicproxy.DirectionIncoming:
					clientTransport.WriteTo(createRandomPacketOfSameType(b), serverTransport.Conn.LocalAddr())
				case quicproxy.DirectionOutgoing:
					injector.toClient(createRandomPacketOfSameType(b), clientTransport)
				}
				<-ticker.C
			}
		}()
		return false
	}

	runMITMTest(t, serverTransport, clientTransport, injector, rtt, dropCallback)
}

func testMITMDuplicatePackets(t *testing.T, direction quicproxy.Direction) {
	serverTransport, clientTransport := getTransportsForMITMTest(t)
	injector := newMITMInjector(t)
	rtt := scaleDuration(10 * time.Millisecond)

	dropCallback := func(dir quicproxy.Direction, _, _ net.Addr, b []byte) bool {
		if dir != direction || injector.wasInjected(b) {
			return false
		}
		// The duplicated packets arrive before the packets sent through the proxy towards the client,
		// and after them towards the server.
		switch direction {
		case quicproxy.DirectionIncoming:
			injector.toServerViaProxy(b, clientTransport)
		case quicproxy.DirectionOutgoing:
			injector.toClient(b, clientTransport)
		}
		return false
	}

	runMITMTest(t, serverTransport, clientTransport, injector, rtt, dropCallback)
}

func testMITMCorruptPackets(t *testing.T, direction quicproxy.Direction) {
	serverTransport, clientTransport := getTransportsForMITMTest(t)
	injector := newMITMInjector(t)
	rtt := scaleDuration(5 * time.Millisecond)

	var numCorrupted atomic.Int32
	dropCallback := func(dir quicproxy.Direction, _, _ net.Addr, b []byte) bool {
		if dir != direction || injector.wasInjected(b) {
			return false
		}
		isLongHeaderPacket := wire.IsLongHeaderPacket(b[0])
		// corrupt 20% of long header packets and 5% of short header packets
		if isLongHeaderPacket && mrand.IntN(4) != 0 {
			return false
		}
		if !isLongHeaderPacket && mrand.IntN(20) != 0 {
			return false
		}
		numCorrupted.Add(1)
		pos := mrand.IntN(len(b))
		b[pos] = byte(mrand.IntN(256))
		// A packet in a corrupted datagram is still processed if the corruption only affects another packet
		// coalesced into the datagram, or if the byte is replaced by the same value.
		switch direction {
		case quicproxy.DirectionIncoming:
			injector.toServerViaProxy(b, clientTransport)
		case quicproxy.DirectionOutgoing:
			injector.toClient(b, clientTransport)
		}
		return true
	}

	runMITMTest(t, serverTransport, clientTransport, injector, rtt, dropCallback)
	t.Logf("corrupted %d packets", numCorrupted.Load())
	require.NotZero(t, int(numCorrupted.Load()))
}

func runMITMTest(t *testing.T, serverTr, clientTr *quic.Transport, injector *mitmInjector, rtt time.Duration, dropCb quicproxy.DropCallback) {
	ln, err := serverTr.Listen(getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer ln.Close()

	proxy := quicproxy.Proxy{
		Conn:        injector.proxyConn,
		ServerAddr:  ln.Addr().(*net.UDPAddr),
		DelayPacket: func(quicproxy.Direction, net.Addr, net.Addr, []byte) time.Duration { return rtt / 2 },
		DropPacket:  dropCb,
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(time.Second))
	defer cancel()
	conn, err := clientTr.Dial(ctx, proxy.LocalAddr(), getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	serverConn, err := ln.Accept(ctx)
	require.NoError(t, err)
	defer serverConn.CloseWithError(0, "")

	str, err := conn.OpenStreamSync(ctx)
	require.NoError(t, err)
	clientErrChan := make(chan error, 1)
	go func() {
		_, err := str.Write(PRData)
		clientErrChan <- err
		str.Close()
	}()

	serverStr, err := serverConn.AcceptStream(ctx)
	require.NoError(t, err)
	serverErrChan := make(chan error, 1)
	go func() {
		defer close(serverErrChan)
		if _, err := io.Copy(serverStr, serverStr); err != nil {
			serverErrChan <- err
			return
		}
		serverStr.Close()
	}()
	require.NoError(t, <-serverErrChan)

	data, err := io.ReadAll(str)
	require.NoError(t, err)
	require.Equal(t, PRData, data)

	select {
	case err := <-clientErrChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	select {
	case err := <-serverErrChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestMITMForgedVersionNegotiationPacket(t *testing.T) {
	serverTransport, clientTransport := getTransportsForMITMTest(t)
	injector := newMITMInjector(t)
	rtt := scaleDuration(10 * time.Millisecond)

	const supportedVersion protocol.Version = 42

	var once sync.Once
	delayCb := func(dir quicproxy.Direction, _, _ net.Addr, raw []byte) time.Duration {
		if dir != quicproxy.DirectionIncoming {
			return rtt / 2
		}
		once.Do(func() {
			hdr, _, _, err := wire.ParsePacket(raw)
			if err != nil {
				panic("failed to parse packet: " + err.Error())
			}
			// create fake version negotiation packet with a fake supported version
			packet := wire.ComposeVersionNegotiation(
				protocol.ArbitraryLenConnectionID(hdr.SrcConnectionID.Bytes()),
				protocol.ArbitraryLenConnectionID(hdr.DestConnectionID.Bytes()),
				[]protocol.Version{supportedVersion},
			)
			if err := injector.toClient(packet, clientTransport); err != nil {
				panic("failed to write packet: " + err.Error())
			}
		})
		return rtt / 2
	}

	err := runMITMTestSuccessful(t, serverTransport, clientTransport, injector, delayCb)
	var vnErr *quic.VersionNegotiationError
	require.ErrorAs(t, err, &vnErr)
	require.Contains(t, vnErr.Theirs, supportedVersion) // might contain greased versions
}

// times out, because client doesn't accept subsequent real retry packets from server
// as it has already accepted a retry.
// TODO: determine behavior when server does not send Retry packets
func TestMITMForgedRetryPacket(t *testing.T) {
	serverTransport, clientTransport := getTransportsForMITMTest(t)
	injector := newMITMInjector(t)
	serverTransport.VerifySourceAddress = func(net.Addr) bool { return true }
	rtt := scaleDuration(10 * time.Millisecond)

	var once sync.Once
	delayCb := func(dir quicproxy.Direction, _, _ net.Addr, raw []byte) time.Duration {
		hdr, _, _, err := wire.ParsePacket(raw)
		if err != nil {
			panic("failed to parse packet: " + err.Error())
		}
		if dir == quicproxy.DirectionIncoming && hdr.Type == protocol.PacketTypeInitial {
			once.Do(func() {
				fakeSrcConnID := protocol.ParseConnectionID([]byte{0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12})
				retryPacket := testutils.ComposeRetryPacket(fakeSrcConnID, hdr.SrcConnectionID, hdr.DestConnectionID, []byte("token"), hdr.Version)
				if err := injector.toClient(retryPacket, clientTransport); err != nil {
					panic("failed to write packet: " + err.Error())
				}
			})
		}
		return rtt / 2
	}
	err := runMITMTestSuccessful(t, serverTransport, clientTransport, injector, delayCb)
	var nerr net.Error
	require.ErrorAs(t, err, &nerr)
	require.True(t, nerr.Timeout())
}

func TestMITMForgedInitialPacket(t *testing.T) {
	serverTransport, clientTransport := getTransportsForMITMTest(t)
	injector := newMITMInjector(t)
	rtt := scaleDuration(10 * time.Millisecond)

	var once sync.Once
	delayCb := func(dir quicproxy.Direction, _, _ net.Addr, raw []byte) time.Duration {
		if dir == quicproxy.DirectionIncoming {
			hdr, _, _, err := wire.ParsePacket(raw)
			if err != nil {
				panic("failed to parse packet: " + err.Error())
			}
			if hdr.Type != protocol.PacketTypeInitial {
				return 0
			}
			once.Do(func() {
				initialPacket := testutils.ComposeInitialPacket(
					hdr.DestConnectionID,
					hdr.SrcConnectionID,
					hdr.DestConnectionID,
					nil,
					nil,
					protocol.PerspectiveServer,
					hdr.Version,
				)
				if err := injector.toClient(initialPacket, clientTransport); err != nil {
					panic("failed to write packet: " + err.Error())
				}
			})
		}
		return rtt / 2
	}
	err := runMITMTestSuccessful(t, serverTransport, clientTransport, injector, delayCb)
	var nerr net.Error
	require.ErrorAs(t, err, &nerr)
	require.True(t, nerr.Timeout())
}

func TestMITMForgedInitialPacketWithAck(t *testing.T) {
	serverTransport, clientTransport := getTransportsForMITMTest(t)
	injector := newMITMInjector(t)
	rtt := scaleDuration(10 * time.Millisecond)

	var once sync.Once
	delayCb := func(dir quicproxy.Direction, _, _ net.Addr, raw []byte) time.Duration {
		if dir == quicproxy.DirectionIncoming {
			hdr, _, _, err := wire.ParsePacket(raw)
			if err != nil {
				panic("failed to parse packet: " + err.Error())
			}
			if hdr.Type != protocol.PacketTypeInitial {
				return 0
			}
			once.Do(func() {
				// Fake Initial with ACK for packet 2 (unsent)
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 2, Largest: 2}}}
				initialPacket := testutils.ComposeInitialPacket(
					hdr.DestConnectionID,
					hdr.SrcConnectionID,
					hdr.DestConnectionID,
					nil,
					[]wire.Frame{ack},
					protocol.PerspectiveServer,
					hdr.Version,
				)
				if err := injector.toClient(initialPacket, clientTransport); err != nil {
					panic("failed to write packet: " + err.Error())
				}
			})
		}
		return rtt / 2
	}

	err := runMITMTestSuccessful(t, serverTransport, clientTransport, injector, delayCb)
	var transportErr *quic.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, quic.ProtocolViolation, transportErr.ErrorCode)
	require.Contains(t, transportErr.ErrorMessage, "received ACK for an unsent packet")
}

func runMITMTestSuccessful(t *testing.T, serverTransport, clientTransport *quic.Transport, injector *mitmInjector, delayCb quicproxy.DelayCallback) error {
	t.Helper()
	ln, err := serverTransport.Listen(getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer ln.Close()

	proxy := quicproxy.Proxy{
		Conn:        injector.proxyConn,
		ServerAddr:  ln.Addr().(*net.UDPAddr),
		DelayPacket: delayCb,
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(50*time.Millisecond))
	defer cancel()
	_, err = clientTransport.Dial(ctx, proxy.LocalAddr(), getTLSClientConfig(), getQuicConfig(nil))
	require.Error(t, err)
	return err
}
