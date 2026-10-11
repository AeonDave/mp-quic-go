package quic

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/internal/wire"
	"github.com/AeonDave/mp-quic-go/qlog"
	"github.com/AeonDave/mp-quic-go/quicvarint"
	"github.com/AeonDave/mp-quic-go/testutils/events"
	"github.com/AeonDave/mp-quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// newTestAddressDiscovery returns an addressDiscovery that sends OBSERVED_ADDRESS frames.
// The remote addresses of the paths are taken from addrs.
func newTestAddressDiscovery(addrs map[protocol.PathID]netip.AddrPort) (_ *addressDiscovery, numScheduled *int) {
	numScheduled = new(int)
	a := newAddressDiscovery(
		true,
		true,
		func(id protocol.PathID) (netip.AddrPort, bool) {
			addr, ok := addrs[id]
			return addr, ok
		},
		func() { *numScheduled++ },
	)
	return a, numScheduled
}

// appendObservedAddress returns the OBSERVED_ADDRESS frame sent on a path, if one is due.
func appendObservedAddress(t *testing.T, a *addressDiscovery, id protocol.PathID) (ackhandler.Frame, bool) {
	t.Helper()
	frames, l := a.AppendObservedAddress(nil, id, protocol.MaxByteCount, protocol.Version1)
	if len(frames) == 0 {
		require.Zero(t, l)
		return ackhandler.Frame{}, false
	}
	require.Len(t, frames, 1)
	require.Equal(t, frames[0].Frame.Length(protocol.Version1), l)
	return frames[0], true
}

// An OBSERVED_ADDRESS frame is sent on the path used for the handshake, and on every new path.
// The sequence numbers increase across all paths.
func TestAddressDiscoverySendsFrameOnEveryPath(t *testing.T) {
	addr0 := netip.MustParseAddrPort("192.0.2.1:443")
	addr1 := netip.MustParseAddrPort("[2001:db8::1]:4433")
	a, numScheduled := newTestAddressDiscovery(map[protocol.PathID]netip.AddrPort{0: addr0, 1: addr1})
	require.Equal(t, 1, *numScheduled)

	require.True(t, a.HasObservedAddress(0))
	require.False(t, a.HasObservedAddress(1))
	// the frame doesn't fit
	frames, l := a.AppendObservedAddress(nil, 0, 8, protocol.Version1)
	require.Empty(t, frames)
	require.Zero(t, l)
	f, ok := appendObservedAddress(t, a, 0)
	require.True(t, ok)
	require.Equal(t, &wire.ObservedAddressFrame{SequenceNumber: 0, Address: addr0}, f.Frame)
	require.False(t, a.HasObservedAddress(0))
	_, ok = appendObservedAddress(t, a, 0)
	require.False(t, ok)

	a.addPath(1)
	require.Equal(t, 2, *numScheduled)
	require.True(t, a.HasObservedAddress(1))
	f, ok = appendObservedAddress(t, a, 1)
	require.True(t, ok)
	require.Equal(t, &wire.ObservedAddressFrame{SequenceNumber: 1, Address: addr1}, f.Frame)
	require.False(t, a.HasObservedAddress(1))
	// acknowledging the frame doesn't change anything
	f.Handler.OnAcked(f.Frame)
	require.False(t, a.HasObservedAddress(1))

	// no frames are sent on abandoned paths
	a.addPath(2)
	a.removePath(2)
	require.False(t, a.HasObservedAddress(2))
	_, ok = appendObservedAddress(t, a, 2)
	require.False(t, ok)
}

// A lost OBSERVED_ADDRESS frame is sent again on the same path, as a new frame with the current address.
func TestAddressDiscoveryLostFrame(t *testing.T) {
	addrs := map[protocol.PathID]netip.AddrPort{0: netip.MustParseAddrPort("192.0.2.1:443")}
	a, numScheduled := newTestAddressDiscovery(addrs)
	a.addPath(1)
	addrs[1] = netip.MustParseAddrPort("192.0.2.2:443")
	f0, ok := appendObservedAddress(t, a, 0)
	require.True(t, ok)
	f1, ok := appendObservedAddress(t, a, 1)
	require.True(t, ok)

	scheduled := *numScheduled
	f0.Handler.OnLost(f0.Frame)
	require.Equal(t, scheduled+1, *numScheduled)
	require.True(t, a.HasObservedAddress(0))
	require.False(t, a.HasObservedAddress(1))
	addrs[0] = netip.MustParseAddrPort("192.0.2.3:1234")
	f, ok := appendObservedAddress(t, a, 0)
	require.True(t, ok)
	require.Equal(t, &wire.ObservedAddressFrame{SequenceNumber: 2, Address: addrs[0]}, f.Frame)

	// The frame of an abandoned path is not sent again.
	a.removePath(1)
	f1.Handler.OnLost(f1.Frame)
	require.False(t, a.HasObservedAddress(1))
}

// OBSERVED_ADDRESS frames sent in probe packets to another 4-tuple of a path are the frame of the path
// once it switched to that 4-tuple, unless they were lost.
func TestAddressDiscoveryProbeFrames(t *testing.T) {
	addrs := map[protocol.PathID]netip.AddrPort{0: netip.MustParseAddrPort("192.0.2.1:443")}
	a, numScheduled := newTestAddressDiscovery(addrs)
	_, ok := appendObservedAddress(t, a, 0)
	require.True(t, ok)

	tupleA := observationTuple{remote: netip.MustParseAddrPort("192.0.2.10:1000")}
	tupleB := observationTuple{remote: netip.MustParseAddrPort("192.0.2.11:1000")}
	fA, ok := a.probeFrame(0, tupleA)
	require.True(t, ok)
	require.Equal(t, &wire.ObservedAddressFrame{SequenceNumber: 1, Address: tupleA.remote}, fA.Frame)
	// only one frame is sent per 4-tuple
	_, ok = a.probeFrame(0, tupleA)
	require.False(t, ok)
	// no frames are sent for unknown paths, or without an address
	_, ok = a.probeFrame(5, tupleA)
	require.False(t, ok)
	_, ok = a.probeFrame(0, observationTuple{})
	require.False(t, ok)

	// The path switches to 4-tuple A. No new frame is needed.
	a.switchPath(0, tupleA)
	require.False(t, a.HasObservedAddress(0))
	// The frame is lost after switching. A new frame is sent.
	scheduled := *numScheduled
	fA.Handler.OnLost(fA.Frame)
	require.Equal(t, scheduled+1, *numScheduled)
	require.True(t, a.HasObservedAddress(0))
	addrs[0] = tupleA.remote
	f, ok := appendObservedAddress(t, a, 0)
	require.True(t, ok)
	require.Equal(t, &wire.ObservedAddressFrame{SequenceNumber: 2, Address: tupleA.remote}, f.Frame)

	// The frame sent to 4-tuple B is lost before the path switches to it.
	fB, ok := a.probeFrame(0, tupleB)
	require.True(t, ok)
	fB.Handler.OnLost(fB.Frame)
	// It is sent again when probing the 4-tuple again.
	fB, ok = a.probeFrame(0, tupleB)
	require.True(t, ok)
	require.Equal(t, uint64(4), fB.Frame.(*wire.ObservedAddressFrame).SequenceNumber)
	fB.Handler.OnLost(fB.Frame)
	a.switchPath(0, tupleB)
	require.True(t, a.HasObservedAddress(0))

	// Switching to a 4-tuple that wasn't probed.
	addrs[0] = tupleB.remote
	_, ok = appendObservedAddress(t, a, 0)
	require.True(t, ok)
	a.switchPath(0, observationTuple{remote: netip.MustParseAddrPort("192.0.2.12:1000")})
	require.True(t, a.HasObservedAddress(0))
}

// The local address distinguishes the 4-tuples of a path.
// Only a limited number of frames sent to other 4-tuples are kept track of.
func TestAddressDiscoveryProbeFramesLimit(t *testing.T) {
	a, _ := newTestAddressDiscovery(map[protocol.PathID]netip.AddrPort{0: netip.MustParseAddrPort("192.0.2.1:443")})
	remote := netip.MustParseAddrPort("192.0.2.10:1000")
	tuples := make([]observationTuple, maxObservationProbes+1)
	for i := range tuples {
		tuples[i] = observationTuple{local: netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), 0), remote: remote}
		_, ok := a.probeFrame(0, tuples[i])
		require.True(t, ok)
	}
	require.Len(t, a.paths[0].probes, maxObservationProbes)
	// the frame sent to the first 4-tuple was forgotten
	a.switchPath(0, tuples[0])
	require.True(t, a.HasObservedAddress(0))
	a.switchPath(0, tuples[len(tuples)-1])
	require.False(t, a.HasObservedAddress(0))
}

// An endpoint that doesn't provide address observations never sends OBSERVED_ADDRESS frames.
func TestAddressDiscoveryReceiveOnly(t *testing.T) {
	var numScheduled int
	a := newAddressDiscovery(
		false,
		true,
		func(protocol.PathID) (netip.AddrPort, bool) { return netip.MustParseAddrPort("192.0.2.1:443"), true },
		func() { numScheduled++ },
	)
	require.Zero(t, numScheduled)
	a.addPath(1)
	for _, id := range []protocol.PathID{0, 1} {
		require.False(t, a.HasObservedAddress(id))
		_, ok := appendObservedAddress(t, a, id)
		require.False(t, ok)
		_, ok = a.probeFrame(id, observationTuple{remote: netip.MustParseAddrPort("192.0.2.2:443")})
		require.False(t, ok)
	}
	require.Zero(t, numScheduled)
}

// A received OBSERVED_ADDRESS frame is ignored if a frame with an equal or higher sequence number was received on
// the same path (section 4.1 of draft-ietf-quic-address-discovery-01).
func TestAddressDiscoveryReceivedFrames(t *testing.T) {
	a := newAddressDiscovery(false, true, nil, nil)
	_, ok := a.observedAddr(0)
	require.False(t, ok)

	addr1 := netip.MustParseAddrPort("192.0.2.1:443")
	addr2 := netip.MustParseAddrPort("192.0.2.2:443")
	require.True(t, a.receivedFrame(0, &wire.ObservedAddressFrame{SequenceNumber: 5, Address: addr1}))
	addr, ok := a.observedAddr(0)
	require.True(t, ok)
	require.Equal(t, addr1, addr)
	require.False(t, a.receivedFrame(0, &wire.ObservedAddressFrame{SequenceNumber: 5, Address: addr2}))
	require.False(t, a.receivedFrame(0, &wire.ObservedAddressFrame{SequenceNumber: 4, Address: addr2}))
	addr, _ = a.observedAddr(0)
	require.Equal(t, addr1, addr)

	// the sequence numbers are compared per path
	require.True(t, a.receivedFrame(1, &wire.ObservedAddressFrame{SequenceNumber: 3, Address: addr2}))
	addr, ok = a.observedAddr(1)
	require.True(t, ok)
	require.Equal(t, addr2, addr)
	require.True(t, a.receivedFrame(0, &wire.ObservedAddressFrame{SequenceNumber: 6, Address: addr2}))
	addr, _ = a.observedAddr(0)
	require.Equal(t, addr2, addr)

	// IPv4-mapped IPv6 addresses are reported as IPv4 addresses
	require.True(t, a.receivedFrame(1, &wire.ObservedAddressFrame{SequenceNumber: 7, Address: netip.MustParseAddrPort("[::ffff:192.0.2.3]:1")}))
	addr, _ = a.observedAddr(1)
	require.Equal(t, netip.MustParseAddrPort("192.0.2.3:1"), addr)

	a.forgetPath(1)
	_, ok = a.observedAddr(1)
	require.False(t, ok)
	_, ok = a.observedAddr(0)
	require.True(t, ok)
}

func TestAddressDiscoveryTransportParameter(t *testing.T) {
	for _, tc := range []struct {
		request, provide bool
		expected         wire.AddressDiscoveryMode
	}{
		{expected: wire.AddressDiscoveryUnsupported},
		{provide: true, expected: wire.AddressDiscoveryProvide},
		{request: true, expected: wire.AddressDiscoveryReceive},
		{request: true, provide: true, expected: wire.AddressDiscoveryProvideAndReceive},
	} {
		t.Run(tc.expected.String(), func(t *testing.T) {
			for _, perspective := range []protocol.Perspective{protocol.PerspectiveClient, protocol.PerspectiveServer} {
				config := &Config{RequestObservedAddress: tc.request, ProvideObservedAddress: tc.provide, DisablePathMTUDiscovery: true}
				var tc2 *testConnection
				if perspective == protocol.PerspectiveClient {
					tc2 = newClientTestConnection(t, nil, config, false)
				} else {
					tc2 = newServerTestConnection(t, nil, config, false)
				}
				require.Equal(t, tc.expected, tc2.conn.advertisedAddressDiscovery)
				require.Equal(t, tc.expected != wire.AddressDiscoveryUnsupported, tc2.conn.frameParser.IsKnownFrameType(wire.FrameTypeObservedAddressIPv4))
			}
		})
	}
}

// The extension is used in each direction if one endpoint requested address observations,
// and the other one offered to provide them.
func TestAddressDiscoveryNegotiation(t *testing.T) {
	modes := []wire.AddressDiscoveryMode{
		wire.AddressDiscoveryUnsupported,
		wire.AddressDiscoveryProvide,
		wire.AddressDiscoveryReceive,
		wire.AddressDiscoveryProvideAndReceive,
	}
	for _, local := range modes {
		for _, peer := range modes {
			t.Run(fmt.Sprintf("local %s, peer %s", local, peer), func(t *testing.T) {
				config := &Config{
					RequestObservedAddress:  local.Receives(),
					ProvideObservedAddress:  local.Provides(),
					DisablePathMTUDiscovery: true,
				}
				tc := newServerTestConnection(t, nil, config, false)
				send := local.Provides() && peer.Receives()
				receive := local.Receives() && peer.Provides()
				if send {
					tc.packer.EXPECT().EnableAddressDiscovery(gomock.Any())
				}
				tc.conn.maybeNegotiateAddressDiscovery(&wire.TransportParameters{AddressDiscovery: peer})
				if !send && !receive {
					require.Nil(t, tc.conn.addrDisc)
					return
				}
				require.NotNil(t, tc.conn.addrDisc)
				require.Equal(t, send, tc.conn.addrDisc.send)
				require.Equal(t, receive, tc.conn.addrDisc.receive)
				require.Equal(t, send, tc.conn.observedAddrDue(0))
			})
		}
	}
}

func observedAddressFrameData(t *testing.T, f *wire.ObservedAddressFrame) (data []byte, frameType uint64) {
	t.Helper()
	data, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	frameType, _, err = quicvarint.Parse(data)
	require.NoError(t, err)
	return data, frameType
}

// An endpoint that didn't request address observations closes the connection with a PROTOCOL_VIOLATION
// when it receives an OBSERVED_ADDRESS frame (section 4.1 of draft-ietf-quic-address-discovery-01).
// The same applies if the peer didn't offer to provide them.
// Without the extension, the frame types are unknown (section 12.4 of RFC 9000).
func TestAddressDiscoveryUnexpectedFrame(t *testing.T) {
	for _, f := range []*wire.ObservedAddressFrame{
		{SequenceNumber: 1, Address: netip.MustParseAddrPort("192.0.2.1:443")},
		{SequenceNumber: 1, Address: netip.MustParseAddrPort("[2001:db8::1]:443")},
	} {
		data, frameType := observedAddressFrameData(t, f)

		t.Run(fmt.Sprintf("frame type %#x, not supported", frameType), func(t *testing.T) {
			tc := newServerTestConnection(t, nil, nil, false)
			_, _, _, err := tc.conn.handleFrames(data, protocol.ConnectionID{}, protocol.Encryption1RTT, nil, monotime.Now())
			require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.FrameEncodingError, FrameType: frameType})
		})

		t.Run(fmt.Sprintf("frame type %#x, not requested", frameType), func(t *testing.T) {
			tc := newServerTestConnection(t, nil, &Config{ProvideObservedAddress: true, DisablePathMTUDiscovery: true}, false)
			tc.packer.EXPECT().EnableAddressDiscovery(gomock.Any())
			tc.conn.maybeNegotiateAddressDiscovery(&wire.TransportParameters{AddressDiscovery: wire.AddressDiscoveryProvideAndReceive})
			for _, encLevel := range []protocol.EncryptionLevel{protocol.Encryption0RTT, protocol.Encryption1RTT} {
				_, _, _, err := tc.conn.handleFrames(data, protocol.ConnectionID{}, encLevel, nil, monotime.Now())
				require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation, FrameType: frameType})
			}
		})

		t.Run(fmt.Sprintf("frame type %#x, not provided by the peer", frameType), func(t *testing.T) {
			tc := newServerTestConnection(t, nil, &Config{RequestObservedAddress: true, DisablePathMTUDiscovery: true}, false)
			tc.conn.maybeNegotiateAddressDiscovery(&wire.TransportParameters{AddressDiscovery: wire.AddressDiscoveryReceive})
			require.Nil(t, tc.conn.addrDisc)
			_, _, _, err := tc.conn.handleFrames(data, protocol.ConnectionID{}, protocol.Encryption1RTT, nil, monotime.Now())
			require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation, FrameType: frameType})
		})

		// The frame is only allowed in the application data packet number space.
		t.Run(fmt.Sprintf("frame type %#x, in Initial and Handshake packets", frameType), func(t *testing.T) {
			tc := newServerTestConnection(t, nil, &Config{RequestObservedAddress: true, DisablePathMTUDiscovery: true}, false)
			require.Nil(t, tc.conn.peerParams)
			for _, encLevel := range []protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake} {
				_, _, _, err := tc.conn.handleFrames(data, protocol.ConnectionID{}, encLevel, nil, monotime.Now())
				require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation, FrameType: frameType}, "encryption level %s", encLevel)
			}
		})
	}
}

// OBSERVED_ADDRESS frames are accepted in 0-RTT and 1-RTT packets. They are probing frames
// (section 4.1 of draft-ietf-quic-address-discovery-01).
func TestAddressDiscoveryReceiveFrame(t *testing.T) {
	tc := newServerTestConnection(t, nil, &Config{RequestObservedAddress: true, DisablePathMTUDiscovery: true}, false)
	tc.conn.maybeNegotiateAddressDiscovery(&wire.TransportParameters{AddressDiscovery: wire.AddressDiscoveryProvide})
	require.NotNil(t, tc.conn.addrDisc)

	addr := netip.MustParseAddrPort("192.0.2.1:443")
	data, _ := observedAddressFrameData(t, &wire.ObservedAddressFrame{SequenceNumber: 3, Address: addr})
	isAckEliciting, isNonProbing, _, err := tc.conn.handleFrames(data, protocol.ConnectionID{}, protocol.Encryption0RTT, nil, monotime.Now())
	require.NoError(t, err)
	require.True(t, isAckEliciting)
	require.False(t, isNonProbing)
	observed, ok := tc.conn.addrDisc.observedAddr(0)
	require.True(t, ok)
	require.Equal(t, addr, observed)

	// Before the handshake completes, the observed address is not returned.
	_, ok = tc.conn.ObservedAddr()
	require.False(t, ok)
	require.False(t, tc.conn.ConnectionState().SupportsAddressDiscovery.Receive)
	close(tc.conn.handshakeCompleteChan)
	observed, ok = tc.conn.ObservedAddr()
	require.True(t, ok)
	require.Equal(t, addr, observed)
	require.True(t, tc.conn.ConnectionState().SupportsAddressDiscovery.Receive)
	require.False(t, tc.conn.ConnectionState().SupportsAddressDiscovery.Send)

	// an older frame is ignored
	data, _ = observedAddressFrameData(t, &wire.ObservedAddressFrame{SequenceNumber: 2, Address: netip.MustParseAddrPort("192.0.2.2:443")})
	_, _, _, err = tc.conn.handleFrames(data, protocol.ConnectionID{}, protocol.Encryption1RTT, nil, monotime.Now())
	require.NoError(t, err)
	observed, _ = tc.conn.ObservedAddr()
	require.Equal(t, addr, observed)
}

// An OBSERVED_ADDRESS frame is only added to probe packets that validate another 4-tuple, i.e. packets with a
// PATH_CHALLENGE frame.
func TestAddressDiscoveryProbePacketFrames(t *testing.T) {
	tc := newServerTestConnection(t, nil, &Config{ProvideObservedAddress: true, DisablePathMTUDiscovery: true}, false)
	tuple := rfc9000ObservationTuple(nil, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1234})

	// without the extension
	frames := []ackhandler.Frame{{Frame: &wire.PathChallengeFrame{}}}
	require.Equal(t, frames, tc.conn.observedAddrProbeFrame(frames, 0, tuple))

	tc.packer.EXPECT().EnableAddressDiscovery(gomock.Any())
	tc.conn.maybeNegotiateAddressDiscovery(&wire.TransportParameters{AddressDiscovery: wire.AddressDiscoveryReceive})
	frames = []ackhandler.Frame{{Frame: &wire.PathResponseFrame{}}}
	require.Equal(t, frames, tc.conn.observedAddrProbeFrame(frames, 0, tuple))
	frames = tc.conn.observedAddrProbeFrame([]ackhandler.Frame{{Frame: &wire.PathChallengeFrame{}}, {Frame: &wire.PathResponseFrame{}}}, 0, tuple)
	require.Len(t, frames, 3)
	require.Equal(t, &wire.ObservedAddressFrame{Address: netip.MustParseAddrPort("192.0.2.1:1234")}, frames[2].Frame)
	// the frame was sent to this 4-tuple already
	frames = []ackhandler.Frame{{Frame: &wire.PathChallengeFrame{}}}
	require.Equal(t, frames, tc.conn.observedAddrProbeFrame(frames, 0, tuple))
}

// observedAddressFrames returns the OBSERVED_ADDRESS frames sent, and the paths they were sent on.
// It fails the test if a frame was sent in a packet other than a 1-RTT packet.
func observedAddressFrames(t *testing.T, r *events.Recorder) ([]qlog.ObservedAddressFrame, []protocol.PathID) {
	t.Helper()
	for _, ev := range r.Events(qlog.PacketSent{}) {
		ps := ev.(qlog.PacketSent)
		if ps.Header.PacketType != qlog.PacketType1RTT {
			require.False(t, hasFrame[*qlog.ObservedAddressFrame](ps), "OBSERVED_ADDRESS frame sent in a %s packet", ps.Header.PacketType)
		}
	}
	frames, paths := sentFrames[*qlog.ObservedAddressFrame](r)
	res := make([]qlog.ObservedAddressFrame, 0, len(frames))
	for _, f := range frames {
		res = append(res, *f)
	}
	return res, paths
}

// receivedObservedAddressFrames returns the OBSERVED_ADDRESS frames received.
func receivedObservedAddressFrames(r *events.Recorder) []qlog.ObservedAddressFrame {
	var frames []qlog.ObservedAddressFrame
	for _, ev := range r.Events(qlog.PacketReceived{}) {
		for _, f := range ev.(qlog.PacketReceived).Frames {
			if f, ok := f.Frame.(*qlog.ObservedAddressFrame); ok {
				frames = append(frames, *f)
			}
		}
	}
	return frames
}

// A testNAT rewrites the addresses of the packets of an internal address, like a NAT.
// Packets sent to a previous external address are dropped.
type testNAT struct {
	internal net.Addr

	mx       sync.Mutex
	external net.Addr
}

func newTestNAT(internal, external net.Addr) *testNAT {
	return &testNAT{internal: internal, external: external}
}

func (n *testNAT) Rebind(external net.Addr) {
	n.mx.Lock()
	defer n.mx.Unlock()

	n.external = external
}

func (n *testNAT) Rewrite(p simnet.Packet) (simnet.Packet, bool) {
	n.mx.Lock()
	defer n.mx.Unlock()

	switch {
	case sameAddr(p.From, n.internal):
		p.From = n.external
	case sameAddr(p.To, n.external):
		p.To = n.internal
	case sameAddr(p.To, n.internal):
		return p, false
	}
	return p, true
}

func addrPort(t *testing.T, addr net.Addr) netip.AddrPort {
	t.Helper()
	ap, ok := netAddrToAddrPort(addr)
	require.True(t, ok)
	return ap
}

// The client is behind a NAT. Both endpoints use QUIC Address Discovery, without IETF Multipath QUIC.
// Every endpoint sends a single OBSERVED_ADDRESS frame, on the path used for the handshake, in a 1-RTT packet.
// The client learns its address on the other side of the NAT.
func TestAddressDiscoveryEndToEnd(t *testing.T) {
	for _, tc := range []struct {
		name                           string
		clientRequest, clientProvide   bool
		serverRequest, serverProvide   bool
		clientReceives, serverReceives bool
	}{
		{name: "server provides", clientRequest: true, serverProvide: true, clientReceives: true},
		{name: "client provides", clientProvide: true, serverRequest: true, serverReceives: true},
		{
			name:          "both directions",
			clientRequest: true, clientProvide: true, serverRequest: true, serverProvide: true,
			clientReceives: true, serverReceives: true,
		},
		{name: "both request", clientRequest: true, serverRequest: true},
		{name: "both provide", clientProvide: true, serverProvide: true},
		{name: "only the client", clientRequest: true, clientProvide: true},
		{name: "only the server", serverRequest: true, serverProvide: true},
		{name: "disabled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				natAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 40000}
				nat := newTestNAT(multipathTestClientAddr, natAddr)
				p := newMultipathPathTestPair(t, multipathPathTestOpts{
					withoutMultipath: true,
					rewrite:          nat.Rewrite,
					clientConf: func(c *Config) {
						c.RequestObservedAddress = tc.clientRequest
						c.ProvideObservedAddress = tc.clientProvide
					},
					serverConf: func(c *Config) {
						c.RequestObservedAddress = tc.serverRequest
						c.ProvideObservedAddress = tc.serverProvide
					},
				})
				p.transfer(t, randomData(10<<10))

				clientState := p.client.ConnectionState()
				serverState := p.server.ConnectionState()
				require.Equal(t, tc.clientReceives, clientState.SupportsAddressDiscovery.Receive)
				require.Equal(t, tc.serverReceives, clientState.SupportsAddressDiscovery.Send)
				require.Equal(t, tc.serverReceives, serverState.SupportsAddressDiscovery.Receive)
				require.Equal(t, tc.clientReceives, serverState.SupportsAddressDiscovery.Send)

				clientFrames, _ := observedAddressFrames(t, p.clientEvents)
				serverFrames, _ := observedAddressFrames(t, p.serverEvents)
				observed, ok := p.client.ObservedAddr()
				if tc.clientReceives {
					require.Equal(t, []qlog.ObservedAddressFrame{{SequenceNumber: 0, Address: addrPort(t, natAddr)}}, serverFrames)
					require.True(t, ok)
					require.Equal(t, addrPort(t, natAddr), observed)
				} else {
					require.Empty(t, serverFrames)
					require.False(t, ok)
				}
				observed, ok = p.server.ObservedAddr()
				if tc.serverReceives {
					require.Equal(t, []qlog.ObservedAddressFrame{{SequenceNumber: 0, Address: addrPort(t, multipathTestServerAddr)}}, clientFrames)
					require.True(t, ok)
					require.Equal(t, addrPort(t, multipathTestServerAddr), observed)
				} else {
					require.Empty(t, clientFrames)
					require.False(t, ok)
				}
				for _, side := range []struct {
					events           *events.Recorder
					request, provide bool
				}{
					{events: p.clientEvents, request: tc.clientRequest, provide: tc.clientProvide},
					{events: p.serverEvents, request: tc.serverRequest, provide: tc.serverProvide},
				} {
					param := localTransportParameters(t, side.events).AddressDiscovery
					switch {
					case side.request && side.provide:
						require.Equal(t, uint64(2), *param)
					case side.request:
						require.Equal(t, uint64(1), *param)
					case side.provide:
						require.Equal(t, uint64(0), *param)
					default:
						require.Nil(t, param)
					}
				}
				p.close(t)
			})
		})
	}
}

// The server sends its OBSERVED_ADDRESS frame in the first 1-RTT packet, together with its handshake messages.
// If that packet is lost, a new frame is sent.
func TestAddressDiscoveryLostFrameEndToEnd(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var droppedMx sync.Mutex
		var dropped bool
		p := newMultipathPathTestPair(t, multipathPathTestOpts{
			withoutMultipath: true,
			rewrite: func(pkt simnet.Packet) (simnet.Packet, bool) {
				if !sameAddr(pkt.From, multipathTestServerAddr) || !containsShortHeaderPacket(pkt.Data) {
					return pkt, true
				}
				droppedMx.Lock()
				defer droppedMx.Unlock()
				if dropped {
					return pkt, true
				}
				dropped = true
				return pkt, false
			},
			clientConf: func(c *Config) { c.RequestObservedAddress = true },
			serverConf: func(c *Config) { c.ProvideObservedAddress = true },
		})
		p.transfer(t, randomData(10<<10))
		p.close(t)

		frames, _ := observedAddressFrames(t, p.serverEvents)
		require.Len(t, frames, 2)
		for i, f := range frames {
			require.Equal(t, qlog.ObservedAddressFrame{SequenceNumber: uint64(i), Address: addrPort(t, multipathTestClientAddr)}, f)
		}
		require.Equal(t, []qlog.ObservedAddressFrame{frames[1]}, receivedObservedAddressFrames(p.clientEvents))
		observed, ok := p.client.ObservedAddr()
		require.True(t, ok)
		require.Equal(t, addrPort(t, multipathTestClientAddr), observed)
	})
}

// containsShortHeaderPacket says if a datagram contains a short header packet,
// possibly coalesced with long header packets.
func containsShortHeaderPacket(data []byte) bool {
	for len(data) > 0 {
		if !wire.IsLongHeaderPacket(data[0]) {
			return true
		}
		_, _, rest, err := wire.ParsePacket(data)
		if err != nil {
			return false
		}
		data = rest
	}
	return false
}

// A NAT rebinding changes the client's address (without IETF Multipath QUIC). The server validates the new address,
// and sends an OBSERVED_ADDRESS frame in the probe packet. It doesn't send another frame when switching to the new
// address.
func TestAddressDiscoveryNATRebinding(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		natAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 40000}
		nat := newTestNAT(multipathTestClientAddr, natAddr)
		p := newMultipathPathTestPair(t, multipathPathTestOpts{
			withoutMultipath: true,
			rewrite:          nat.Rewrite,
			clientConf:       func(c *Config) { c.RequestObservedAddress = true },
			serverConf:       func(c *Config) { c.ProvideObservedAddress = true },
		})
		p.transfer(t, randomData(10<<10))
		observed, ok := p.client.ObservedAddr()
		require.True(t, ok)
		require.Equal(t, addrPort(t, natAddr), observed)

		newNATAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 50000}
		nat.Rebind(newNATAddr)
		p.transfer(t, randomData(10<<10))
		p.close(t)

		require.True(t, sameAddr(newNATAddr, p.server.RemoteAddr()))
		observed, ok = p.client.ObservedAddr()
		require.True(t, ok)
		require.Equal(t, addrPort(t, newNATAddr), observed)

		frames, _ := observedAddressFrames(t, p.serverEvents)
		require.Equal(t, []qlog.ObservedAddressFrame{
			{SequenceNumber: 0, Address: addrPort(t, natAddr)},
			{SequenceNumber: 1, Address: addrPort(t, newNATAddr)},
		}, frames)
		// the second frame was sent together with the PATH_CHALLENGE
		var numProbes int
		for _, ev := range p.serverEvents.Events(qlog.PacketSent{}) {
			ps := ev.(qlog.PacketSent)
			if !hasFrame[*qlog.ObservedAddressFrame](ps) {
				continue
			}
			if hasFrame[*qlog.PathChallengeFrame](ps) {
				numProbes++
				require.Equal(t, qlog.ObservedAddressFrame{SequenceNumber: 1, Address: addrPort(t, newNATAddr)}, *observedAddressFrameOf(ps))
			}
		}
		require.Equal(t, 1, numProbes)
	})
}

func observedAddressFrameOf(p qlog.PacketSent) *qlog.ObservedAddressFrame {
	for _, f := range p.Frames {
		if f, ok := f.Frame.(*qlog.ObservedAddressFrame); ok {
			return f
		}
	}
	return nil
}

// The client migrates to a new path (RFC 9000 connection migration). It sends an OBSERVED_ADDRESS frame in the
// probe packet, and the server sends one when it validates the client's new address.
func TestAddressDiscoveryClientMigration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		both := func(c *Config) {
			c.RequestObservedAddress = true
			c.ProvideObservedAddress = true
		}
		p := newMultipathPathTestPair(t, multipathPathTestOpts{withoutMultipath: true, clientConf: both, serverConf: both})
		p.transfer(t, randomData(10<<10))

		path, err := p.client.AddPath(p.clientTr2)
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		require.NoError(t, path.Probe(ctx))
		require.NoError(t, path.Switch())
		p.transfer(t, randomData(10<<10))
		p.close(t)

		require.True(t, sameAddr(multipathTestClientAddr2, p.server.RemoteAddr()))
		observed, ok := p.client.ObservedAddr()
		require.True(t, ok)
		require.Equal(t, addrPort(t, multipathTestClientAddr2), observed)
		observed, ok = p.server.ObservedAddr()
		require.True(t, ok)
		require.Equal(t, addrPort(t, multipathTestServerAddr), observed)

		// The client sent a frame on the path used for the handshake, and one in the probe packet on the new path.
		// It didn't send another frame after switching to the new path.
		serverAddr := addrPort(t, multipathTestServerAddr)
		clientFrames, _ := observedAddressFrames(t, p.clientEvents)
		require.Equal(t, []qlog.ObservedAddressFrame{
			{SequenceNumber: 0, Address: serverAddr},
			{SequenceNumber: 1, Address: serverAddr},
		}, clientFrames)
		for _, ev := range p.clientEvents.Events(qlog.PacketSent{}) {
			ps := ev.(qlog.PacketSent)
			if f := observedAddressFrameOf(ps); f != nil && f.SequenceNumber == 1 {
				require.True(t, hasFrame[*qlog.PathChallengeFrame](ps))
			}
		}
		require.NotZero(t, p.router.Delivered(multipathTestClientAddr2, multipathTestServerAddr))

		serverFrames, _ := observedAddressFrames(t, p.serverEvents)
		require.Equal(t, []qlog.ObservedAddressFrame{
			{SequenceNumber: 0, Address: addrPort(t, multipathTestClientAddr)},
			{SequenceNumber: 1, Address: addrPort(t, multipathTestClientAddr2)},
		}, serverFrames)
	})
}

// With IETF Multipath QUIC, an OBSERVED_ADDRESS frame is sent on every path, together with the frames that validate
// the path. Conn.Paths returns the address observed on every path.
func TestAddressDiscoveryMultipath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		natAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 40000}
		nat := newTestNAT(multipathTestClientAddr2, natAddr)
		both := func(c *Config) {
			c.RequestObservedAddress = true
			c.ProvideObservedAddress = true
		}
		p := newMultipathPathTestPair(t, multipathPathTestOpts{rewrite: nat.Rewrite, clientConf: both, serverConf: both})
		p.openPath(t)
		p.transfer(t, randomData(100<<10))

		serverAddr := addrPort(t, multipathTestServerAddr)
		clientPaths := p.client.Paths()
		require.Len(t, clientPaths, 2)
		require.Equal(t, addrPort(t, multipathTestClientAddr), clientPaths[0].ObservedAddr)
		require.Equal(t, addrPort(t, natAddr), clientPaths[1].ObservedAddr)
		serverPaths := p.server.Paths()
		require.Len(t, serverPaths, 2)
		require.Equal(t, serverAddr, serverPaths[0].ObservedAddr)
		require.Equal(t, serverAddr, serverPaths[1].ObservedAddr)
		observed, ok := p.client.ObservedAddr()
		require.True(t, ok)
		require.Equal(t, addrPort(t, multipathTestClientAddr), observed)

		// The frames of path 1 were sent in the first packet on path 1, together with the PATH_CHALLENGE.
		for _, r := range []*events.Recorder{p.clientEvents, p.serverEvents} {
			frames, paths := observedAddressFrames(t, r)
			require.Len(t, frames, 2)
			require.Equal(t, []protocol.PathID{0, 1}, paths)
			first := sentPathPackets(r, 1)[0]
			require.True(t, hasFrame[*qlog.PathChallengeFrame](first))
			require.Equal(t, frames[1], *observedAddressFrameOf(first))
		}

		// When path 0 is abandoned, path 1 becomes the primary path.
		require.NoError(t, p.client.closeMultipathPath(0))
		time.Sleep(time.Second)
		synctest.Wait()
		observed, ok = p.client.ObservedAddr()
		require.True(t, ok)
		require.Equal(t, addrPort(t, natAddr), observed)
		p.close(t)
	})
}

// With IETF Multipath QUIC, a NAT rebinding changes the client's address on path 1. The server sends an
// OBSERVED_ADDRESS frame together with the PATH_CHALLENGE that validates the new 4-tuple of path 1.
// Path 0 is not affected.
func TestAddressDiscoveryMultipathNATRebinding(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		natAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 40000}
		nat := newTestNAT(multipathTestClientAddr2, natAddr)
		p := newMultipathPathTestPair(t, multipathPathTestOpts{
			rewrite:    nat.Rewrite,
			clientConf: func(c *Config) { c.RequestObservedAddress = true },
			serverConf: func(c *Config) { c.ProvideObservedAddress = true },
		})
		p.openPath(t)
		p.transfer(t, randomData(100<<10))

		newNATAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 50000}
		nat.Rebind(newNATAddr)
		p.transfer(t, randomData(100<<10))
		p.close(t)

		require.True(t, sameAddr(newNATAddr, p.server.mp.paths[1].conn.RemoteAddr()))
		clientPaths := p.client.Paths()
		require.Len(t, clientPaths, 2)
		require.Equal(t, addrPort(t, multipathTestClientAddr), clientPaths[0].ObservedAddr)
		require.Equal(t, addrPort(t, newNATAddr), clientPaths[1].ObservedAddr)

		frames, paths := observedAddressFrames(t, p.serverEvents)
		require.Equal(t, []qlog.ObservedAddressFrame{
			{SequenceNumber: 0, Address: addrPort(t, multipathTestClientAddr)},
			{SequenceNumber: 1, Address: addrPort(t, natAddr)},
			{SequenceNumber: 2, Address: addrPort(t, newNATAddr)},
		}, frames)
		require.Equal(t, []protocol.PathID{0, 1, 1}, paths)
		for _, ps := range sentPathPackets(p.serverEvents, 1) {
			if f := observedAddressFrameOf(ps); f != nil {
				require.True(t, hasFrame[*qlog.PathChallengeFrame](ps))
			}
		}
	})
}
