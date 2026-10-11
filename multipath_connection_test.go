package quic

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/internal/wire"
	"github.com/AeonDave/mp-quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

func TestMultipathControllerPerConnection(t *testing.T) {
	t.Run("built-in controller", func(t *testing.T) {
		controller := NewDefaultMultipathController(NewMinRTTScheduler(0.3))
		tc1 := newServerTestConnection(t, nil, &Config{MultipathController: controller}, false)
		require.Same(t, controller, tc1.conn.MultipathController())

		// the controller is in use: the next connection gets a clone
		tc2 := newServerTestConnection(t, nil, &Config{MultipathController: controller}, false)
		clone, ok := tc2.conn.MultipathController().(*DefaultMultipathController)
		require.True(t, ok)
		require.NotSame(t, controller, clone)
		require.Equal(t, 0.3, clone.scheduler.(*MinRTTScheduler).rttBias)

		// once the first connection is closed, the controller can be used again
		tc1.conn.releaseMultipath()
		tc3 := newServerTestConnection(t, nil, &Config{MultipathController: controller}, false)
		require.Same(t, controller, tc3.conn.MultipathController())
		tc3.conn.releaseMultipath()
	})

	t.Run("custom controller", func(t *testing.T) {
		controller := &selectingTestController{}
		tc1 := newServerTestConnection(t, nil, &Config{MultipathController: controller}, false)
		require.Same(t, controller, tc1.conn.MultipathController())
		// a custom controller can't be cloned: multipath is disabled for the second connection
		tc2 := newServerTestConnection(t, nil, &Config{MultipathController: controller}, false)
		require.Nil(t, tc2.conn.MultipathController())
		tc1.conn.releaseMultipath()
	})

	t.Run("factory", func(t *testing.T) {
		var created []MultipathController
		config := &Config{MultipathControllerFactory: func() MultipathController {
			c := NewDefaultMultipathController(nil)
			created = append(created, c)
			return c
		}}
		tc1 := newServerTestConnection(t, nil, config, false)
		tc2 := newServerTestConnection(t, nil, config, false)
		require.Len(t, created, 2)
		require.Same(t, created[0], tc1.conn.MultipathController())
		require.Same(t, created[1], tc2.conn.MultipathController())
	})
}

func TestMultipathSchedulerUsesPathCongestion(t *testing.T) {
	controller := NewDefaultMultipathController(NewLowLatencyScheduler())
	var paths []PathInfo
	for _, id := range []PathID{1, 2} {
		path := PathInfo{
			ID:         id,
			LocalAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000},
			RemoteAddr: &net.UDPAddr{IP: net.IPv4(10, 0, 0, byte(id)), Port: 443},
		}
		controller.RegisterPath(path)
		paths = append(paths, path)
	}
	fast, slow := 10*time.Millisecond, 100*time.Millisecond
	controller.UpdatePathState(1, PathStateUpdate{SmoothedRTT: &fast})
	controller.UpdatePathState(2, PathStateUpdate{SmoothedRTT: &slow})

	congested := map[PathID]bool{}
	ctx := PathSelectionContext{Paths: paths, PathCongestion: func(id PathID) (ByteCount, ByteCount, bool) {
		if congested[id] {
			return 10000, 10000, true
		}
		return 10000, 0, true
	}}
	path, ok := controller.SelectPath(ctx)
	require.True(t, ok)
	require.Equal(t, PathID(1), path.ID)
	// the fast path's congestion window is full: use the other path
	congested[1] = true
	path, ok = controller.SelectPath(ctx)
	require.True(t, ok)
	require.Equal(t, PathID(2), path.ID)
	// all paths are congestion limited
	congested[2] = true
	_, ok = controller.SelectPath(ctx)
	require.False(t, ok)
	// ACK-only packets can still be sent
	ctx.AckOnly = true
	_, ok = controller.SelectPath(ctx)
	require.True(t, ok)
}

func TestQueueRawFrameReservedTypes(t *testing.T) {
	tc := newServerTestConnection(t, nil, nil, false)
	for _, ft := range []uint64{0x0, 0x6, 0x1e, 0x24, 0x30, 0x31, 0xaf} {
		require.Error(t, tc.conn.QueueRawFrame(RawFrame{FrameType: ft}), "frame type %#x", ft)
	}
	// frame types of the IETF multipath extension
	for _, ft := range []uint64{0x3e, 0x3f, 0x3e75, 0x3e76, 0x3e77, 0x3e78, 0x3e79, 0x3e7a, 0x3e7b, 0x3e7c} {
		require.Error(t, tc.conn.QueueRawFrame(RawFrame{FrameType: ft}), "frame type %#x", ft)
	}
	// frame types of QUIC Address Discovery
	for _, ft := range []uint64{0x9f81a6, 0x9f81a7} {
		require.Error(t, tc.conn.QueueRawFrame(RawFrame{FrameType: ft}), "frame type %#x", ft)
	}
	require.Error(t, tc.conn.QueueRawFrame(RawFrame{FrameType: 1 << 62}))
	// 0x40-0x42 were used by multipath frames in earlier versions of this module
	for _, ft := range []uint64{0x40, 0x41, 0x42, 0x1234, 0x3e74, 0x3e7d} {
		require.NoError(t, tc.conn.QueueRawFrame(RawFrame{FrameType: ft}), "frame type %#x", ft)
	}
}

func ietfMultipathTestFrames() []wire.Frame {
	return []wire.Frame{
		&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 2}}, HasPathID: true},
		&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 2}}, ECT0: 1, PathID: 1, HasPathID: true},
		&wire.PathAbandonFrame{PathID: 1},
		&wire.PathStatusFrame{PathID: 1, SequenceNumber: 1, Backup: true},
		&wire.PathStatusFrame{PathID: 1, SequenceNumber: 2},
		&wire.PathNewConnectionIDFrame{PathID: 1, ConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4})},
		&wire.PathRetireConnectionIDFrame{PathID: 1},
		&wire.MaxPathIDFrame{MaximumPathID: 3},
		&wire.PathsBlockedFrame{MaximumPathID: 3},
		&wire.PathCIDsBlockedFrame{PathID: 1, NextSequenceNumber: 1},
	}
}

// Without a multipath controller, the frames of the IETF multipath extension are unknown frame types
// (section 12.4 of RFC 9000).
func TestIETFMultipathFramesNotNegotiated(t *testing.T) {
	for _, frame := range ietfMultipathTestFrames() {
		data, err := frame.Append(nil, protocol.Version1)
		require.NoError(t, err)
		frameType, _, err := quicvarint.Parse(data)
		require.NoError(t, err)

		t.Run(fmt.Sprintf("frame type %#x", frameType), func(t *testing.T) {
			tc := newServerTestConnection(t, nil, nil, false)
			_, _, _, err := tc.conn.handleFrames(data, protocol.ConnectionID{}, protocol.Encryption1RTT, nil, monotime.Now())
			require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.FrameEncodingError, FrameType: frameType})
		})
	}
}

type recordingExtensionFrameHandler struct {
	frameTypes []uint64
}

func (h *recordingExtensionFrameHandler) HandleFrame(ctx ExtensionFrameContext) (int, error) {
	h.frameTypes = append(h.frameTypes, ctx.FrameType)
	return len(ctx.Data), nil
}

// Unless we advertise the IETF multipath extension, its frame types are passed to the extension frame handler.
// Like all frames of unknown types, they are ack-eliciting and non-probing.
func TestIETFMultipathFrameTypesExtensionFrameHandler(t *testing.T) {
	for _, frameType := range []uint64{0x3e, 0x3f, 0x3e75, 0x3e78, 0x3e7c} {
		t.Run(fmt.Sprintf("frame type %#x", frameType), func(t *testing.T) {
			handler := &recordingExtensionFrameHandler{}
			tc := newServerTestConnection(t, nil, &Config{ExtensionFrameHandler: handler, DisablePathMTUDiscovery: true}, false)
			data := quicvarint.Append(nil, frameType)
			data = append(data, 1, 2, 3)
			isAckEliciting, isNonProbing, _, err := tc.conn.handleFrames(data, protocol.ConnectionID{}, protocol.Encryption1RTT, nil, monotime.Now())
			require.NoError(t, err)
			require.True(t, isAckEliciting)
			require.True(t, isNonProbing)
			require.Equal(t, []uint64{frameType}, handler.frameTypes)
		})
	}
}

// Once we advertise the IETF multipath extension, the frame parser knows its frame types.
// Receiving these frames in Initial, Handshake or 0-RTT packets is a PROTOCOL_VIOLATION,
// also before the peer's transport parameters are known (section 4 of draft-ietf-quic-multipath).
// Receiving them in 1-RTT packets is a PROTOCOL_VIOLATION if the peer didn't advertise the extension (section 2).
func TestIETFMultipathFramesAdvertised(t *testing.T) {
	for _, frame := range ietfMultipathTestFrames() {
		data, err := frame.Append(nil, protocol.Version1)
		require.NoError(t, err)
		frameType, _, err := quicvarint.Parse(data)
		require.NoError(t, err)

		for _, perspective := range []protocol.Perspective{protocol.PerspectiveClient, protocol.PerspectiveServer} {
			t.Run(fmt.Sprintf("%s, frame type %#x", perspective, frameType), func(t *testing.T) {
				handler := &recordingExtensionFrameHandler{}
				config := &Config{ExtensionFrameHandler: handler, DisablePathMTUDiscovery: true}
				var tc *testConnection
				if perspective == protocol.PerspectiveClient {
					tc = newClientTestConnection(t, nil, config, false)
				} else {
					tc = newServerTestConnection(t, nil, config, false)
				}
				tc.conn.frameParser.EnableMultipath()
				require.Nil(t, tc.conn.peerParams)

				for _, encLevel := range []protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake, protocol.Encryption0RTT} {
					_, _, _, err := tc.conn.handleFrames(data, protocol.ConnectionID{}, encLevel, nil, monotime.Now())
					require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation, FrameType: frameType}, "encryption level %s", encLevel)
				}

				tc.conn.peerParams = &wire.TransportParameters{}
				_, _, _, err := tc.conn.handleFrames(data, protocol.ConnectionID{}, protocol.Encryption1RTT, nil, monotime.Now())
				require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation, FrameType: frameType})
				require.Empty(t, handler.frameTypes)
			})
		}
	}
}

func TestPacketInfoFromPathInfo(t *testing.T) {
	// For sockets bound to an unspecified address, the kernel selects the source address.
	require.Equal(t, packetInfo{}, packetInfoFromPathInfo(PathInfo{LocalAddr: &net.UDPAddr{IP: net.IPv6unspecified, Port: 1234}}))
	require.Equal(t, packetInfo{}, packetInfoFromPathInfo(PathInfo{LocalAddr: &net.UDPAddr{IP: net.IPv4zero, Port: 1234}}))
	require.Equal(t, packetInfo{}, packetInfoFromPathInfo(PathInfo{LocalAddr: &net.UDPAddr{Port: 1234}}))

	info := packetInfoFromPathInfo(PathInfo{LocalAddr: &net.UDPAddr{IP: net.IPv4(192, 168, 1, 2), Port: 1234}, IfIndex: 3})
	require.True(t, info.addr.Is4())
	require.Equal(t, "192.168.1.2", info.addr.String())
	require.Equal(t, uint32(3), info.ifIndex)
}
