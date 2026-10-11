package quic

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/wire"
	"github.com/AeonDave/mp-quic-go/qlog"
	"github.com/AeonDave/mp-quic-go/qlogwriter/jsontext"

	"github.com/stretchr/testify/require"
)

func TestConnectionLoggingCryptoFrame(t *testing.T) {
	f := toQlogFrame(&wire.CryptoFrame{
		Offset: 1234,
		Data:   []byte("foobar"),
	})
	require.Equal(t, &qlog.CryptoFrame{
		Offset: 1234,
		Length: 6,
	}, f.Frame)
}

func TestConnectionLoggingStreamFrame(t *testing.T) {
	f := toQlogFrame(&wire.StreamFrame{
		StreamID: 42,
		Offset:   1234,
		Data:     []byte("foo"),
		Fin:      true,
	})
	require.Equal(t, &qlog.StreamFrame{
		StreamID: 42,
		Offset:   1234,
		Length:   3,
		Fin:      true,
	}, f.Frame)
}

func TestConnectionLoggingAckFrame(t *testing.T) {
	ack := &wire.AckFrame{
		AckRanges: []wire.AckRange{
			{Smallest: 1, Largest: 3},
			{Smallest: 6, Largest: 7},
		},
		DelayTime: 42,
		ECNCE:     123,
		ECT0:      456,
		ECT1:      789,
	}
	f := toQlogFrame(ack)
	// now modify the ACK range in the original frame
	ack.AckRanges[0].Smallest = 2
	require.Equal(t, &qlog.AckFrame{
		AckRanges: []wire.AckRange{
			{Smallest: 1, Largest: 3}, // unchanged, since the ACK ranges were cloned
			{Smallest: 6, Largest: 7},
		},
		DelayTime: 42,
		ECNCE:     123,
		ECT0:      456,
		ECT1:      789,
	}, f.Frame)
}

func TestConnectionLoggingPathAckFrame(t *testing.T) {
	ack := &wire.AckFrame{
		AckRanges: []wire.AckRange{{Smallest: 1, Largest: 3}},
		DelayTime: 42,
		ECT0:      456,
		PathID:    7,
		HasPathID: true,
	}
	f := toQlogFrame(ack)
	// the frame parser reuses the ACK frame
	ack.Reset()
	require.Equal(t, &qlog.AckFrame{
		AckRanges: []wire.AckRange{{Smallest: 1, Largest: 3}},
		DelayTime: 42,
		ECT0:      456,
		PathID:    7,
		HasPathID: true,
	}, f.Frame)
}

func TestConnectionLoggingMultipathFrames(t *testing.T) {
	for _, frame := range []wire.Frame{
		&wire.PathAbandonFrame{PathID: 1, ErrorCode: 0x3e},
		&wire.PathStatusFrame{PathID: 1, SequenceNumber: 2, Backup: true},
		&wire.PathStatusFrame{PathID: 1, SequenceNumber: 3},
		&wire.PathNewConnectionIDFrame{PathID: 1, SequenceNumber: 2, ConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4})},
		&wire.PathRetireConnectionIDFrame{PathID: 1, SequenceNumber: 2},
		&wire.MaxPathIDFrame{MaximumPathID: 3},
		&wire.PathsBlockedFrame{MaximumPathID: 3},
		&wire.PathCIDsBlockedFrame{PathID: 2, NextSequenceNumber: 1},
	} {
		f := toQlogFrame(frame)
		require.Equal(t, frame, f.Frame)
		// the frame can be encoded
		var buf bytes.Buffer
		require.NoError(t, f.Encode(jsontext.NewEncoder(&buf)))
		require.Contains(t, buf.String(), `"frame_type":"`)
	}
}

// Frames that have no qlog definition are logged as unknown frames.
func TestConnectionLoggingUnknownFrames(t *testing.T) {
	for _, tc := range []struct {
		name      string
		frame     wire.Frame
		frameType uint64
	}{
		{
			name:      "raw frame",
			frame:     &rawFrame{frameType: 0x1234, data: []byte("foobar"), ackEliciting: true},
			frameType: 0x1234,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := toQlogFrame(tc.frame)
			require.Equal(t, &qlog.UnknownFrame{FrameType: tc.frameType}, f.Frame)
			var buf bytes.Buffer
			require.NoError(t, f.Encode(jsontext.NewEncoder(&buf)))
			require.JSONEq(t, fmt.Sprintf(`{"frame_type": "unknown", "frame_type_bytes": %d}`, tc.frameType), buf.String())
		})
	}
}

func TestConnectionLoggingDatagramFrame(t *testing.T) {
	f := toQlogFrame(&wire.DatagramFrame{Data: []byte("foobar")})
	require.Equal(t, &qlog.DatagramFrame{Length: 6}, f.Frame)
}

func TestConnectionLoggingOtherFrames(t *testing.T) {
	f := toQlogFrame(&wire.MaxDataFrame{MaximumData: 1234})
	require.Equal(t, &qlog.MaxDataFrame{MaximumData: 1234}, f.Frame)
}

func TestConnectionLoggingStartedConnectionEvent(t *testing.T) {
	tests := []struct {
		name          string
		local         *net.UDPAddr
		remote        *net.UDPAddr
		wantLocalIP   string
		wantLocalPort uint16
		wantRemote    netip.AddrPort
	}{
		{
			name:          "unspecified local, remote IPv4 -> 0.0.0.0",
			local:         &net.UDPAddr{Port: 58451},
			remote:        &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 6121},
			wantLocalIP:   "0.0.0.0",
			wantLocalPort: 58451,
			wantRemote:    netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 6121),
		},
		{
			name:          "unspecified local, remote IPv6 -> ::",
			local:         &net.UDPAddr{Port: 4242},
			remote:        &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 6121},
			wantLocalIP:   "::",
			wantLocalPort: 4242,
			wantRemote:    func() netip.AddrPort { a, _ := netip.ParseAddr("2001:db8::1"); return netip.AddrPortFrom(a, 6121) }(),
		},
		{
			name:          "specified local IPv4",
			local:         &net.UDPAddr{IP: net.IPv4(192, 168, 1, 10), Port: 9999},
			remote:        &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1234},
			wantLocalIP:   "192.168.1.10",
			wantLocalPort: 9999,
			wantRemote:    netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 1}), 1234),
		},
		{
			name:          "specified local IPv6",
			local:         &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 999},
			remote:        &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 6121},
			wantLocalIP:   "fe80::1",
			wantLocalPort: 999,
			wantRemote:    func() netip.AddrPort { a, _ := netip.ParseAddr("2001:db8::1"); return netip.AddrPortFrom(a, 6121) }(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := startedConnectionEvent(tc.local, tc.remote)
			var gotIP string
			var gotPort uint16
			if ev.Local.IPv4.IsValid() {
				gotIP = ev.Local.IPv4.Addr().String()
				gotPort = ev.Local.IPv4.Port()
			} else if ev.Local.IPv6.IsValid() {
				gotIP = ev.Local.IPv6.Addr().String()
				gotPort = ev.Local.IPv6.Port()
			}
			require.Equal(t, tc.wantLocalIP, gotIP)
			require.Equal(t, tc.wantLocalPort, gotPort)

			var gotRemote netip.AddrPort
			if ev.Remote.IPv4.IsValid() {
				gotRemote = ev.Remote.IPv4
			} else if ev.Remote.IPv6.IsValid() {
				gotRemote = ev.Remote.IPv6
			}
			require.Equal(t, tc.wantRemote, gotRemote)
		})
	}
}
