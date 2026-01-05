package quic

import (
	"net"
	"testing"

	"github.com/AeonDave/mp-quic-go/internal/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type duplicationTestController struct {
	paths []PathInfo
}

func (c *duplicationTestController) SelectPath(PathSelectionContext) (PathInfo, bool) {
	if len(c.paths) == 0 {
		return PathInfo{}, false
	}
	return c.paths[0], true
}

func (c *duplicationTestController) PathIDForPacket(net.Addr, net.Addr) (PathID, bool) {
	return InvalidPathID, false
}

func (c *duplicationTestController) GetAvailablePaths() []PathInfo {
	return c.paths
}

type recordingSendQueue struct {
	sent []net.Addr
}

func (q *recordingSendQueue) Send(p *packetBuffer, gsoSize uint16, ecn protocol.ECN) {
	q.SendPath(p, gsoSize, ecn, nil, packetInfo{})
}

func (q *recordingSendQueue) SendPath(p *packetBuffer, gsoSize uint16, ecn protocol.ECN, addr net.Addr, info packetInfo) {
	q.sent = append(q.sent, addr)
	p.Release()
}

func (q *recordingSendQueue) SendProbe(p *packetBuffer, addr net.Addr) {
	q.sent = append(q.sent, addr)
	p.Release()
}

func (q *recordingSendQueue) Run() error { return nil }

func (q *recordingSendQueue) WouldBlock() bool { return false }

func (q *recordingSendQueue) Available() <-chan struct{} { return make(chan struct{}) }

func (q *recordingSendQueue) Close() {}

func TestMultipathDuplicationSendsOnAlternatePath(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	path1 := PathInfo{
		ID:         1,
		LocalAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1111},
		RemoteAddr: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 4444},
	}
	path2 := PathInfo{
		ID:         2,
		LocalAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2222},
		RemoteAddr: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 5555},
	}
	controller := &duplicationTestController{paths: []PathInfo{path1, path2}}

	policy := NewMultipathDuplicationPolicy()
	policy.Enable()
	policy.AddStreamForDuplication(4)

	config := &Config{
		DisablePathMTUDiscovery:    true,
		MultipathController:        controller,
		MultipathDuplicationPolicy: policy,
	}

	sendQueue := &recordingSendQueue{}
	tc := newServerTestConnection(
		t,
		ctrl,
		config,
		false,
		connectionOptHandshakeConfirmed(),
		connectionOptSender(sendQueue),
	)
	tc.conn.peerParams = &wire.TransportParameters{EnableMultipath: true}
	tc.conn.maybeEnableMultipath()

	sel, ok := tc.conn.selectPathForSending(monotime.Now(), false, false)
	require.True(t, ok)
	require.Equal(t, path1.RemoteAddr.String(), sel.remoteAddr.String())

	packet := shortHeaderPacket{
		PacketNumber: 1,
		Length:       1200,
		StreamFrames: []ackhandler.StreamFrame{{
			Frame: &wire.StreamFrame{
				StreamID:       4,
				Data:           []byte("x"),
				DataLenPresent: true,
			},
		}},
	}

	tc.packer.EXPECT().
		AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(packet, nil).
		Times(1)
	tc.packer.EXPECT().
		AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(shortHeaderPacket{}, errNothingToPack).
		AnyTimes()

	err := tc.conn.sendPacketsWithoutGSO(monotime.Now())
	require.NoError(t, err)
	require.Len(t, sendQueue.sent, 2)
	require.Equal(t, path1.RemoteAddr.String(), sendQueue.sent[0].String())
	require.Equal(t, path2.RemoteAddr.String(), sendQueue.sent[1].String())
}
