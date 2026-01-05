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

type testFrameHandler struct {
	lost int
}

func (h *testFrameHandler) OnAcked(wire.Frame) {}

func (h *testFrameHandler) OnLost(wire.Frame) {
	h.lost++
}

func TestMultipathReinjectionQueuesFrames(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	controller := &duplicationTestController{paths: []PathInfo{{
		ID:         1,
		LocalAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1111},
		RemoteAddr: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 4444},
	}}}

	policy := NewMultipathReinjectionPolicy()
	policy.Enable()
	policy.SetReinjectionDelay(0)

	config := &Config{
		DisablePathMTUDiscovery:    true,
		MultipathController:        controller,
		MultipathReinjectionPolicy: policy,
	}

	tc := newServerTestConnection(t, ctrl, config, false, connectionOptHandshakeConfirmed())
	require.NotNil(t, tc.conn.multipathReinjectionManager)
	tc.conn.peerParams = &wire.TransportParameters{EnableMultipath: true}
	tc.conn.maybeEnableMultipath()

	handler := &testFrameHandler{}
	frame := &wire.StreamFrame{
		StreamID:       1,
		Data:           []byte("x"),
		DataLenPresent: true,
	}
	frames := []ackhandler.Frame{{Frame: frame, Handler: handler}}

	tc.conn.multipathReinjectionManager.OnPacketLost(1, 1, protocol.Encryption1RTT, frames)
	tc.conn.handlePendingReinjections(monotime.Now())

	require.Equal(t, 1, handler.lost)
	pending, reinjected := tc.conn.multipathReinjectionManager.GetStatistics()
	require.Equal(t, 0, pending)
	require.Equal(t, 1, reinjected)
}

func TestMultipathReinjectionSelectsPreferredPath(t *testing.T) {
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

	policy := NewMultipathReinjectionPolicy()
	policy.Enable()
	policy.SetReinjectionDelay(0)
	policy.AddPreferredPathForReinjection(protocol.PathID(path2.ID))

	config := &Config{
		DisablePathMTUDiscovery:    true,
		MultipathController:        controller,
		MultipathReinjectionPolicy: policy,
	}

	tc := newServerTestConnection(t, ctrl, config, false, connectionOptHandshakeConfirmed())
	tc.conn.peerParams = &wire.TransportParameters{EnableMultipath: true}
	tc.conn.maybeEnableMultipath()

	handler := &testFrameHandler{}
	frame := &wire.StreamFrame{
		StreamID:       1,
		Data:           []byte("x"),
		DataLenPresent: true,
	}
	frames := []ackhandler.Frame{{Frame: frame, Handler: handler}}

	tc.conn.multipathReinjectionManager.OnPacketLost(path1.ID, 1, protocol.Encryption1RTT, frames)
	tc.conn.handlePendingReinjections(monotime.Now())

	require.Equal(t, 1, handler.lost)
	require.Len(t, tc.conn.reinjectionPathQueue, 1)
	require.Equal(t, protocol.PathID(path2.ID), tc.conn.reinjectionPathQueue[0])
}

type reinjectionSelectController struct {
	duplicationTestController
	selected PathID
	called   int
}

func (c *reinjectionSelectController) SelectReinjectionTarget(ReinjectionTargetContext) (PathID, bool) {
	c.called++
	return c.selected, true
}

func TestMultipathReinjectionCustomTargetSelector(t *testing.T) {
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
	controller := &reinjectionSelectController{
		duplicationTestController: duplicationTestController{paths: []PathInfo{path1, path2}},
		selected:                  PathID(path2.ID),
	}

	policy := NewMultipathReinjectionPolicy()
	policy.Enable()
	policy.SetReinjectionDelay(0)

	config := &Config{
		DisablePathMTUDiscovery:    true,
		MultipathController:        controller,
		MultipathReinjectionPolicy: policy,
	}

	tc := newServerTestConnection(t, ctrl, config, false, connectionOptHandshakeConfirmed())
	tc.conn.peerParams = &wire.TransportParameters{EnableMultipath: true}
	tc.conn.maybeEnableMultipath()

	handler := &testFrameHandler{}
	frame := &wire.StreamFrame{
		StreamID:       1,
		Data:           []byte("x"),
		DataLenPresent: true,
	}
	frames := []ackhandler.Frame{{Frame: frame, Handler: handler}}

	tc.conn.multipathReinjectionManager.OnPacketLost(path1.ID, 1, protocol.Encryption1RTT, frames)
	tc.conn.handlePendingReinjections(monotime.Now())

	require.Equal(t, 1, controller.called)
	require.Equal(t, 1, handler.lost)
	require.Len(t, tc.conn.reinjectionPathQueue, 1)
	require.Equal(t, protocol.PathID(path2.ID), tc.conn.reinjectionPathQueue[0])
}

func TestMultipathReinjectionQueueLimit(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	controller := &duplicationTestController{paths: []PathInfo{{
		ID:         1,
		LocalAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1111},
		RemoteAddr: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 4444},
	}}}

	policy := NewMultipathReinjectionPolicy()
	policy.Enable()
	policy.SetReinjectionDelay(0)
	policy.SetMaxReinjectionQueuePerPath(1)

	config := &Config{
		DisablePathMTUDiscovery:    true,
		MultipathController:        controller,
		MultipathReinjectionPolicy: policy,
	}

	tc := newServerTestConnection(t, ctrl, config, false, connectionOptHandshakeConfirmed())
	tc.conn.peerParams = &wire.TransportParameters{EnableMultipath: true}
	tc.conn.maybeEnableMultipath()

	handler := &testFrameHandler{}
	frame := &wire.StreamFrame{
		StreamID:       1,
		Data:           []byte("x"),
		DataLenPresent: true,
	}
	frames := []ackhandler.Frame{{Frame: frame, Handler: handler}}

	tc.conn.multipathReinjectionManager.OnPacketLost(1, 1, protocol.Encryption1RTT, frames)
	tc.conn.multipathReinjectionManager.OnPacketLost(1, 2, protocol.Encryption1RTT, frames)
	tc.conn.handlePendingReinjections(monotime.Now())

	require.Equal(t, 1, handler.lost)
	require.Len(t, tc.conn.reinjectionPathQueue, 1)
	pending, reinjected := tc.conn.multipathReinjectionManager.GetStatistics()
	require.Equal(t, 1, pending)
	require.Equal(t, 1, reinjected)

	tc.conn.popReinjectionSelection()
	tc.conn.handlePendingReinjections(monotime.Now())

	require.Equal(t, 2, handler.lost)
	require.Len(t, tc.conn.reinjectionPathQueue, 1)
	pending, reinjected = tc.conn.multipathReinjectionManager.GetStatistics()
	require.Equal(t, 0, pending)
	require.Equal(t, 2, reinjected)
}
