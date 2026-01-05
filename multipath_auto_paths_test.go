package quic

import (
	"net"
	"testing"

	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

type autoPathController struct {
	paths     []PathInfo
	validated []PathID
	nextID    PathID
}

func (c *autoPathController) SelectPath(PathSelectionContext) (PathInfo, bool) {
	return PathInfo{}, false
}

func (c *autoPathController) PathIDForPacket(net.Addr, net.Addr) (PathID, bool) {
	return InvalidPathID, false
}

func (c *autoPathController) EnableMultipath() {}

func (c *autoPathController) AddPath(info PathInfo) (PathID, bool) {
	if info.ID == InvalidPathID {
		if c.nextID == 0 {
			c.nextID = 1
		}
		info.ID = c.nextID
		c.nextID++
	}
	c.paths = append(c.paths, info)
	return info.ID, true
}

func (c *autoPathController) ValidatePath(pathID PathID) {
	c.validated = append(c.validated, pathID)
}

func TestMultipathAutoPathsAndAdvertise(t *testing.T) {
	ctrl := &autoPathController{}
	config := &Config{
		DisablePathMTUDiscovery: true,
		MultipathController:     ctrl,
		MultipathAutoPaths:      true,
		MultipathAutoAdvertise:  true,
		MultipathAutoAddrs: []net.IP{
			net.IPv4(127, 0, 0, 1),
			net.IPv4(127, 0, 0, 2),
			net.IPv4(127, 0, 0, 3),
		},
	}
	tc := newClientTestConnection(t, nil, config, false)
	tc.conn.peerParams = &wire.TransportParameters{EnableMultipath: true}
	tc.conn.maybeEnableMultipath()

	tc.conn.maybeStartAutoPaths()
	tc.conn.maybeStartAutoPaths()

	require.Len(t, ctrl.paths, 2)
	require.Len(t, ctrl.validated, 2)

	gotIPs := map[string]bool{}
	for _, info := range ctrl.paths {
		udpAddr, ok := info.LocalAddr.(*net.UDPAddr)
		require.True(t, ok)
		gotIPs[udpAddr.IP.String()] = true
		require.Equal(t, tc.conn.RemoteAddr().String(), info.RemoteAddr.String())
		require.Equal(t, tc.conn.LocalAddr().(*net.UDPAddr).Port, udpAddr.Port)
	}
	require.True(t, gotIPs["127.0.0.2"])
	require.True(t, gotIPs["127.0.0.3"])

	frames, _, _ := tc.conn.framer.Append(nil, nil, protocol.MaxPacketBufferSize, monotime.Now(), protocol.Version1)
	var addrs []*wire.AddAddressFrame
	for _, frame := range frames {
		if f, ok := frame.Frame.(*wire.AddAddressFrame); ok {
			addrs = append(addrs, f)
		}
	}
	require.Len(t, addrs, 2)

	added := map[string]bool{}
	for _, frame := range addrs {
		added[frame.GetIPAddress().String()] = true
		require.Equal(t, uint16(tc.conn.LocalAddr().(*net.UDPAddr).Port), frame.Port)
	}
	require.True(t, added["127.0.0.2"])
	require.True(t, added["127.0.0.3"])
}
