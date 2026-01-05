package quic

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMultiSocketManager_AddRemoveLocalAddr(t *testing.T) {
	base, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	require.NoError(t, err)

	mgr, err := NewMultiSocketManager(MultiSocketManagerConfig{BaseConn: base})
	require.NoError(t, err)
	defer mgr.Close()

	_, err = mgr.AddLocalAddr(net.IPv4(127, 0, 0, 1))
	require.NoError(t, err)
	require.Len(t, mgr.LocalAddrs(), 1)

	require.True(t, mgr.RemoveLocalAddr(net.IPv4(127, 0, 0, 1)))
	require.Len(t, mgr.LocalAddrs(), 0)
}

func TestMultiSocketManager_SetLocalAddrs(t *testing.T) {
	base, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	require.NoError(t, err)

	mgr, err := NewMultiSocketManager(MultiSocketManagerConfig{BaseConn: base})
	require.NoError(t, err)
	defer mgr.Close()

	err = mgr.SetLocalAddrs([]net.IP{net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	require.Len(t, mgr.LocalAddrs(), 1)

	err = mgr.SetLocalAddrs(nil)
	require.NoError(t, err)
	require.Len(t, mgr.LocalAddrs(), 0)
}

func TestMultiSocketManager_ReadPacketUsesLocalAddr(t *testing.T) {
	base, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	require.NoError(t, err)

	mgr, err := NewMultiSocketManager(MultiSocketManagerConfig{BaseConn: base})
	require.NoError(t, err)
	defer mgr.Close()

	localAddr, err := mgr.AddLocalAddr(net.IPv4(127, 0, 0, 1))
	require.NoError(t, err)

	sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer sender.Close()

	_, err = sender.WriteTo([]byte("ping"), localAddr)
	require.NoError(t, err)

	done := make(chan receivedPacket, 1)
	go func() {
		p, readErr := mgr.ReadPacket()
		require.NoError(t, readErr)
		done <- p
	}()

	select {
	case p := <-done:
		if p.info.addr.IsValid() {
			require.Equal(t, localAddr.IP.String(), p.info.addr.String())
		} else {
			t.Fatalf("expected packet info to include local addr")
		}
		if p.buffer != nil {
			p.buffer.Release()
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for packet")
	}
}
