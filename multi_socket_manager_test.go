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

func TestMultiSocketManager_RemoveLocalAddrKeepsReading(t *testing.T) {
	base, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)

	mgr, err := NewMultiSocketManager(MultiSocketManagerConfig{BaseConn: base})
	require.NoError(t, err)
	defer mgr.Close()

	_, err = mgr.AddLocalAddr(net.IPv4(127, 0, 0, 1))
	require.NoError(t, err)
	// closing the removed socket must not cause ReadPacket to return an error,
	// since the Transport would then close
	require.True(t, mgr.RemoveLocalAddr(net.IPv4(127, 0, 0, 1)))

	sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer sender.Close()
	_, err = sender.WriteTo([]byte("ping"), base.LocalAddr())
	require.NoError(t, err)

	type result struct {
		p   receivedPacket
		err error
	}
	done := make(chan result, 1)
	go func() {
		p, err := mgr.ReadPacket()
		done <- result{p: p, err: err}
	}()
	select {
	case r := <-done:
		require.NoError(t, r.err)
		require.Equal(t, []byte("ping"), r.p.data)
		if r.p.buffer != nil {
			r.p.buffer.Release()
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for packet")
	}
}

func TestMultiSocketManager_WritePacketToRemoteAddr(t *testing.T) {
	remote := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443} // TEST-NET-1
	plain, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	require.NoError(t, err)
	defer plain.Close()
	if _, err := plain.WriteTo([]byte("ping"), remote); err != nil {
		t.Skipf("no route to %s: %s", remote, err)
	}

	mgr, err := NewMultiSocketManager(MultiSocketManagerConfig{})
	require.NoError(t, err)
	defer mgr.Close()

	// The packet info selects the source address. It must not be derived from the destination address,
	// which the kernel would reject (e.g. "network is unreachable").
	_, err = mgr.WriteTo([]byte("ping"), remote)
	require.NoError(t, err)
}
