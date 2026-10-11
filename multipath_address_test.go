package quic

import (
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

func mustUDPAddr(s string) *net.UDPAddr {
	return net.UDPAddrFromAddrPort(netip.MustParseAddrPort(s))
}

// usablePeerAddressTestAddr is a net.Addr of a type usablePeerAddress doesn't know
type usablePeerAddressTestAddr string

func (a usablePeerAddressTestAddr) Network() string { return "udp" }
func (a usablePeerAddressTestAddr) String() string  { return string(a) }

func TestUsablePeerAddress(t *testing.T) {
	public := mustUDPAddr("198.51.100.1:443")
	loopback := mustUDPAddr("127.0.0.1:443")
	loopback6 := mustUDPAddr("[::1]:443")
	linkLocal := mustUDPAddr("169.254.10.1:443")
	linkLocal6 := mustUDPAddr("[fe80::1]:443")

	tests := []struct {
		name    string
		addr    *net.UDPAddr
		primary net.Addr
		want    bool
	}{
		{name: "nil address", addr: nil, primary: public, want: false},
		{name: "public IPv4", addr: mustUDPAddr("203.0.113.5:4433"), primary: public, want: true},
		{name: "private IPv4", addr: mustUDPAddr("192.168.1.2:4433"), primary: public, want: true},
		{name: "global IPv6", addr: mustUDPAddr("[2001:db8::1]:4433"), primary: public, want: true},
		{name: "IPv4-mapped IPv6", addr: mustUDPAddr("[::ffff:203.0.113.5]:4433"), primary: public, want: true},
		{name: "16-byte IPv4", addr: &net.UDPAddr{IP: net.ParseIP("203.0.113.5"), Port: 4433}, primary: public, want: true},
		{name: "nil primary", addr: mustUDPAddr("203.0.113.5:4433"), primary: nil, want: true},

		{name: "port 0", addr: mustUDPAddr("203.0.113.5:0"), primary: public, want: false},
		{name: "negative port", addr: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 5), Port: -1}, primary: public, want: false},
		{name: "port too large", addr: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 65536}, primary: public, want: false},
		{name: "nil IP", addr: &net.UDPAddr{Port: 4433}, primary: public, want: false},
		{name: "invalid IP length", addr: &net.UDPAddr{IP: net.IP{1, 2, 3}, Port: 4433}, primary: public, want: false},

		{name: "unspecified IPv4", addr: mustUDPAddr("0.0.0.0:4433"), primary: public, want: false},
		{name: "unspecified IPv6", addr: mustUDPAddr("[::]:4433"), primary: public, want: false},
		{name: "unspecified IPv4-mapped", addr: mustUDPAddr("[::ffff:0.0.0.0]:4433"), primary: public, want: false},
		{name: "multicast IPv4", addr: mustUDPAddr("224.0.0.1:4433"), primary: public, want: false},
		{name: "multicast IPv4 admin-scoped", addr: mustUDPAddr("239.1.2.3:4433"), primary: public, want: false},
		{name: "multicast IPv4-mapped", addr: mustUDPAddr("[::ffff:224.0.0.251]:4433"), primary: public, want: false},
		{name: "multicast IPv6 link-local", addr: mustUDPAddr("[ff02::1]:4433"), primary: linkLocal6, want: false},
		{name: "multicast IPv6 global", addr: mustUDPAddr("[ff0e::1]:4433"), primary: public, want: false},
		{name: "broadcast", addr: mustUDPAddr("255.255.255.255:4433"), primary: public, want: false},
		{name: "broadcast IPv4-mapped", addr: mustUDPAddr("[::ffff:255.255.255.255]:4433"), primary: public, want: false},

		{name: "loopback, public primary", addr: mustUDPAddr("127.0.0.1:4433"), primary: public, want: false},
		{name: "loopback, nil primary", addr: mustUDPAddr("127.0.0.1:4433"), primary: nil, want: false},
		{name: "loopback, typed nil primary", addr: mustUDPAddr("127.0.0.1:4433"), primary: (*net.UDPAddr)(nil), want: false},
		{name: "loopback, loopback primary", addr: mustUDPAddr("127.0.0.1:4433"), primary: loopback, want: true},
		{name: "other loopback, loopback primary", addr: mustUDPAddr("127.0.0.2:4433"), primary: loopback, want: true},
		{name: "IPv6 loopback, public primary", addr: mustUDPAddr("[::1]:4433"), primary: public, want: false},
		{name: "IPv6 loopback, IPv6 loopback primary", addr: mustUDPAddr("[::1]:4433"), primary: loopback6, want: true},
		{name: "IPv4-mapped loopback, public primary", addr: mustUDPAddr("[::ffff:127.0.0.1]:4433"), primary: public, want: false},
		{name: "loopback, IPv4-mapped loopback primary", addr: mustUDPAddr("127.0.0.1:4433"), primary: mustUDPAddr("[::ffff:127.0.0.1]:443"), want: true},
		{name: "loopback, link-local primary", addr: mustUDPAddr("127.0.0.1:4433"), primary: linkLocal, want: false},
		{name: "loopback, IPAddr loopback primary", addr: mustUDPAddr("127.0.0.1:4433"), primary: &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}, want: true},
		{name: "loopback, TCPAddr loopback primary", addr: mustUDPAddr("127.0.0.1:4433"), primary: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}, want: true},
		{name: "loopback, other net.Addr loopback primary", addr: mustUDPAddr("127.0.0.1:4433"), primary: usablePeerAddressTestAddr("127.0.0.1:443"), want: true},
		{name: "loopback, other net.Addr public primary", addr: mustUDPAddr("127.0.0.1:4433"), primary: usablePeerAddressTestAddr("198.51.100.1:443"), want: false},
		{name: "loopback, unparsable primary", addr: mustUDPAddr("127.0.0.1:4433"), primary: usablePeerAddressTestAddr("localhost"), want: false},

		{name: "link-local, public primary", addr: mustUDPAddr("169.254.1.1:4433"), primary: public, want: false},
		{name: "link-local, loopback primary", addr: mustUDPAddr("169.254.1.1:4433"), primary: loopback, want: false},
		{name: "link-local, link-local primary", addr: mustUDPAddr("169.254.1.1:4433"), primary: linkLocal, want: true},
		{name: "IPv6 link-local, public primary", addr: mustUDPAddr("[fe80::2]:4433"), primary: public, want: false},
		{name: "IPv6 link-local, IPv6 link-local primary", addr: mustUDPAddr("[fe80::2]:4433"), primary: linkLocal6, want: true},
		{name: "public, loopback primary", addr: mustUDPAddr("203.0.113.5:4433"), primary: loopback, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, usablePeerAddress(tt.addr, tt.primary))
		})
	}
}

func TestAdvertisableAddress(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{addr: "203.0.113.5:4433", want: true},
		{addr: "[2001:db8::1]:4433", want: true},
		{addr: "127.0.0.2:4433", want: true}, // the peer decides if it uses loopback addresses
		{addr: "[fe80::1]:4433", want: true},
		{addr: "[::ffff:203.0.113.5]:4433", want: true},
		{addr: "203.0.113.5:0", want: false},
		{addr: "0.0.0.0:4433", want: false},
		{addr: "[::]:4433", want: false},
		{addr: "224.0.0.1:4433", want: false},
		{addr: "[ff02::1]:4433", want: false},
		{addr: "255.255.255.255:4433", want: false},
		{addr: "[::ffff:255.255.255.255]:4433", want: false},
	} {
		t.Run(tc.addr, func(t *testing.T) {
			require.Equal(t, tc.want, advertisableAddress(netip.MustParseAddrPort(tc.addr)))
		})
	}
	require.False(t, advertisableAddress(netip.AddrPort{}))
}

func TestAddressAdvertisementAdvertise(t *testing.T) {
	var a addressAdvertisement
	f, err := a.advertise(netip.MustParseAddrPort("192.0.2.1:443"))
	require.NoError(t, err)
	require.Equal(t, &wire.AddAddressFrame{AddressID: 0, IPVersion: 4, Address: []byte{192, 0, 2, 1}, Port: 443}, f)
	f, err = a.advertise(netip.MustParseAddrPort("[2001:db8::1]:4433"))
	require.NoError(t, err)
	require.Equal(t, &wire.AddAddressFrame{AddressID: 1, IPVersion: 6, Address: []byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}, Port: 4433}, f)
	// advertising an address again doesn't create a frame
	f, err = a.advertise(netip.MustParseAddrPort("192.0.2.1:443"))
	require.NoError(t, err)
	require.Nil(t, f)
	// the same IP with another port is another address
	f, err = a.advertise(netip.MustParseAddrPort("192.0.2.1:444"))
	require.NoError(t, err)
	require.Equal(t, uint64(2), f.AddressID)

	for i := 3; i < protocol.MaxAdvertisedAddresses; i++ {
		f, err := a.advertise(netip.MustParseAddrPort(fmt.Sprintf("192.0.2.%d:443", i)))
		require.NoError(t, err)
		require.Equal(t, uint64(i), f.AddressID)
	}
	_, err = a.advertise(netip.MustParseAddrPort("198.51.100.1:443"))
	require.ErrorIs(t, err, ErrTooManyAdvertisedAddresses)
	// the frames can be serialized
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	require.Len(t, b, int(f.Length(protocol.Version1)))
}

func TestAddressAdvertisementPeerAddresses(t *testing.T) {
	addr1 := netip.MustParseAddrPort("192.0.2.1:443")
	addr2 := netip.MustParseAddrPort("192.0.2.2:443")
	addr3 := netip.MustParseAddrPort("[2001:db8::3]:443")

	var a addressAdvertisement
	require.Empty(t, a.peerAddresses())
	adv, ok := a.addPeerAddress(5, 0, addr1)
	require.True(t, ok)
	require.Equal(t, AdvertisedAddress{ID: 5, Addr: addr1}, adv)
	_, ok = a.addPeerAddress(2, 7, addr2)
	require.True(t, ok)
	// the addresses are sorted by their address IDs
	require.Equal(t, []AdvertisedAddress{{ID: 2, Addr: addr2}, {ID: 5, Addr: addr1}}, a.peerAddresses())

	// retransmissions and reordered frames don't change anything
	_, ok = a.addPeerAddress(5, 0, addr1)
	require.False(t, ok)
	_, ok = a.addPeerAddress(2, 6, addr3)
	require.False(t, ok)
	// an address that was advertised for another address ID is ignored
	_, ok = a.addPeerAddress(9, 0, addr1)
	require.False(t, ok)
	require.Equal(t, []AdvertisedAddress{{ID: 2, Addr: addr2}, {ID: 5, Addr: addr1}}, a.peerAddresses())

	// a frame with a larger sequence number replaces the address of the address ID
	adv, ok = a.addPeerAddress(5, 1, addr3)
	require.True(t, ok)
	require.Equal(t, AdvertisedAddress{ID: 5, Addr: addr3}, adv)
	require.Equal(t, []AdvertisedAddress{{ID: 2, Addr: addr2}, {ID: 5, Addr: addr3}}, a.peerAddresses())
	// the same address with a larger sequence number: nothing changes, but older frames are ignored afterwards
	_, ok = a.addPeerAddress(2, 8, addr2)
	require.False(t, ok)
	_, ok = a.addPeerAddress(2, 8, addr1)
	require.False(t, ok)
	adv, ok = a.addPeerAddress(2, 9, addr1)
	require.True(t, ok)
	require.Equal(t, AdvertisedAddress{ID: 2, Addr: addr1}, adv)

	// the number of addresses is limited
	for i := len(a.peerAddresses()); i < protocol.MaxAdvertisedAddresses; i++ {
		_, ok := a.addPeerAddress(uint64(100+i), 0, netip.MustParseAddrPort(fmt.Sprintf("198.51.100.%d:443", i)))
		require.True(t, ok)
	}
	require.Len(t, a.peerAddresses(), protocol.MaxAdvertisedAddresses)
	_, ok = a.addPeerAddress(1000, 0, netip.MustParseAddrPort("203.0.113.1:443"))
	require.False(t, ok)
	require.Len(t, a.peerAddresses(), protocol.MaxAdvertisedAddresses)
	// known address IDs can still be updated
	_, ok = a.addPeerAddress(5, 2, netip.MustParseAddrPort("203.0.113.1:443"))
	require.True(t, ok)
}
