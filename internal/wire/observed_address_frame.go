package wire

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/quicvarint"
)

// An ObservedAddressFrame is an OBSERVED_ADDRESS frame of QUIC Address Discovery
// (draft-ietf-quic-address-discovery-01). It reports the address that the sender observed for the receiver.
// IPv4 addresses are sent in a frame of type FrameTypeObservedAddressIPv4, all other addresses
// (including IPv4-mapped IPv6 addresses) in a frame of type FrameTypeObservedAddressIPv6.
type ObservedAddressFrame struct {
	SequenceNumber uint64
	Address        netip.AddrPort
}

func parseObservedAddressFrame(b []byte, typ FrameType, _ protocol.Version) (*ObservedAddressFrame, int, error) {
	startLen := len(b)
	seq, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	var ip netip.Addr
	if typ == FrameTypeObservedAddressIPv4 {
		if len(b) < 4+2 {
			return nil, 0, io.EOF
		}
		ip = netip.AddrFrom4([4]byte(b[:4]))
		b = b[4:]
	} else {
		if len(b) < 16+2 {
			return nil, 0, io.EOF
		}
		ip = netip.AddrFrom16([16]byte(b[:16]))
		b = b[16:]
	}
	port := binary.BigEndian.Uint16(b[:2])
	b = b[2:]
	return &ObservedAddressFrame{
		SequenceNumber: seq,
		Address:        netip.AddrPortFrom(ip, port),
	}, startLen - len(b), nil
}

func (f *ObservedAddressFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	if !f.Address.Addr().IsValid() {
		return nil, errors.New("invalid address")
	}
	if f.SequenceNumber > quicvarint.Max {
		return nil, errVarintTooLarge
	}
	ip := f.Address.Addr()
	if ip.Is4() {
		b = quicvarint.Append(b, uint64(FrameTypeObservedAddressIPv4))
		b = quicvarint.Append(b, f.SequenceNumber)
		ipv4 := ip.As4()
		b = append(b, ipv4[:]...)
	} else {
		b = quicvarint.Append(b, uint64(FrameTypeObservedAddressIPv6))
		b = quicvarint.Append(b, f.SequenceNumber)
		ipv6 := ip.As16()
		b = append(b, ipv6[:]...)
	}
	return binary.BigEndian.AppendUint16(b, f.Address.Port()), nil
}

// Length of a written frame
func (f *ObservedAddressFrame) Length(_ protocol.Version) protocol.ByteCount {
	addrLen := 16
	if f.Address.Addr().Is4() {
		addrLen = 4
	}
	// Both frame types are encoded in 4 bytes.
	return protocol.ByteCount(4 + varintLen(f.SequenceNumber) + addrLen + 2)
}
