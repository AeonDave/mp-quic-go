package wire

import (
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/quicvarint"
)

var errVarintTooLarge = errors.New("value doesn't fit into a varint")

// AddAddressFrame is an ADD_ADDRESS frame used to announce an address to the peer.
// It belongs to the address advertisement extension of this module (see FrameTypeAddAddress), which is negotiated
// using the add_address transport parameter. The frame parser only accepts it after EnableAddAddress was called.
type AddAddressFrame struct {
	// AddressID identifies the address
	AddressID uint64
	// SequenceNumber orders the announcements of an address ID: the announcement with the largest
	// sequence number is the current address of the address ID
	SequenceNumber uint64
	// IPVersion is 4 for IPv4, 6 for IPv6
	IPVersion uint8
	// Address is the IP address bytes (4 bytes for IPv4, 16 for IPv6)
	Address []byte
	// Port is the UDP port number
	Port uint16
}

func parseAddAddressFrame(b []byte, _ protocol.Version) (*AddAddressFrame, int, error) {
	startLen := len(b)

	// Parse AddressID
	addrID, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]

	// Parse SequenceNumber
	seqNum, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]

	// Parse IPVersion
	if len(b) < 1 {
		return nil, 0, io.EOF
	}
	ipVersion := b[0]
	b = b[1:]

	if ipVersion != 4 && ipVersion != 6 {
		return nil, 0, fmt.Errorf("invalid IP version: %d", ipVersion)
	}

	// Parse Address
	addrLen := 4
	if ipVersion == 6 {
		addrLen = 16
	}
	if len(b) < addrLen {
		return nil, 0, io.EOF
	}
	address := make([]byte, addrLen)
	copy(address, b[:addrLen])
	b = b[addrLen:]

	// Parse Port
	if len(b) < 2 {
		return nil, 0, io.EOF
	}
	port := uint16(b[0])<<8 | uint16(b[1])
	b = b[2:]

	frame := &AddAddressFrame{
		AddressID:      addrID,
		SequenceNumber: seqNum,
		IPVersion:      ipVersion,
		Address:        address,
		Port:           port,
	}

	return frame, startLen - len(b), nil
}

func (f *AddAddressFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	if f.AddressID > quicvarint.Max || f.SequenceNumber > quicvarint.Max {
		return nil, errVarintTooLarge
	}
	b = quicvarint.Append(b, uint64(FrameTypeAddAddress))
	b = quicvarint.Append(b, f.AddressID)
	b = quicvarint.Append(b, f.SequenceNumber)
	b = append(b, f.IPVersion)

	switch f.IPVersion {
	case 4:
		if len(f.Address) != 4 {
			return nil, errors.New("IPv4 address must be 4 bytes")
		}
	case 6:
		if len(f.Address) != 16 {
			return nil, errors.New("IPv6 address must be 16 bytes")
		}
	default:
		// the peer would fail to parse this frame
		return nil, fmt.Errorf("invalid IP version: %d", f.IPVersion)
	}

	b = append(b, f.Address...)
	b = append(b, byte(f.Port>>8), byte(f.Port))

	return b, nil
}

// Length of a written frame
func (f *AddAddressFrame) Length(_ protocol.Version) protocol.ByteCount {
	addrLen := protocol.ByteCount(len(f.Address))
	return protocol.ByteCount(quicvarint.Len(uint64(FrameTypeAddAddress))) +
		protocol.ByteCount(varintLen(f.AddressID)) +
		protocol.ByteCount(varintLen(f.SequenceNumber)) +
		1 + // IP version
		addrLen +
		2 // port
}

// GetIPAddress returns the IP address as net.IP
func (f *AddAddressFrame) GetIPAddress() net.IP {
	return net.IP(f.Address)
}

// GetUDPAddr returns the full UDP address
func (f *AddAddressFrame) GetUDPAddr() *net.UDPAddr {
	return &net.UDPAddr{
		IP:   f.GetIPAddress(),
		Port: int(f.Port),
	}
}

// varintLen returns the length of a varint.
// Unlike quicvarint.Len, it doesn't panic for values that are too large: Append returns an error for those.
func varintLen(v uint64) int {
	if v > quicvarint.Max {
		return 8
	}
	return quicvarint.Len(v)
}
