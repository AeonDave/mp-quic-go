package wire

import (
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/quicvarint"
)

// AddAddressFrame is an ADD_ADDRESS frame used to announce a new address to the peer.
// This is part of multipath QUIC extensions.
type AddAddressFrame struct {
	// AddressID uniquely identifies this address
	AddressID uint64
	// SequenceNumber for this announcement
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
	b = quicvarint.Append(b, uint64(FrameTypeAddAddress))
	b = quicvarint.Append(b, f.AddressID)
	b = quicvarint.Append(b, f.SequenceNumber)
	b = append(b, f.IPVersion)

	if f.IPVersion == 4 && len(f.Address) != 4 {
		return nil, errors.New("IPv4 address must be 4 bytes")
	}
	if f.IPVersion == 6 && len(f.Address) != 16 {
		return nil, errors.New("IPv6 address must be 16 bytes")
	}

	b = append(b, f.Address...)
	b = append(b, byte(f.Port>>8), byte(f.Port))

	return b, nil
}

// Length of a written frame
func (f *AddAddressFrame) Length(_ protocol.Version) protocol.ByteCount {
	addrLen := protocol.ByteCount(len(f.Address))
	return protocol.ByteCount(quicvarint.Len(uint64(FrameTypeAddAddress))) +
		protocol.ByteCount(quicvarint.Len(f.AddressID)) +
		protocol.ByteCount(quicvarint.Len(f.SequenceNumber)) +
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
