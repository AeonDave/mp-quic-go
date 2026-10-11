package wire

import (
	"errors"
	"fmt"
	"io"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/quicvarint"
)

// A PathNewConnectionIDFrame is a PATH_NEW_CONNECTION_ID frame of the multipath extension.
// Sequence numbers are counted per path.
type PathNewConnectionIDFrame struct {
	PathID              protocol.PathID
	SequenceNumber      uint64
	RetirePriorTo       uint64
	ConnectionID        protocol.ConnectionID
	StatelessResetToken protocol.StatelessResetToken
}

func parsePathNewConnectionIDFrame(b []byte, _ protocol.Version) (*PathNewConnectionIDFrame, int, error) {
	startLen := len(b)
	pathID, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	seq, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	ret, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	if ret > seq {
		//nolint:staticcheck // SA1021: Retire Prior To is the name of the field
		return nil, 0, fmt.Errorf("Retire Prior To value (%d) larger than Sequence Number (%d)", ret, seq)
	}
	if len(b) == 0 {
		return nil, 0, io.EOF
	}
	connIDLen := int(b[0])
	b = b[1:]
	if connIDLen == 0 {
		return nil, 0, errors.New("invalid zero-length connection ID")
	}
	if connIDLen > protocol.MaxConnIDLen {
		return nil, 0, protocol.ErrInvalidConnectionIDLen
	}
	if len(b) < connIDLen {
		return nil, 0, io.EOF
	}
	frame := &PathNewConnectionIDFrame{
		PathID:         protocol.PathID(pathID),
		SequenceNumber: seq,
		RetirePriorTo:  ret,
		ConnectionID:   protocol.ParseConnectionID(b[:connIDLen]),
	}
	b = b[connIDLen:]
	if len(b) < len(frame.StatelessResetToken) {
		return nil, 0, io.EOF
	}
	copy(frame.StatelessResetToken[:], b)
	return frame, startLen - len(b) + len(frame.StatelessResetToken), nil
}

func (f *PathNewConnectionIDFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	connIDLen := f.ConnectionID.Len()
	if connIDLen > protocol.MaxConnIDLen {
		return nil, fmt.Errorf("invalid connection ID length: %d", connIDLen)
	}
	b = quicvarint.Append(b, uint64(FrameTypePathNewConnectionID))
	b = quicvarint.Append(b, uint64(f.PathID))
	b = quicvarint.Append(b, f.SequenceNumber)
	b = quicvarint.Append(b, f.RetirePriorTo)
	b = append(b, uint8(connIDLen))
	b = append(b, f.ConnectionID.Bytes()...)
	return append(b, f.StatelessResetToken[:]...), nil
}

// Length of a written frame
func (f *PathNewConnectionIDFrame) Length(protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(2+quicvarint.Len(uint64(f.PathID))+quicvarint.Len(f.SequenceNumber)+quicvarint.Len(f.RetirePriorTo)+1 /* connection ID length */ +f.ConnectionID.Len()) + 16
}
