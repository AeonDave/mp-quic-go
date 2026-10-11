package wire

import (
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/quicvarint"
)

// A PathCIDsBlockedFrame is a PATH_CIDS_BLOCKED frame of the multipath extension.
type PathCIDsBlockedFrame struct {
	PathID             protocol.PathID
	NextSequenceNumber uint64
}

func parsePathCIDsBlockedFrame(b []byte, _ protocol.Version) (*PathCIDsBlockedFrame, int, error) {
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
	return &PathCIDsBlockedFrame{
		PathID:             protocol.PathID(pathID),
		NextSequenceNumber: seq,
	}, startLen - len(b), nil
}

func (f *PathCIDsBlockedFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, uint64(FrameTypePathCIDsBlocked))
	b = quicvarint.Append(b, uint64(f.PathID))
	return quicvarint.Append(b, f.NextSequenceNumber), nil
}

// Length of a written frame
func (f *PathCIDsBlockedFrame) Length(protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(2 + quicvarint.Len(uint64(f.PathID)) + quicvarint.Len(f.NextSequenceNumber))
}
