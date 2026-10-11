package wire

import (
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/quicvarint"
)

// A PathsBlockedFrame is a PATHS_BLOCKED frame of the multipath extension.
type PathsBlockedFrame struct {
	MaximumPathID protocol.PathID
}

func parsePathsBlockedFrame(b []byte, _ protocol.Version) (*PathsBlockedFrame, int, error) {
	maxPathID, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	return &PathsBlockedFrame{MaximumPathID: protocol.PathID(maxPathID)}, l, nil
}

func (f *PathsBlockedFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, uint64(FrameTypePathsBlocked))
	return quicvarint.Append(b, uint64(f.MaximumPathID)), nil
}

// Length of a written frame
func (f *PathsBlockedFrame) Length(protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(2 + quicvarint.Len(uint64(f.MaximumPathID)))
}
