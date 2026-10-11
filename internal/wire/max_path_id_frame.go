package wire

import (
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/quicvarint"
)

// A MaxPathIDFrame is a MAX_PATH_ID frame of the multipath extension.
type MaxPathIDFrame struct {
	// MaximumPathID is not validated when parsing the frame:
	// values larger than protocol.MaxPathID are a PROTOCOL_VIOLATION (section 4.6 of draft-ietf-quic-multipath).
	MaximumPathID protocol.PathID
}

func parseMaxPathIDFrame(b []byte, _ protocol.Version) (*MaxPathIDFrame, int, error) {
	maxPathID, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	return &MaxPathIDFrame{MaximumPathID: protocol.PathID(maxPathID)}, l, nil
}

func (f *MaxPathIDFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, uint64(FrameTypeMaxPathID))
	return quicvarint.Append(b, uint64(f.MaximumPathID)), nil
}

// Length of a written frame
func (f *MaxPathIDFrame) Length(protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(2 + quicvarint.Len(uint64(f.MaximumPathID)))
}
