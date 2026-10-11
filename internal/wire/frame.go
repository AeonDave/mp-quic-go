package wire

import (
	"github.com/AeonDave/mp-quic-go/internal/protocol"
)

// A Frame in QUIC
type Frame interface {
	Append(b []byte, version protocol.Version) ([]byte, error)
	Length(version protocol.Version) protocol.ByteCount
}

// IsProbingFrame returns true if the frame is a probing frame.
// See section 9.1 of RFC 9000.
// The OBSERVED_ADDRESS frame is a probing frame as well (section 4.1 of draft-ietf-quic-address-discovery-01).
func IsProbingFrame(f Frame) bool {
	switch f.(type) {
	case *PathChallengeFrame, *PathResponseFrame, *NewConnectionIDFrame, *ObservedAddressFrame:
		return true
	}
	return false
}

// IsProbingFrameType returns true if the FrameType is a probing frame.
// See section 9.1 of RFC 9000, and section 4.1 of draft-ietf-quic-address-discovery-01.
func IsProbingFrameType(f FrameType) bool {
	//nolint:exhaustive // PATH_CHALLENGE, PATH_RESPONSE, NEW_CONNECTION_ID and OBSERVED_ADDRESS are the only probing frames
	switch f {
	case FrameTypePathChallenge, FrameTypePathResponse, FrameTypeNewConnectionID,
		FrameTypeObservedAddressIPv4, FrameTypeObservedAddressIPv6:
		return true
	default:
		return false
	}
}
