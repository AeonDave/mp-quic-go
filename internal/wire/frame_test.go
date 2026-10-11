package wire

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProbingFrames(t *testing.T) {
	testCases := map[Frame]bool{
		&AckFrame{}:             false,
		&ConnectionCloseFrame{}: false,
		&DataBlockedFrame{}:     false,
		&PingFrame{}:            false,
		&ResetStreamFrame{}:     false,
		&StreamFrame{}:          false,
		&DatagramFrame{}:        false,
		&MaxDataFrame{}:         false,
		&MaxStreamDataFrame{}:   false,
		&StopSendingFrame{}:     false,
		&PathChallengeFrame{}:   true,
		&PathResponseFrame{}:    true,
		&NewConnectionIDFrame{}: true,
		// multipath extension: none of its frames is a probing frame (section 9.1 of RFC 9000)
		&AckFrame{HasPathID: true}:     false,
		&PathAbandonFrame{}:            false,
		&PathStatusFrame{}:             false,
		&PathStatusFrame{Backup: true}: false,
		&PathNewConnectionIDFrame{}:    false,
		&PathRetireConnectionIDFrame{}: false,
		&MaxPathIDFrame{}:              false,
		&PathsBlockedFrame{}:           false,
		&PathCIDsBlockedFrame{}:        false,
		&AddAddressFrame{}:             false,
	}

	for f, expected := range testCases {
		require.Equal(t, expected, IsProbingFrame(f), "%#v", f)
	}
}

func TestIsProbingFrameType(t *testing.T) {
	tests := map[FrameType]bool{
		FrameTypePathChallenge:   true,
		FrameTypePathResponse:    true,
		FrameTypeNewConnectionID: true,
		FrameType(0x01):          false,
		FrameType(0xFF):          false,
		// multipath extension: none of its frames is a probing frame (section 9.1 of RFC 9000)
		FrameTypePathAck:                false,
		FrameTypePathAckECN:             false,
		FrameTypePathAbandon:            false,
		FrameTypePathStatusBackup:       false,
		FrameTypePathStatusAvailable:    false,
		FrameTypePathNewConnectionID:    false,
		FrameTypePathRetireConnectionID: false,
		FrameTypeMaxPathID:              false,
		FrameTypePathsBlocked:           false,
		FrameTypePathCIDsBlocked:        false,
		FrameTypeAddAddress:             false,
	}
	for ft, expected := range tests {
		require.Equal(t, expected, IsProbingFrameType(ft))
	}
}
