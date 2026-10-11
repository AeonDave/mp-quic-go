package protocol

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPacketQueueCapacities(t *testing.T) {
	// Ensure that the session can queue more packets than the 0-RTT queue
	require.Greater(t, MaxConnUnprocessedPackets, Max0RTTQueueLen)
	require.Greater(t, MaxUndecryptablePackets, Max0RTTQueueLen)
}

func TestMultipathLimits(t *testing.T) {
	// path IDs are 32 bit values (section 2.1 of draft-ietf-quic-multipath)
	require.Equal(t, PathID(0xffffffff), MaxPathID)
	require.Less(t, MaxPathID, InvalidPathID)
	// initial_max_path_id is derived from the number of paths, and must not exceed MaxPathID
	require.Greater(t, MaxMultipathPaths, 1)
	require.LessOrEqual(t, PathID(MaxMultipathPaths-1), MaxPathID)
}
