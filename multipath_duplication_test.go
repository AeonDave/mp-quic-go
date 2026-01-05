package quic

import (
	"testing"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestMultipathDuplicationPolicy_Creation(t *testing.T) {
	policy := NewMultipathDuplicationPolicy()
	require.NotNil(t, policy)
	require.False(t, policy.IsEnabled())

	// Enable to check defaults
	policy.Enable()
	require.True(t, policy.ShouldDuplicateCrypto())     // Default enabled
	require.True(t, policy.ShouldDuplicateReset())      // Default enabled
	require.Equal(t, 2, policy.GetDuplicatePathCount()) // Default 2 paths
}

func TestMultipathDuplicationPolicy_EnableDisable(t *testing.T) {
	policy := NewMultipathDuplicationPolicy()

	require.False(t, policy.IsEnabled())

	policy.Enable()
	require.True(t, policy.IsEnabled())

	policy.Disable()
	require.False(t, policy.IsEnabled())
}

func TestMultipathDuplicationPolicy_StreamDuplication(t *testing.T) {
	policy := NewMultipathDuplicationPolicy()
	policy.Enable()

	streamID := protocol.StreamID(42)

	// Initially not marked for duplication
	require.False(t, policy.ShouldDuplicateStream(streamID))

	// Mark for duplication
	policy.AddStreamForDuplication(streamID)
	require.True(t, policy.ShouldDuplicateStream(streamID))

	// Remove from duplication
	policy.RemoveStreamForDuplication(streamID)
	require.False(t, policy.ShouldDuplicateStream(streamID))
}

func TestMultipathDuplicationPolicy_CryptoFrames(t *testing.T) {
	policy := NewMultipathDuplicationPolicy()

	// Crypto frames enabled by default
	policy.Enable()
	require.True(t, policy.ShouldDuplicateCrypto())

	// Disable crypto duplication
	policy.SetDuplicateCryptoFrames(false)
	require.False(t, policy.ShouldDuplicateCrypto())

	// Re-enable
	policy.SetDuplicateCryptoFrames(true)
	require.True(t, policy.ShouldDuplicateCrypto())

	// Should return false when policy disabled
	policy.Disable()
	require.False(t, policy.ShouldDuplicateCrypto())
}

func TestMultipathDuplicationPolicy_ResetFrames(t *testing.T) {
	policy := NewMultipathDuplicationPolicy()

	// Reset frames enabled by default
	policy.Enable()
	require.True(t, policy.ShouldDuplicateReset())

	// Disable reset duplication
	policy.SetDuplicateResets(false)
	require.False(t, policy.ShouldDuplicateReset())

	// Re-enable
	policy.SetDuplicateResets(true)
	require.True(t, policy.ShouldDuplicateReset())

	// Should return false when policy disabled
	policy.Disable()
	require.False(t, policy.ShouldDuplicateReset())
}

func TestMultipathDuplicationPolicy_PathCount(t *testing.T) {
	policy := NewMultipathDuplicationPolicy()

	// Default is 2 paths
	require.Equal(t, 2, policy.GetDuplicatePathCount())

	// Set to 3 paths
	policy.SetDuplicatePathCount(3)
	require.Equal(t, 3, policy.GetDuplicatePathCount())

	// Cannot go below 1
	policy.SetDuplicatePathCount(0)
	require.Equal(t, 1, policy.GetDuplicatePathCount())

	policy.SetDuplicatePathCount(-5)
	require.Equal(t, 1, policy.GetDuplicatePathCount())

	// Cannot exceed maxDuplicates (3)
	policy.SetDuplicatePathCount(10)
	require.Equal(t, 3, policy.GetDuplicatePathCount())
}

func TestMultipathDuplicationPolicy_MultipleStreams(t *testing.T) {
	policy := NewMultipathDuplicationPolicy()
	policy.Enable()

	stream1 := protocol.StreamID(1)
	stream2 := protocol.StreamID(2)
	stream3 := protocol.StreamID(3)

	// Add multiple streams
	policy.AddStreamForDuplication(stream1)
	policy.AddStreamForDuplication(stream2)
	policy.AddStreamForDuplication(stream3)

	require.True(t, policy.ShouldDuplicateStream(stream1))
	require.True(t, policy.ShouldDuplicateStream(stream2))
	require.True(t, policy.ShouldDuplicateStream(stream3))
	require.False(t, policy.ShouldDuplicateStream(protocol.StreamID(99)))

	// Remove one stream
	policy.RemoveStreamForDuplication(stream2)
	require.True(t, policy.ShouldDuplicateStream(stream1))
	require.False(t, policy.ShouldDuplicateStream(stream2))
	require.True(t, policy.ShouldDuplicateStream(stream3))
}

func TestMultipathDuplicationPolicy_DisabledIgnoresSettings(t *testing.T) {
	policy := NewMultipathDuplicationPolicy()

	streamID := protocol.StreamID(42)
	policy.AddStreamForDuplication(streamID)

	// When disabled, all should return false
	require.False(t, policy.ShouldDuplicateStream(streamID))
	require.False(t, policy.ShouldDuplicateCrypto())
	require.False(t, policy.ShouldDuplicateReset())

	// Enable and check again
	policy.Enable()
	require.True(t, policy.ShouldDuplicateStream(streamID))
	require.True(t, policy.ShouldDuplicateCrypto())
	require.True(t, policy.ShouldDuplicateReset())
}
