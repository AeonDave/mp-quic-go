package qlog

import (
	"testing"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"

	"github.com/stretchr/testify/require"
)

func TestEncryptionLevelToPacketType(t *testing.T) {
	require.Equal(t, "initial", string(EncryptionLevelToPacketType(protocol.EncryptionInitial)))
	require.Equal(t, "handshake", string(EncryptionLevelToPacketType(protocol.EncryptionHandshake)))
	require.Equal(t, "0RTT", string(EncryptionLevelToPacketType(protocol.Encryption0RTT)))
	require.Equal(t, "1RTT", string(EncryptionLevelToPacketType(protocol.Encryption1RTT)))
}

func TestCalculateDatagramPayloadChecksum(t *testing.T) {
	require.Equal(t, DatagramPayloadChecksum(0xe3069283), CalculateDatagramPayloadChecksum([]byte("123456789")))
}

func TestMultipathTransportErrorNames(t *testing.T) {
	require.Equal(t, "application_abandon_path", transportError(qerr.ApplicationAbandonPath).String())
	require.Equal(t, "path_resource_limit_reached", transportError(qerr.PathResourceLimitReached).String())
	require.Equal(t, "path_unstable_or_poor", transportError(qerr.PathUnstableOrPoor).String())
	require.Equal(t, "no_cid_available_for_path", transportError(qerr.NoCIDAvailableForPath).String())
}

func TestVersionNegotiationErrorName(t *testing.T) {
	require.Equal(t, "version_negotiation_error", transportError(qerr.VersionNegotiationErrorCode).String())
}
