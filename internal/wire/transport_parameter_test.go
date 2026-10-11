package wire

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	mrand "math/rand/v2"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/quicvarint"

	ossfuzzseeds "github.com/quic-go/go-ossfuzz-seeds"

	"github.com/stretchr/testify/require"
)

func getRandomValueUpTo(max uint64) uint64 {
	maxVals := []uint64{math.MaxUint8 / 4, math.MaxUint16 / 4, math.MaxUint32 / 4, math.MaxUint64 / 4}
	return mrand.Uint64N(min(max, maxVals[mrand.IntN(4)]))
}

func getRandomValue() uint64 { return getRandomValueUpTo(quicvarint.Max) }

func appendInitialSourceConnectionID(b []byte) []byte {
	b = quicvarint.Append(b, uint64(initialSourceConnectionIDParameterID))
	b = quicvarint.Append(b, 6)
	return append(b, []byte("foobar")...)
}

func TestTransportParametersStringRepresentation(t *testing.T) {
	rcid := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xc0, 0xde})
	minAckDelay := 42 * time.Millisecond
	p := &TransportParameters{
		InitialMaxStreamDataBidiLocal:   1234,
		InitialMaxStreamDataBidiRemote:  2345,
		InitialMaxStreamDataUni:         3456,
		InitialMaxData:                  4567,
		MaxBidiStreamNum:                1337,
		MaxUniStreamNum:                 7331,
		MaxIdleTimeout:                  42 * time.Second,
		OriginalDestinationConnectionID: protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
		InitialSourceConnectionID:       protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad}),
		RetrySourceConnectionID:         &rcid,
		AckDelayExponent:                14,
		MaxAckDelay:                     37 * time.Millisecond,
		StatelessResetToken:             &protocol.StatelessResetToken{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00},
		ActiveConnectionIDLimit:         123,
		MaxDatagramFrameSize:            876,
		EnableResetStreamAt:             true,
		MinAckDelay:                     &minAckDelay,
	}
	expected := "&wire.TransportParameters{OriginalDestinationConnectionID: deadbeef, InitialSourceConnectionID: decafbad, RetrySourceConnectionID: deadc0de, InitialMaxStreamDataBidiLocal: 1234, InitialMaxStreamDataBidiRemote: 2345, InitialMaxStreamDataUni: 3456, InitialMaxData: 4567, MaxBidiStreamNum: 1337, MaxUniStreamNum: 7331, MaxIdleTimeout: 42s, AckDelayExponent: 14, MaxAckDelay: 37ms, ActiveConnectionIDLimit: 123, StatelessResetToken: 0x112233445566778899aabbccddeeff00, MaxDatagramFrameSize: 876, EnableResetStreamAt: true, MinAckDelay: 42ms}"
	require.Equal(t, expected, p.String())
}

func TestTransportParametersStringRepresentationWithInitialMaxPathID(t *testing.T) {
	p := &TransportParameters{
		OriginalDestinationConnectionID: protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
		InitialSourceConnectionID:       protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad}),
		ActiveConnectionIDLimit:         2,
		MaxDatagramFrameSize:            protocol.InvalidByteCount,
		InitialMaxPathID:                42,
		HasInitialMaxPathID:             true,
	}
	expected := "&wire.TransportParameters{OriginalDestinationConnectionID: deadbeef, InitialSourceConnectionID: decafbad, InitialMaxStreamDataBidiLocal: 0, InitialMaxStreamDataBidiRemote: 0, InitialMaxStreamDataUni: 0, InitialMaxData: 0, MaxBidiStreamNum: 0, MaxUniStreamNum: 0, MaxIdleTimeout: 0s, AckDelayExponent: 0, MaxAckDelay: 0s, ActiveConnectionIDLimit: 2, EnableResetStreamAt: false, InitialMaxPathID: 42}"
	require.Equal(t, expected, p.String())

	p.InitialMaxPathID = 0
	require.Contains(t, p.String(), "InitialMaxPathID: 0}")
	p.HasInitialMaxPathID = false
	require.NotContains(t, p.String(), "InitialMaxPathID")
}

func TestTransportParametersStringRepresentationWithoutOptionalFields(t *testing.T) {
	p := &TransportParameters{
		InitialMaxStreamDataBidiLocal:   1234,
		InitialMaxStreamDataBidiRemote:  2345,
		InitialMaxStreamDataUni:         3456,
		InitialMaxData:                  4567,
		MaxBidiStreamNum:                1337,
		MaxUniStreamNum:                 7331,
		MaxIdleTimeout:                  42 * time.Second,
		OriginalDestinationConnectionID: protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
		InitialSourceConnectionID:       protocol.ParseConnectionID([]byte{}),
		AckDelayExponent:                14,
		MaxAckDelay:                     37 * time.Second,
		ActiveConnectionIDLimit:         89,
		MaxDatagramFrameSize:            protocol.InvalidByteCount,
	}
	expected := "&wire.TransportParameters{OriginalDestinationConnectionID: deadbeef, InitialSourceConnectionID: (empty), InitialMaxStreamDataBidiLocal: 1234, InitialMaxStreamDataBidiRemote: 2345, InitialMaxStreamDataUni: 3456, InitialMaxData: 4567, MaxBidiStreamNum: 1337, MaxUniStreamNum: 7331, MaxIdleTimeout: 42s, AckDelayExponent: 14, MaxAckDelay: 37s, ActiveConnectionIDLimit: 89, EnableResetStreamAt: false}"
	require.Equal(t, expected, p.String())
}

func TestMarshalAndUnmarshalTransportParameters(t *testing.T) {
	var token protocol.StatelessResetToken
	rand.Read(token[:])
	rcid := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xc0, 0xde})
	minAckDelay := 42 * time.Millisecond
	params := &TransportParameters{
		InitialMaxStreamDataBidiLocal:   protocol.ByteCount(getRandomValue()),
		InitialMaxStreamDataBidiRemote:  protocol.ByteCount(getRandomValue()),
		InitialMaxStreamDataUni:         protocol.ByteCount(getRandomValue()),
		InitialMaxData:                  protocol.ByteCount(getRandomValue()),
		MaxIdleTimeout:                  0xcafe * time.Second,
		MaxBidiStreamNum:                protocol.StreamNum(getRandomValueUpTo(uint64(protocol.MaxStreamCount))),
		MaxUniStreamNum:                 protocol.StreamNum(getRandomValueUpTo(uint64(protocol.MaxStreamCount))),
		DisableActiveMigration:          true,
		StatelessResetToken:             &token,
		OriginalDestinationConnectionID: protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
		InitialSourceConnectionID:       protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad}),
		RetrySourceConnectionID:         &rcid,
		AckDelayExponent:                13,
		MaxAckDelay:                     42 * time.Millisecond,
		ActiveConnectionIDLimit:         2 + getRandomValueUpTo(quicvarint.Max-2),
		MaxUDPPayloadSize:               1200 + protocol.ByteCount(getRandomValueUpTo(quicvarint.Max-1200)),
		MaxDatagramFrameSize:            protocol.ByteCount(getRandomValue()),
		EnableResetStreamAt:             getRandomValue()%2 == 0,
		MinAckDelay:                     &minAckDelay,
		InitialMaxPathID:                protocol.PathID(getRandomValue()),
		HasInitialMaxPathID:             true,
		EnableAddAddress:                getRandomValue()%2 == 0,
		AddressDiscovery:                AddressDiscoveryMode(1 + getRandomValueUpTo(3)),
		GreaseQUICBit:                   getRandomValue()%2 == 0,
		VersionInformation: &VersionInformation{
			ChosenVersion:     protocol.Version2,
			AvailableVersions: []protocol.Version{protocol.Version1, protocol.Version2, 0x1a2a3a4a},
		},
	}
	data := params.Marshal(protocol.PerspectiveServer)

	p := &TransportParameters{}
	require.NoError(t, p.Unmarshal(data, protocol.PerspectiveServer))
	require.Equal(t, params.InitialMaxStreamDataBidiLocal, p.InitialMaxStreamDataBidiLocal)
	require.Equal(t, params.InitialMaxStreamDataBidiRemote, p.InitialMaxStreamDataBidiRemote)
	require.Equal(t, params.InitialMaxStreamDataUni, p.InitialMaxStreamDataUni)
	require.Equal(t, params.InitialMaxData, p.InitialMaxData)
	require.Equal(t, params.MaxUniStreamNum, p.MaxUniStreamNum)
	require.Equal(t, params.MaxBidiStreamNum, p.MaxBidiStreamNum)
	require.Equal(t, params.MaxIdleTimeout, p.MaxIdleTimeout)
	require.Equal(t, params.DisableActiveMigration, p.DisableActiveMigration)
	require.Equal(t, params.StatelessResetToken, p.StatelessResetToken)
	require.Equal(t, protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}), p.OriginalDestinationConnectionID)
	require.Equal(t, protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad}), p.InitialSourceConnectionID)
	require.Equal(t, &rcid, p.RetrySourceConnectionID)
	require.Equal(t, uint8(13), p.AckDelayExponent)
	require.Equal(t, 42*time.Millisecond, p.MaxAckDelay)
	require.Equal(t, params.ActiveConnectionIDLimit, p.ActiveConnectionIDLimit)
	require.Equal(t, params.MaxUDPPayloadSize, p.MaxUDPPayloadSize)
	require.Equal(t, params.MaxDatagramFrameSize, p.MaxDatagramFrameSize)
	require.Equal(t, params.EnableResetStreamAt, p.EnableResetStreamAt)
	require.NotNil(t, p.MinAckDelay)
	require.Equal(t, minAckDelay, *p.MinAckDelay)
	require.True(t, p.HasInitialMaxPathID)
	require.Equal(t, params.InitialMaxPathID, p.InitialMaxPathID)
	require.Equal(t, params.EnableAddAddress, p.EnableAddAddress)
	require.Equal(t, params.AddressDiscovery, p.AddressDiscovery)
	require.Equal(t, params.VersionInformation, p.VersionInformation)
	require.Equal(t, params.GreaseQUICBit, p.GreaseQUICBit)
}

// The grease_quic_bit transport parameter (RFC 9287) has an empty value.
func TestGreaseQUICBitTransportParameter(t *testing.T) {
	for _, pers := range []protocol.Perspective{protocol.PerspectiveClient, protocol.PerspectiveServer} {
		t.Run(pers.String(), func(t *testing.T) {
			params := &TransportParameters{
				StatelessResetToken:     &protocol.StatelessResetToken{},
				ActiveConnectionIDLimit: 2,
				MaxDatagramFrameSize:    protocol.InvalidByteCount,
			}
			if pers == protocol.PerspectiveClient {
				params.StatelessResetToken = nil
			}
			expected := quicvarint.Append(nil, 0x2ab2)
			expected = quicvarint.Append(expected, 0)

			data := params.Marshal(pers)
			require.False(t, bytes.Contains(data, expected))
			p := &TransportParameters{}
			require.NoError(t, p.Unmarshal(data, pers))
			require.False(t, p.GreaseQUICBit)
			require.NotContains(t, p.String(), "GreaseQUICBit")

			params.GreaseQUICBit = true
			data = params.Marshal(pers)
			require.True(t, bytes.Contains(data, expected))
			p = &TransportParameters{}
			require.NoError(t, p.Unmarshal(data, pers))
			require.True(t, p.GreaseQUICBit)
			require.Contains(t, p.String(), "GreaseQUICBit: true")
		})
	}

	// section 3 of RFC 9287
	t.Run("non-empty value", func(t *testing.T) {
		b := quicvarint.Append(nil, 0x2ab2)
		b = quicvarint.Append(b, 1)
		b = append(b, 1)
		b = appendInitialSourceConnectionID(b)
		err := (&TransportParameters{}).Unmarshal(b, protocol.PerspectiveClient)
		var transportErr *qerr.TransportError
		require.ErrorAs(t, err, &transportErr)
		require.Equal(t, qerr.TransportParameterError, transportErr.ErrorCode)
		require.Equal(t, "wrong length for grease_quic_bit: 1 (expected empty)", transportErr.ErrorMessage)
	})

	t.Run("duplicate", func(t *testing.T) {
		b := quicvarint.Append(nil, 0x2ab2)
		b = quicvarint.Append(b, 0)
		b = quicvarint.Append(b, 0x2ab2)
		b = quicvarint.Append(b, 0)
		b = appendInitialSourceConnectionID(b)
		err := (&TransportParameters{}).Unmarshal(b, protocol.PerspectiveClient)
		var transportErr *qerr.TransportError
		require.ErrorAs(t, err, &transportErr)
		require.Equal(t, qerr.TransportParameterError, transportErr.ErrorCode)
		require.Equal(t, "received duplicate transport parameter 0x2ab2", transportErr.ErrorMessage)
	})

	// A server must not set the QUIC Bit to 0 based on a previous connection (section 3.1 of RFC 9287).
	t.Run("not saved in session ticket", func(t *testing.T) {
		params := &TransportParameters{
			ActiveConnectionIDLimit: 2,
			MaxDatagramFrameSize:    protocol.InvalidByteCount,
			GreaseQUICBit:           true,
		}
		b := params.MarshalForSessionTicket(nil)
		var tp TransportParameters
		require.NoError(t, tp.UnmarshalFromSessionTicket(b))
		require.False(t, tp.GreaseQUICBit)

		b = quicvarint.Append(b, 0x2ab2)
		b = quicvarint.Append(b, 0)
		require.EqualError(t, tp.UnmarshalFromSessionTicket(b), "grease_quic_bit in session ticket")
	})
}

func TestVersionInformationTransportParameter(t *testing.T) {
	appendVersionInformation := func(b []byte, versions ...uint32) []byte {
		b = quicvarint.Append(b, uint64(versionInformationParameterID))
		b = quicvarint.Append(b, uint64(4*len(versions)))
		for _, v := range versions {
			b = binary.BigEndian.AppendUint32(b, v)
		}
		return b
	}

	t.Run("absent", func(t *testing.T) {
		data := (&TransportParameters{ActiveConnectionIDLimit: 2}).Marshal(protocol.PerspectiveClient)
		var p TransportParameters
		require.NoError(t, p.Unmarshal(data, protocol.PerspectiveClient))
		require.Nil(t, p.VersionInformation)
		require.NotContains(t, p.String(), "VersionInformation")
	})

	t.Run("wire encoding", func(t *testing.T) {
		data := (&TransportParameters{
			ActiveConnectionIDLimit: 2,
			VersionInformation: &VersionInformation{
				ChosenVersion:     protocol.Version1,
				AvailableVersions: []protocol.Version{protocol.Version1, protocol.Version2},
			},
		}).Marshal(protocol.PerspectiveClient)
		require.True(t, bytes.Contains(data, []byte{0x11, 12, 0, 0, 0, 1, 0, 0, 0, 1, 0x6b, 0x33, 0x43, 0xcf}))
	})

	t.Run("sent by the client", func(t *testing.T) {
		data := appendInitialSourceConnectionID(appendVersionInformation(nil, 1, 0x6b3343cf, 1))
		var p TransportParameters
		require.NoError(t, p.Unmarshal(data, protocol.PerspectiveClient))
		require.Equal(t, &VersionInformation{
			ChosenVersion:     protocol.Version1,
			AvailableVersions: []protocol.Version{protocol.Version2, protocol.Version1},
		}, p.VersionInformation)
		require.Contains(t, p.String(), "VersionInformation: {ChosenVersion: v1, AvailableVersions: [v2 v1]}")
	})

	t.Run("sent by the server, with empty Available Versions", func(t *testing.T) {
		// Section 3 of RFC 9368: the server's Available Versions field may be empty,
		// and it doesn't need to contain the Chosen Version.
		data := appendVersionInformation(nil, 0x6b3343cf)
		data = quicvarint.Append(data, uint64(originalDestinationConnectionIDParameterID))
		data = quicvarint.Append(data, 0)
		data = appendInitialSourceConnectionID(data)
		var p TransportParameters
		require.NoError(t, p.Unmarshal(data, protocol.PerspectiveServer))
		require.Equal(t, protocol.Version2, p.VersionInformation.ChosenVersion)
		require.Empty(t, p.VersionInformation.AvailableVersions)

		data = appendVersionInformation(nil, 0x6b3343cf, 1, 0x1a2a3a4a)
		data = quicvarint.Append(data, uint64(originalDestinationConnectionIDParameterID))
		data = quicvarint.Append(data, 0)
		data = appendInitialSourceConnectionID(data)
		require.NoError(t, p.Unmarshal(data, protocol.PerspectiveServer))
		require.Equal(t, []protocol.Version{protocol.Version1, 0x1a2a3a4a}, p.VersionInformation.AvailableVersions)
	})

	// Section 4 of RFC 9368: parsing failures are TRANSPORT_PARAMETER_ERRORs.
	for _, tc := range []struct {
		name   string
		data   []byte
		sentBy protocol.Perspective
		errMsg string
	}{
		{
			name:   "empty",
			data:   appendVersionInformation(nil),
			sentBy: protocol.PerspectiveClient,
			errMsg: "invalid length for version_information: 0",
		},
		{
			name: "length not divisible by four",
			data: func() []byte {
				b := quicvarint.Append(nil, uint64(versionInformationParameterID))
				b = quicvarint.Append(b, 6)
				return append(b, 0, 0, 0, 1, 0, 0)
			}(),
			sentBy: protocol.PerspectiveServer,
			errMsg: "invalid length for version_information: 6",
		},
		{
			name:   "Chosen Version is 0",
			data:   appendVersionInformation(nil, 0, 1),
			sentBy: protocol.PerspectiveServer,
			errMsg: "version_information: Chosen Version is 0",
		},
		{
			name:   "Available Version is 0",
			data:   appendVersionInformation(nil, 1, 1, 0),
			sentBy: protocol.PerspectiveServer,
			errMsg: "version_information: Available Version is 0",
		},
		{
			name:   "client's Chosen Version not contained in Available Versions",
			data:   appendVersionInformation(nil, 1, 0x6b3343cf),
			sentBy: protocol.PerspectiveClient,
			errMsg: "version_information: Chosen Version v1 not contained in Available Versions [v2]",
		},
		{
			name:   "client's empty Available Versions",
			data:   appendVersionInformation(nil, 1),
			sentBy: protocol.PerspectiveClient,
			errMsg: "version_information: Chosen Version v1 not contained in Available Versions []",
		},
		{
			name:   "duplicate",
			data:   appendVersionInformation(appendVersionInformation(nil, 1, 1), 1, 1),
			sentBy: protocol.PerspectiveClient,
			errMsg: "received duplicate transport parameter 0x11",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := appendInitialSourceConnectionID(tc.data)
			if tc.sentBy == protocol.PerspectiveServer {
				data = quicvarint.Append(data, uint64(originalDestinationConnectionIDParameterID))
				data = quicvarint.Append(data, 0)
			}
			var p TransportParameters
			err := p.Unmarshal(data, tc.sentBy)
			require.Equal(t, &qerr.TransportError{
				ErrorCode:    qerr.TransportParameterError,
				ErrorMessage: tc.errMsg,
			}, err)
		})
	}
}

func TestVersionInformationNotSavedInSessionTicket(t *testing.T) {
	params := &TransportParameters{
		ActiveConnectionIDLimit: 2,
		MaxDatagramFrameSize:    protocol.InvalidByteCount,
		VersionInformation: &VersionInformation{
			ChosenVersion:     protocol.Version1,
			AvailableVersions: []protocol.Version{protocol.Version1},
		},
	}
	var tp TransportParameters
	require.NoError(t, tp.UnmarshalFromSessionTicket(params.MarshalForSessionTicket(nil)))
	require.Nil(t, tp.VersionInformation)

	// a session ticket containing the parameter is rejected
	b := quicvarint.Append(nil, transportParameterMarshalingVersion)
	b = quicvarint.Append(b, uint64(versionInformationParameterID))
	b = quicvarint.Append(b, 8)
	b = append(b, 0, 0, 0, 1, 0, 0, 0, 1)
	require.EqualError(t, tp.UnmarshalFromSessionTicket(b), "version_information in session ticket")
}

func TestInitialMaxPathIDTransportParameter(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		for _, pers := range []protocol.Perspective{protocol.PerspectiveClient, protocol.PerspectiveServer} {
			params := &TransportParameters{
				StatelessResetToken:     &protocol.StatelessResetToken{},
				ActiveConnectionIDLimit: 2,
				MaxDatagramFrameSize:    protocol.InvalidByteCount,
				// ignored, since HasInitialMaxPathID is not set
				InitialMaxPathID: 42,
			}
			if pers == protocol.PerspectiveClient {
				params.StatelessResetToken = nil
			}
			data := params.Marshal(pers)
			p := &TransportParameters{}
			require.NoError(t, p.Unmarshal(data, pers))
			require.False(t, p.HasInitialMaxPathID)
			require.Zero(t, p.InitialMaxPathID)
		}
	})

	for _, val := range []protocol.PathID{0, 1, protocol.MaxPathID, protocol.MaxPathID + 1, quicvarint.Max} {
		t.Run(fmt.Sprintf("value %d", val), func(t *testing.T) {
			for _, pers := range []protocol.Perspective{protocol.PerspectiveClient, protocol.PerspectiveServer} {
				params := &TransportParameters{
					StatelessResetToken:     &protocol.StatelessResetToken{},
					ActiveConnectionIDLimit: 2,
					MaxDatagramFrameSize:    protocol.InvalidByteCount,
					InitialMaxPathID:        val,
					HasInitialMaxPathID:     true,
				}
				if pers == protocol.PerspectiveClient {
					params.StatelessResetToken = nil
				}
				data := params.Marshal(pers)
				expected := quicvarint.Append(nil, 0x3e)
				expected = quicvarint.Append(expected, uint64(quicvarint.Len(uint64(val))))
				expected = quicvarint.Append(expected, uint64(val))
				require.True(t, bytes.Contains(data, expected))
				p := &TransportParameters{}
				require.NoError(t, p.Unmarshal(data, pers))
				require.True(t, p.HasInitialMaxPathID)
				require.Equal(t, val, p.InitialMaxPathID)
			}
		})
	}

	// The value is a varint. Like all other parameters, the length must match its encoding.
	t.Run("malformed", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			val  []byte
		}{
			{name: "empty", val: []byte{}},
			{name: "too long", val: []byte{0x1, 0x2}},
			{name: "too short", val: []byte{0x40}},
			{name: "non-minimal encoding with wrong length", val: append(quicvarint.AppendWithLen(nil, 1, 2), 0)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				b := quicvarint.Append(nil, 0x3e)
				b = quicvarint.Append(b, uint64(len(tc.val)))
				b = append(b, tc.val...)
				b = appendInitialSourceConnectionID(b)
				err := (&TransportParameters{}).Unmarshal(b, protocol.PerspectiveClient)
				var transportErr *qerr.TransportError
				require.ErrorAs(t, err, &transportErr)
				require.Equal(t, qerr.TransportParameterError, transportErr.ErrorCode)
			})
		}
	})

	t.Run("duplicate", func(t *testing.T) {
		b := quicvarint.Append(nil, 0x3e)
		b = quicvarint.Append(b, 1)
		b = quicvarint.Append(b, 2)
		b = quicvarint.Append(b, 0x3e)
		b = quicvarint.Append(b, 1)
		b = quicvarint.Append(b, 2)
		b = appendInitialSourceConnectionID(b)
		err := (&TransportParameters{}).Unmarshal(b, protocol.PerspectiveClient)
		var transportErr *qerr.TransportError
		require.ErrorAs(t, err, &transportErr)
		require.Equal(t, qerr.TransportParameterError, transportErr.ErrorCode)
		require.Equal(t, "received duplicate transport parameter 0x3e", transportErr.ErrorMessage)
	})
}

// Section 2.1 of draft-ietf-quic-multipath: initial_max_path_id must not be remembered.
func TestInitialMaxPathIDNotSavedInSessionTicket(t *testing.T) {
	params := &TransportParameters{
		InitialMaxStreamDataBidiLocal: 1,
		ActiveConnectionIDLimit:       2,
		MaxDatagramFrameSize:          protocol.InvalidByteCount,
		InitialMaxPathID:              3,
		HasInitialMaxPathID:           true,
	}
	b := params.MarshalForSessionTicket(nil)
	withoutPathID := *params
	withoutPathID.InitialMaxPathID = 0
	withoutPathID.HasInitialMaxPathID = false
	require.Equal(t, withoutPathID.MarshalForSessionTicket(nil), b)

	var tp TransportParameters
	require.NoError(t, tp.UnmarshalFromSessionTicket(b))
	require.False(t, tp.HasInitialMaxPathID)
	require.Zero(t, tp.InitialMaxPathID)

	// a session ticket containing the parameter is rejected
	b = quicvarint.Append(b, 0x3e)
	b = quicvarint.Append(b, 1)
	b = quicvarint.Append(b, 3)
	require.EqualError(t, tp.UnmarshalFromSessionTicket(b), "initial_max_path_id in session ticket")
}

// The add_address transport parameter of the address advertisement extension has an empty value.
func TestAddAddressTransportParameter(t *testing.T) {
	// the codepoint is not a reserved value (section 18.1 of RFC 9000)
	require.NotZero(t, (uint64(addAddressParameterID)-27)%31)

	for _, pers := range []protocol.Perspective{protocol.PerspectiveClient, protocol.PerspectiveServer} {
		t.Run(pers.String(), func(t *testing.T) {
			params := &TransportParameters{
				StatelessResetToken:     &protocol.StatelessResetToken{},
				ActiveConnectionIDLimit: 2,
				MaxDatagramFrameSize:    protocol.InvalidByteCount,
			}
			if pers == protocol.PerspectiveClient {
				params.StatelessResetToken = nil
			}
			expected := quicvarint.Append(nil, 0x1f0f9c0d40)
			expected = quicvarint.Append(expected, 0)

			data := params.Marshal(pers)
			require.False(t, bytes.Contains(data, expected))
			p := &TransportParameters{}
			require.NoError(t, p.Unmarshal(data, pers))
			require.False(t, p.EnableAddAddress)

			params.EnableAddAddress = true
			data = params.Marshal(pers)
			require.True(t, bytes.Contains(data, expected))
			p = &TransportParameters{}
			require.NoError(t, p.Unmarshal(data, pers))
			require.True(t, p.EnableAddAddress)
			require.Contains(t, p.String(), "EnableAddAddress: true")
		})
	}

	t.Run("non-empty value", func(t *testing.T) {
		b := quicvarint.Append(nil, 0x1f0f9c0d40)
		b = quicvarint.Append(b, 1)
		b = append(b, 1)
		b = appendInitialSourceConnectionID(b)
		err := (&TransportParameters{}).Unmarshal(b, protocol.PerspectiveClient)
		var transportErr *qerr.TransportError
		require.ErrorAs(t, err, &transportErr)
		require.Equal(t, qerr.TransportParameterError, transportErr.ErrorCode)
		require.Equal(t, "wrong length for add_address: 1 (expected empty)", transportErr.ErrorMessage)
	})

	t.Run("duplicate", func(t *testing.T) {
		b := quicvarint.Append(nil, 0x1f0f9c0d40)
		b = quicvarint.Append(b, 0)
		b = quicvarint.Append(b, 0x1f0f9c0d40)
		b = quicvarint.Append(b, 0)
		b = appendInitialSourceConnectionID(b)
		err := (&TransportParameters{}).Unmarshal(b, protocol.PerspectiveClient)
		var transportErr *qerr.TransportError
		require.ErrorAs(t, err, &transportErr)
		require.Equal(t, qerr.TransportParameterError, transportErr.ErrorCode)
		require.Equal(t, "received duplicate transport parameter 0x1f0f9c0d40", transportErr.ErrorMessage)
	})

	// The extension is only used together with IETF Multipath QUIC, whose transport parameter is not remembered
	// for 0-RTT either.
	t.Run("not saved in session ticket", func(t *testing.T) {
		params := &TransportParameters{
			ActiveConnectionIDLimit: 2,
			MaxDatagramFrameSize:    protocol.InvalidByteCount,
			EnableAddAddress:        true,
		}
		b := params.MarshalForSessionTicket(nil)
		var tp TransportParameters
		require.NoError(t, tp.UnmarshalFromSessionTicket(b))
		require.False(t, tp.EnableAddAddress)

		b = quicvarint.Append(b, 0x1f0f9c0d40)
		b = quicvarint.Append(b, 0)
		require.EqualError(t, tp.UnmarshalFromSessionTicket(b), "add_address in session ticket")
	})
}

// Versions of this module before IETF Multipath QUIC was implemented (v0.1.x and v0.2.0) negotiated their own
// multipath protocol, using a transport parameter from the private use range. Peers sending it are treated like
// peers that don't support multipath: the parameter is ignored, like any other unknown transport parameter
// (section 18.1 of RFC 9000). Session tickets that remembered it are not used for 0-RTT.
func TestAddressDiscoveryTransportParameter(t *testing.T) {
	for _, tc := range []struct {
		mode               AddressDiscoveryMode
		value              uint64
		provides, receives bool
	}{
		{mode: AddressDiscoveryProvide, value: 0, provides: true},
		{mode: AddressDiscoveryReceive, value: 1, receives: true},
		{mode: AddressDiscoveryProvideAndReceive, value: 2, provides: true, receives: true},
	} {
		t.Run(tc.mode.String(), func(t *testing.T) {
			require.Equal(t, tc.provides, tc.mode.Provides())
			require.Equal(t, tc.receives, tc.mode.Receives())
			for _, pers := range []protocol.Perspective{protocol.PerspectiveClient, protocol.PerspectiveServer} {
				params := &TransportParameters{
					ActiveConnectionIDLimit: 2,
					MaxDatagramFrameSize:    protocol.InvalidByteCount,
					AddressDiscovery:        tc.mode,
				}
				expected := quicvarint.Append(nil, 0x9f81a176)
				expected = quicvarint.Append(expected, uint64(quicvarint.Len(tc.value)))
				expected = quicvarint.Append(expected, tc.value)
				data := params.Marshal(pers)
				require.True(t, bytes.Contains(data, expected))
				p := &TransportParameters{}
				require.NoError(t, p.Unmarshal(data, pers))
				require.Equal(t, tc.mode, p.AddressDiscovery)
				require.Contains(t, p.String(), "AddressDiscovery: "+tc.mode.String())
			}
		})
	}

	t.Run("not sent", func(t *testing.T) {
		require.False(t, AddressDiscoveryUnsupported.Provides())
		require.False(t, AddressDiscoveryUnsupported.Receives())
		params := &TransportParameters{
			ActiveConnectionIDLimit: 2,
			MaxDatagramFrameSize:    protocol.InvalidByteCount,
		}
		data := params.Marshal(protocol.PerspectiveClient)
		require.False(t, bytes.Contains(data, quicvarint.Append(nil, 0x9f81a176)))
		p := &TransportParameters{}
		require.NoError(t, p.Unmarshal(data, protocol.PerspectiveClient))
		require.Equal(t, AddressDiscoveryUnsupported, p.AddressDiscovery)
		require.NotContains(t, p.String(), "AddressDiscovery")
	})

	// Section 3 of draft-ietf-quic-address-discovery-01:
	// Any other value is a TRANSPORT_PARAMETER_ERROR.
	t.Run("invalid value", func(t *testing.T) {
		for _, val := range []uint64{3, 4, 1 << 20, quicvarint.Max} {
			b := quicvarint.Append(nil, 0x9f81a176)
			b = quicvarint.Append(b, uint64(quicvarint.Len(val)))
			b = quicvarint.Append(b, val)
			b = appendInitialSourceConnectionID(b)
			err := (&TransportParameters{}).Unmarshal(b, protocol.PerspectiveClient)
			var transportErr *qerr.TransportError
			require.ErrorAs(t, err, &transportErr)
			require.Equal(t, qerr.TransportParameterError, transportErr.ErrorCode)
			require.Equal(t, fmt.Sprintf("invalid value for address_discovery: %d", val), transportErr.ErrorMessage)
		}
	})

	t.Run("inconsistent length", func(t *testing.T) {
		b := quicvarint.Append(nil, 0x9f81a176)
		b = quicvarint.Append(b, 2)
		b = append(b, 1, 0)
		b = appendInitialSourceConnectionID(b)
		err := (&TransportParameters{}).Unmarshal(b, protocol.PerspectiveClient)
		var transportErr *qerr.TransportError
		require.ErrorAs(t, err, &transportErr)
		require.Equal(t, qerr.TransportParameterError, transportErr.ErrorCode)
	})

	t.Run("duplicate", func(t *testing.T) {
		b := quicvarint.Append(nil, 0x9f81a176)
		b = quicvarint.Append(b, 1)
		b = quicvarint.Append(b, 0)
		b = quicvarint.Append(b, 0x9f81a176)
		b = quicvarint.Append(b, 1)
		b = quicvarint.Append(b, 2)
		b = appendInitialSourceConnectionID(b)
		err := (&TransportParameters{}).Unmarshal(b, protocol.PerspectiveClient)
		var transportErr *qerr.TransportError
		require.ErrorAs(t, err, &transportErr)
		require.Equal(t, qerr.TransportParameterError, transportErr.ErrorCode)
		require.Equal(t, "received duplicate transport parameter 0x9f81a176", transportErr.ErrorMessage)
	})

	// Section 3 of draft-ietf-quic-address-discovery-01:
	// When using 0-RTT, both endpoints remember the value of the transport parameter.
	t.Run("saved in session ticket", func(t *testing.T) {
		for _, mode := range []AddressDiscoveryMode{AddressDiscoveryUnsupported, AddressDiscoveryProvide, AddressDiscoveryReceive, AddressDiscoveryProvideAndReceive} {
			params := &TransportParameters{
				ActiveConnectionIDLimit: 2,
				MaxDatagramFrameSize:    protocol.InvalidByteCount,
				AddressDiscovery:        mode,
			}
			var tp TransportParameters
			require.NoError(t, tp.UnmarshalFromSessionTicket(params.MarshalForSessionTicket(nil)))
			require.Equal(t, mode, tp.AddressDiscovery)
		}
	})
}

// If 0-RTT is accepted, the server must not disable QUIC Address Discovery,
// or change the value of the address_discovery transport parameter
// (section 3 of draft-ietf-quic-address-discovery-01).
func TestAddressDiscoveryTransportParameterFor0RTT(t *testing.T) {
	modes := []AddressDiscoveryMode{AddressDiscoveryUnsupported, AddressDiscoveryProvide, AddressDiscoveryReceive, AddressDiscoveryProvideAndReceive}
	for _, saved := range modes {
		for _, current := range modes {
			savedParams := &TransportParameters{ActiveConnectionIDLimit: 2, MaxDatagramFrameSize: protocol.InvalidByteCount, AddressDiscovery: saved}
			params := &TransportParameters{ActiveConnectionIDLimit: 2, MaxDatagramFrameSize: protocol.InvalidByteCount, AddressDiscovery: current}
			require.Equal(t, saved == current, params.ValidFor0RTT(savedParams), "saved: %s, current: %s", saved, current)
			require.Equal(t, saved == current, params.ValidForUpdate(savedParams), "saved: %s, current: %s", saved, current)
		}
	}
}

func TestRemovedMultipathTransportParameter(t *testing.T) {
	// the transport parameter IDs used by v0.1.x and by v0.2.0
	for _, id := range []uint64{133405871402, 133405871403} {
		t.Run(fmt.Sprintf("%#x", id), func(t *testing.T) {
			b := quicvarint.Append(nil, id)
			b = quicvarint.Append(b, 0)
			b = appendInitialSourceConnectionID(b)
			p := &TransportParameters{}
			require.NoError(t, p.Unmarshal(b, protocol.PerspectiveClient))
			require.False(t, p.HasInitialMaxPathID)
			require.NotContains(t, string(p.Marshal(protocol.PerspectiveClient)), string(quicvarint.Append(nil, id)))

			ticket := (&TransportParameters{ActiveConnectionIDLimit: 2, MaxDatagramFrameSize: protocol.InvalidByteCount}).MarshalForSessionTicket(nil)
			ticket = quicvarint.Append(ticket, id)
			ticket = quicvarint.Append(ticket, 0)
			require.EqualError(t,
				(&TransportParameters{}).UnmarshalFromSessionTicket(ticket),
				fmt.Sprintf("unknown transport parameter %#x in session ticket", id),
			)
		})
	}
}

func TestResetStreamAtTransportParameterCodepoints(t *testing.T) {
	for _, tc := range []struct {
		name string
		ids  []transportParameterID
	}{
		{name: "current", ids: []transportParameterID{resetStreamAtParameterID}},
		{name: "legacy", ids: []transportParameterID{legacyResetStreamAtParameterID}},
		{name: "both", ids: []transportParameterID{resetStreamAtParameterID, legacyResetStreamAtParameterID}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var data []byte
			for _, id := range tc.ids {
				data = quicvarint.Append(data, uint64(id))
				data = quicvarint.Append(data, 0)
			}
			data = appendInitialSourceConnectionID(data)

			var p TransportParameters
			require.NoError(t, p.Unmarshal(data, protocol.PerspectiveClient))
			require.True(t, p.EnableResetStreamAt)
		})
	}
}

func TestMarshalAdditionalTransportParameters(t *testing.T) {
	origAdditionalTransportParametersClient := AdditionalTransportParametersClient
	t.Cleanup(func() {
		AdditionalTransportParametersClient = origAdditionalTransportParametersClient
	})
	AdditionalTransportParametersClient = map[uint64][]byte{1337: []byte("foobar")}

	result := quicvarint.Append([]byte{}, 1337)
	result = quicvarint.Append(result, 6)
	result = append(result, []byte("foobar")...)

	params := &TransportParameters{}
	require.True(t, bytes.Contains(params.Marshal(protocol.PerspectiveClient), result))
	require.False(t, bytes.Contains(params.Marshal(protocol.PerspectiveServer), result))
}

func TestMarshalRetrySourceConnectionID(t *testing.T) {
	// no retry source connection ID
	data := (&TransportParameters{
		StatelessResetToken:     &protocol.StatelessResetToken{},
		ActiveConnectionIDLimit: 2,
	}).Marshal(protocol.PerspectiveServer)
	var p TransportParameters
	require.NoError(t, p.Unmarshal(data, protocol.PerspectiveServer))
	require.Nil(t, p.RetrySourceConnectionID)

	// zero-length retry source connection ID
	rcid := protocol.ParseConnectionID([]byte{})
	data = (&TransportParameters{
		RetrySourceConnectionID: &rcid,
		StatelessResetToken:     &protocol.StatelessResetToken{},
		ActiveConnectionIDLimit: 2,
	}).Marshal(protocol.PerspectiveServer)
	p = TransportParameters{}
	require.NoError(t, p.Unmarshal(data, protocol.PerspectiveServer))
	require.NotNil(t, p.RetrySourceConnectionID)
	require.Zero(t, p.RetrySourceConnectionID.Len())
}

func TestTransportParameterNoMaxAckDelayIfDefault(t *testing.T) {
	const num = 1000
	var defaultLen, dataLen int
	maxAckDelay := protocol.DefaultMaxAckDelay + time.Millisecond
	for range num {
		dataDefault := (&TransportParameters{
			MaxAckDelay:         protocol.DefaultMaxAckDelay,
			StatelessResetToken: &protocol.StatelessResetToken{},
		}).Marshal(protocol.PerspectiveServer)
		defaultLen += len(dataDefault)
		data := (&TransportParameters{
			MaxAckDelay:         maxAckDelay,
			StatelessResetToken: &protocol.StatelessResetToken{},
		}).Marshal(protocol.PerspectiveServer)
		dataLen += len(data)
	}
	entryLen := quicvarint.Len(uint64(ackDelayExponentParameterID)) +
		quicvarint.Len(uint64(quicvarint.Len(uint64(maxAckDelay.Milliseconds())))) +
		quicvarint.Len(uint64(maxAckDelay.Milliseconds()))
	require.InDelta(t, float32(defaultLen)/num+float32(entryLen), float32(dataLen)/num, 1)
}

func TestTransportParameterNoAckDelayExponentIfDefault(t *testing.T) {
	const num = 1000
	var defaultLen, dataLen int
	for range num {
		dataDefault := (&TransportParameters{
			AckDelayExponent:    protocol.DefaultAckDelayExponent,
			StatelessResetToken: &protocol.StatelessResetToken{},
		}).Marshal(protocol.PerspectiveServer)
		defaultLen += len(dataDefault)
		data := (&TransportParameters{
			AckDelayExponent:    protocol.DefaultAckDelayExponent + 1,
			StatelessResetToken: &protocol.StatelessResetToken{},
		}).Marshal(protocol.PerspectiveServer)
		dataLen += len(data)
	}
	entryLen := quicvarint.Len(uint64(ackDelayExponentParameterID)) +
		quicvarint.Len(uint64(quicvarint.Len(protocol.DefaultAckDelayExponent+1))) +
		quicvarint.Len(protocol.DefaultAckDelayExponent+1)
	require.InDelta(t, float32(defaultLen)/num+float32(entryLen), float32(dataLen)/num, 1)
}

func TestTransportParameterSetsDefaultValuesWhenNotSent(t *testing.T) {
	data := (&TransportParameters{
		AckDelayExponent:        protocol.DefaultAckDelayExponent,
		StatelessResetToken:     &protocol.StatelessResetToken{},
		ActiveConnectionIDLimit: protocol.DefaultActiveConnectionIDLimit,
	}).Marshal(protocol.PerspectiveServer)
	p := &TransportParameters{}
	require.NoError(t, p.Unmarshal(data, protocol.PerspectiveServer))
	require.EqualValues(t, protocol.DefaultAckDelayExponent, p.AckDelayExponent)
	require.EqualValues(t, protocol.DefaultActiveConnectionIDLimit, p.ActiveConnectionIDLimit)
}

func TestTransportParameterErrors(t *testing.T) {
	tests := []struct {
		name           string
		params         *TransportParameters
		perspective    protocol.Perspective
		data           []byte
		expectedErrMsg string
	}{
		{
			name: "invalid stateless reset token length",
			data: func() []byte {
				b := quicvarint.Append(nil, uint64(statelessResetTokenParameterID))
				b = quicvarint.Append(b, 15)
				return append(b, make([]byte, 15)...)
			}(),
			perspective:    protocol.PerspectiveServer,
			expectedErrMsg: "wrong length for stateless_reset_token: 15 (expected 16)",
		},
		{
			name: "small max UDP payload size",
			data: func() []byte {
				b := quicvarint.Append(nil, uint64(maxUDPPayloadSizeParameterID))
				b = quicvarint.Append(b, uint64(quicvarint.Len(1199)))
				return quicvarint.Append(b, 1199)
			}(),
			perspective:    protocol.PerspectiveServer,
			expectedErrMsg: "invalid value for max_udp_payload_size: 1199 (minimum 1200)",
		},
		{
			name: "active connection ID limit too small",
			params: &TransportParameters{
				ActiveConnectionIDLimit: 1,
				StatelessResetToken:     &protocol.StatelessResetToken{},
			},
			perspective:    protocol.PerspectiveServer,
			expectedErrMsg: "invalid value for active_connection_id_limit: 1 (minimum 2)",
		},
		{
			name: "ack delay exponent too large",
			params: &TransportParameters{
				AckDelayExponent:    21,
				StatelessResetToken: &protocol.StatelessResetToken{},
			},
			perspective:    protocol.PerspectiveServer,
			expectedErrMsg: "invalid value for ack_delay_exponent: 21 (maximum 20)",
		},
		{
			name: "disable active migration has content",
			data: func() []byte {
				b := quicvarint.Append(nil, uint64(disableActiveMigrationParameterID))
				b = quicvarint.Append(b, 6)
				return append(b, []byte("foobar")...)
			}(),
			perspective:    protocol.PerspectiveServer,
			expectedErrMsg: "wrong length for disable_active_migration: 6 (expected empty)",
		},
		{
			name: "server doesn't set original destination connection ID",
			data: func() []byte {
				b := quicvarint.Append(nil, uint64(statelessResetTokenParameterID))
				b = quicvarint.Append(b, 16)
				b = append(b, make([]byte, 16)...)
				return appendInitialSourceConnectionID(b)
			}(),
			perspective:    protocol.PerspectiveServer,
			expectedErrMsg: "missing original_destination_connection_id",
		},
		{
			name:           "initial source connection ID is missing",
			data:           []byte{},
			perspective:    protocol.PerspectiveClient,
			expectedErrMsg: "missing initial_source_connection_id",
		},
		{
			name: "max ack delay is too large",
			params: &TransportParameters{
				MaxAckDelay:         1 << 14 * time.Millisecond,
				StatelessResetToken: &protocol.StatelessResetToken{},
			},
			perspective:    protocol.PerspectiveServer,
			expectedErrMsg: "invalid value for max_ack_delay: 16384ms (maximum 16383ms)",
		},
		{
			name: "varint value has wrong length",
			data: func() []byte {
				b := quicvarint.Append(nil, uint64(initialMaxStreamDataBidiLocalParameterID))
				b = quicvarint.Append(b, 2)
				val := uint64(0xdeadbeef)
				b = quicvarint.Append(b, val)
				return appendInitialSourceConnectionID(b)
			}(),
			perspective:    protocol.PerspectiveServer,
			expectedErrMsg: fmt.Sprintf("inconsistent transport parameter length for transport parameter %#x", initialMaxStreamDataBidiLocalParameterID),
		},
		{
			name: "initial max streams bidi is too large",
			data: func() []byte {
				b := quicvarint.Append(nil, uint64(initialMaxStreamsBidiParameterID))
				b = quicvarint.Append(b, uint64(quicvarint.Len(uint64(protocol.MaxStreamCount+1))))
				b = quicvarint.Append(b, uint64(protocol.MaxStreamCount+1))
				return appendInitialSourceConnectionID(b)
			}(),
			perspective:    protocol.PerspectiveServer,
			expectedErrMsg: "initial_max_streams_bidi too large: 1152921504606846977 (maximum 1152921504606846976)",
		},
		{
			name: "initial max streams uni is too large",
			data: func() []byte {
				b := quicvarint.Append(nil, uint64(initialMaxStreamsUniParameterID))
				b = quicvarint.Append(b, uint64(quicvarint.Len(uint64(protocol.MaxStreamCount+1))))
				b = quicvarint.Append(b, uint64(protocol.MaxStreamCount+1))
				return appendInitialSourceConnectionID(b)
			}(),
			perspective:    protocol.PerspectiveServer,
			expectedErrMsg: "initial_max_streams_uni too large: 1152921504606846977 (maximum 1152921504606846976)",
		},
		{
			name: "not enough data to read",
			data: func() []byte {
				b := quicvarint.Append(nil, 0x42)
				b = quicvarint.Append(b, 7)
				return append(b, []byte("foobar")...)
			}(),
			perspective:    protocol.PerspectiveServer,
			expectedErrMsg: "remaining length (6) smaller than parameter length (7)",
		},
		{
			name: "client sent stateless reset token",
			data: func() []byte {
				b := quicvarint.Append(nil, uint64(statelessResetTokenParameterID))
				b = quicvarint.Append(b, uint64(quicvarint.Len(16)))
				return append(b, make([]byte, 16)...)
			}(),
			perspective:    protocol.PerspectiveClient,
			expectedErrMsg: "client sent a stateless_reset_token",
		},
		{
			name: "client sent original destination connection ID",
			data: func() []byte {
				b := quicvarint.Append(nil, uint64(originalDestinationConnectionIDParameterID))
				b = quicvarint.Append(b, 6)
				return append(b, []byte("foobar")...)
			}(),
			perspective:    protocol.PerspectiveClient,
			expectedErrMsg: "client sent an original_destination_connection_id",
		},
		{
			name: "huge max ack delay value",
			data: func() []byte {
				val := uint64(math.MaxUint64) / 5
				b := quicvarint.Append(nil, uint64(maxAckDelayParameterID))
				b = quicvarint.Append(b, uint64(quicvarint.Len(val)))
				b = quicvarint.Append(b, val)
				return appendInitialSourceConnectionID(b)
			}(),
			perspective:    protocol.PerspectiveClient,
			expectedErrMsg: "invalid value for max_ack_delay: 3689348814741910323ms (maximum 16383ms)",
		},
		{
			name: "invalid value for reset_stream_at",
			data: func() []byte {
				b := quicvarint.Append(nil, uint64(resetStreamAtParameterID))
				b = quicvarint.Append(b, 1)
				b = quicvarint.Append(b, 1)
				return appendInitialSourceConnectionID(b)
			}(),
			perspective:    protocol.PerspectiveClient,
			expectedErrMsg: "wrong length for reset_stream_at: 1 (expected empty)",
		},
		{
			name: "invalid value for legacy reset_stream_at",
			data: func() []byte {
				b := quicvarint.Append(nil, uint64(legacyResetStreamAtParameterID))
				b = quicvarint.Append(b, 1)
				b = quicvarint.Append(b, 1)
				return appendInitialSourceConnectionID(b)
			}(),
			perspective:    protocol.PerspectiveClient,
			expectedErrMsg: "wrong length for reset_stream_at: 1 (expected empty)",
		},
		{
			name: "min ack delay is greater than max ack delay",
			data: func() []byte {
				b := quicvarint.Append(nil, uint64(minAckDelayParameterID))
				b = quicvarint.Append(b, uint64(quicvarint.Len(42001)))
				b = quicvarint.Append(b, 42001) // 42001 microseconds
				b = quicvarint.Append(b, uint64(maxAckDelayParameterID))
				b = quicvarint.Append(b, uint64(quicvarint.Len(42)))
				b = quicvarint.Append(b, 42) // 42 microseconds
				return appendInitialSourceConnectionID(b)
			}(),
			perspective:    protocol.PerspectiveClient,
			expectedErrMsg: "min_ack_delay (42.001ms) is greater than max_ack_delay (42ms)",
		},
		{
			name: "huge min ack delay value",
			data: func() []byte {
				b := quicvarint.Append(nil, uint64(minAckDelayParameterID))
				b = quicvarint.Append(b, uint64(quicvarint.Len(quicvarint.Max)))
				b = quicvarint.Append(b, quicvarint.Max)
				b = quicvarint.Append(b, uint64(maxAckDelayParameterID))
				b = quicvarint.Append(b, uint64(quicvarint.Len(42)))
				b = quicvarint.Append(b, 42) // 42 microseconds
				return appendInitialSourceConnectionID(b)
			}(),
			perspective:    protocol.PerspectiveClient,
			expectedErrMsg: "min_ack_delay (2562047h47m16.854775807s) is greater than max_ack_delay (42ms)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.params != nil {
				data := tt.params.Marshal(tt.perspective)
				err = (&TransportParameters{}).Unmarshal(data, tt.perspective)
			} else {
				err = (&TransportParameters{}).Unmarshal(tt.data, tt.perspective)
			}
			require.Error(t, err)
			transportErr, ok := err.(*qerr.TransportError)
			require.True(t, ok)
			require.Equal(t, qerr.TransportParameterError, transportErr.ErrorCode)
			require.Equal(t, tt.expectedErrMsg, transportErr.ErrorMessage)
		})
	}
}

func TestTransportParameterUnknownParameters(t *testing.T) {
	// write a known parameter
	b := quicvarint.Append(nil, uint64(initialMaxStreamDataBidiLocalParameterID))
	b = quicvarint.Append(b, uint64(quicvarint.Len(0x1337)))
	b = quicvarint.Append(b, 0x1337)
	// write an unknown parameter
	b = quicvarint.Append(b, 0x42)
	b = quicvarint.Append(b, 6)
	b = append(b, []byte("foobar")...)
	// write a known parameter
	b = quicvarint.Append(b, uint64(initialMaxStreamDataBidiRemoteParameterID))
	b = quicvarint.Append(b, uint64(quicvarint.Len(0x42)))
	b = quicvarint.Append(b, 0x42)
	b = appendInitialSourceConnectionID(b)
	p := &TransportParameters{}
	err := p.Unmarshal(b, protocol.PerspectiveClient)
	require.NoError(t, err)
	require.Equal(t, protocol.ByteCount(0x1337), p.InitialMaxStreamDataBidiLocal)
	require.Equal(t, protocol.ByteCount(0x42), p.InitialMaxStreamDataBidiRemote)
}

func TestSessionTicketTransportParameterRejectsUnknownParameter(t *testing.T) {
	b := (&TransportParameters{
		ActiveConnectionIDLimit: 2,
		MaxDatagramFrameSize:    protocol.InvalidByteCount,
	}).MarshalForSessionTicket(nil)
	b = quicvarint.Append(b, 0x42)
	b = quicvarint.Append(b, 6)
	b = append(b, []byte("foobar")...)

	var p TransportParameters
	err := p.UnmarshalFromSessionTicket(b)
	require.EqualError(t, err, "unknown transport parameter 0x42 in session ticket")
}

func TestTransportParameterRejectsDuplicateParameters(t *testing.T) {
	// write first parameter
	b := quicvarint.Append(nil, uint64(initialMaxStreamDataBidiLocalParameterID))
	b = quicvarint.Append(b, uint64(quicvarint.Len(0x1337)))
	b = quicvarint.Append(b, 0x1337)
	// write a second parameter
	b = quicvarint.Append(b, uint64(initialMaxStreamDataBidiRemoteParameterID))
	b = quicvarint.Append(b, uint64(quicvarint.Len(0x42)))
	b = quicvarint.Append(b, 0x42)
	// write first parameter again
	b = quicvarint.Append(b, uint64(initialMaxStreamDataBidiLocalParameterID))
	b = quicvarint.Append(b, uint64(quicvarint.Len(0x1337)))
	b = quicvarint.Append(b, 0x1337)
	b = appendInitialSourceConnectionID(b)
	err := (&TransportParameters{}).Unmarshal(b, protocol.PerspectiveClient)
	require.Error(t, err)
	transportErr, ok := err.(*qerr.TransportError)
	require.True(t, ok)
	require.Equal(t, qerr.TransportParameterError, transportErr.ErrorCode)
	require.Equal(t, fmt.Sprintf("received duplicate transport parameter %#x", initialMaxStreamDataBidiLocalParameterID), transportErr.ErrorMessage)
}

func TestTransportParameterPreferredAddress(t *testing.T) {
	testCases := []struct {
		name    string
		hasIPv4 bool
		hasIPv6 bool
	}{
		{"IPv4 and IPv6", true, true},
		{"IPv4 only", true, false},
		{"IPv6 only", false, true},
		{"neither IPv4 nor IPv6", false, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testTransportParameterPreferredAddress(t, tc.hasIPv4, tc.hasIPv6)
		})
	}
}

func testTransportParameterPreferredAddress(t *testing.T, hasIPv4, hasIPv6 bool) {
	addr4 := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 42)
	addr6 := netip.AddrPortFrom(netip.AddrFrom16([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}), 13)
	pa := &PreferredAddress{
		ConnectionID:        protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
		StatelessResetToken: protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
	}
	if hasIPv4 {
		pa.IPv4 = addr4
	}
	if hasIPv6 {
		pa.IPv6 = addr6
	}

	data := (&TransportParameters{
		PreferredAddress:        pa,
		StatelessResetToken:     &protocol.StatelessResetToken{},
		ActiveConnectionIDLimit: 2,
	}).Marshal(protocol.PerspectiveServer)
	p := &TransportParameters{}
	require.NoError(t, p.Unmarshal(data, protocol.PerspectiveServer))
	if hasIPv4 {
		require.True(t, p.PreferredAddress.IPv4.IsValid())
		require.Equal(t, addr4, p.PreferredAddress.IPv4)
	} else {
		require.False(t, p.PreferredAddress.IPv4.IsValid())
	}
	if hasIPv6 {
		require.True(t, p.PreferredAddress.IPv6.IsValid())
		require.Equal(t, addr6, p.PreferredAddress.IPv6)
	} else {
		require.False(t, p.PreferredAddress.IPv6.IsValid())
	}
	require.Equal(t, pa.ConnectionID, p.PreferredAddress.ConnectionID)
	require.Equal(t, pa.StatelessResetToken, p.PreferredAddress.StatelessResetToken)
}

func TestTransportParameterPreferredAddressFromClient(t *testing.T) {
	b := quicvarint.Append(nil, uint64(preferredAddressParameterID))
	b = quicvarint.Append(b, 6)
	b = append(b, []byte("foobar")...)
	p := &TransportParameters{}
	err := p.Unmarshal(b, protocol.PerspectiveClient)
	require.Error(t, err)
	require.IsType(t, &qerr.TransportError{}, err)
	transportErr := err.(*qerr.TransportError)
	require.Equal(t, qerr.TransportParameterError, transportErr.ErrorCode)
	require.Equal(t, "client sent a preferred_address", transportErr.ErrorMessage)
}

func TestTransportParameterPreferredAddressZeroLengthConnectionID(t *testing.T) {
	pa := &PreferredAddress{
		IPv4:                netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 42),
		IPv6:                netip.AddrPortFrom(netip.AddrFrom16([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}), 13),
		ConnectionID:        protocol.ParseConnectionID([]byte{}),
		StatelessResetToken: protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
	}
	data := (&TransportParameters{
		PreferredAddress:    pa,
		StatelessResetToken: &protocol.StatelessResetToken{},
	}).Marshal(protocol.PerspectiveServer)
	p := &TransportParameters{}
	err := p.Unmarshal(data, protocol.PerspectiveServer)
	require.Error(t, err)
	require.IsType(t, &qerr.TransportError{}, err)
	transportErr := err.(*qerr.TransportError)
	require.Equal(t, qerr.TransportParameterError, transportErr.ErrorCode)
	require.Equal(t, "invalid connection ID length: 0", transportErr.ErrorMessage)
}

func TestPreferredAddressErrorOnEOF(t *testing.T) {
	raw := []byte{
		127, 0, 0, 1, // IPv4
		0, 42, // IPv4 Port
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, // IPv6
		13, 37, // IPv6 Port,
		4, // conn ID len
		0xde, 0xad, 0xbe, 0xef,
		16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, // stateless reset token
	}
	for i := 1; i < len(raw); i++ {
		b := quicvarint.Append(nil, uint64(preferredAddressParameterID))
		b = append(b, raw[:i]...)
		p := &TransportParameters{}
		err := p.Unmarshal(b, protocol.PerspectiveServer)
		require.Error(t, err)
	}
}

func TestTransportParametersFromSessionTicket(t *testing.T) {
	params := &TransportParameters{
		InitialMaxStreamDataBidiLocal:  protocol.ByteCount(getRandomValue()),
		InitialMaxStreamDataBidiRemote: protocol.ByteCount(getRandomValue()),
		InitialMaxStreamDataUni:        protocol.ByteCount(getRandomValue()),
		InitialMaxData:                 protocol.ByteCount(getRandomValue()),
		MaxBidiStreamNum:               protocol.StreamNum(getRandomValueUpTo(uint64(protocol.MaxStreamCount))),
		MaxUniStreamNum:                protocol.StreamNum(getRandomValueUpTo(uint64(protocol.MaxStreamCount))),
		ActiveConnectionIDLimit:        2 + getRandomValueUpTo(quicvarint.Max-2),
		MaxDatagramFrameSize:           protocol.ByteCount(getRandomValueUpTo(uint64(MaxDatagramSize))),
		EnableResetStreamAt:            getRandomValue()%2 == 0,
		AddressDiscovery:               AddressDiscoveryMode(getRandomValueUpTo(4)),
	}
	require.True(t, params.ValidFor0RTT(params))
	b := params.MarshalForSessionTicket(nil)
	var tp TransportParameters
	require.NoError(t, tp.UnmarshalFromSessionTicket(b))
	require.Equal(t, params.InitialMaxStreamDataBidiLocal, tp.InitialMaxStreamDataBidiLocal)
	require.Equal(t, params.InitialMaxStreamDataBidiRemote, tp.InitialMaxStreamDataBidiRemote)
	require.Equal(t, params.InitialMaxStreamDataUni, tp.InitialMaxStreamDataUni)
	require.Equal(t, params.InitialMaxData, tp.InitialMaxData)
	require.Equal(t, params.MaxBidiStreamNum, tp.MaxBidiStreamNum)
	require.Equal(t, params.MaxUniStreamNum, tp.MaxUniStreamNum)
	require.Equal(t, params.ActiveConnectionIDLimit, tp.ActiveConnectionIDLimit)
	require.Equal(t, params.MaxDatagramFrameSize, tp.MaxDatagramFrameSize)
	require.Equal(t, params.EnableResetStreamAt, tp.EnableResetStreamAt)
	require.Equal(t, params.AddressDiscovery, tp.AddressDiscovery)
}

func TestSessionTicketInvalidTransportParameters(t *testing.T) {
	var p TransportParameters
	require.Error(t, p.UnmarshalFromSessionTicket([]byte("foobar")))
}

func TestSessionTicketLegacyResetStreamAtTransportParameter(t *testing.T) {
	b := quicvarint.Append(nil, transportParameterMarshalingVersion)
	b = quicvarint.Append(b, uint64(legacyResetStreamAtParameterID))
	b = quicvarint.Append(b, 0)

	var p TransportParameters
	require.NoError(t, p.UnmarshalFromSessionTicket(b))
	require.True(t, p.EnableResetStreamAt)
}

func TestSessionTicketTransportParameterVersionMismatch(t *testing.T) {
	var p TransportParameters
	data := p.MarshalForSessionTicket(nil)
	b := quicvarint.Append(nil, transportParameterMarshalingVersion+1)
	b = append(b, data[quicvarint.Len(transportParameterMarshalingVersion):]...)
	err := p.UnmarshalFromSessionTicket(b)
	require.EqualError(t, err, fmt.Sprintf("unknown transport parameter marshaling version: %d", transportParameterMarshalingVersion+1))
}

func TestTransportParametersValidFor0RTT(t *testing.T) {
	saved := &TransportParameters{
		InitialMaxStreamDataBidiLocal:  1,
		InitialMaxStreamDataBidiRemote: 2,
		InitialMaxStreamDataUni:        3,
		InitialMaxData:                 4,
		MaxBidiStreamNum:               5,
		MaxUniStreamNum:                6,
		ActiveConnectionIDLimit:        7,
		MaxDatagramFrameSize:           1000,
		EnableResetStreamAt:            true,
	}

	tests := []struct {
		name   string
		modify func(*TransportParameters)
		valid  bool
	}{
		{
			name:   "No Changes",
			modify: func(p *TransportParameters) {},
			valid:  true,
		},
		{
			name:   "ResetStreamAt disabled",
			modify: func(p *TransportParameters) { p.EnableResetStreamAt = false },
			valid:  false,
		},
		{
			name: "InitialMaxStreamDataBidiLocal reduced",
			modify: func(p *TransportParameters) {
				p.InitialMaxStreamDataBidiLocal = saved.InitialMaxStreamDataBidiLocal - 1
			},
			valid: false,
		},
		{
			name: "InitialMaxStreamDataBidiLocal increased",
			modify: func(p *TransportParameters) {
				p.InitialMaxStreamDataBidiLocal = saved.InitialMaxStreamDataBidiLocal + 1
			},
			valid: true,
		},
		{
			name: "InitialMaxStreamDataBidiRemote reduced",
			modify: func(p *TransportParameters) {
				p.InitialMaxStreamDataBidiRemote = saved.InitialMaxStreamDataBidiRemote - 1
			},
			valid: false,
		},
		{
			name: "InitialMaxStreamDataBidiRemote increased",
			modify: func(p *TransportParameters) {
				p.InitialMaxStreamDataBidiRemote = saved.InitialMaxStreamDataBidiRemote + 1
			},
			valid: true,
		},
		{
			name:   "InitialMaxStreamDataUni reduced",
			modify: func(p *TransportParameters) { p.InitialMaxStreamDataUni = saved.InitialMaxStreamDataUni - 1 },
			valid:  false,
		},
		{
			name:   "InitialMaxStreamDataUni increased",
			modify: func(p *TransportParameters) { p.InitialMaxStreamDataUni = saved.InitialMaxStreamDataUni + 1 },
			valid:  true,
		},
		{
			name:   "InitialMaxData reduced",
			modify: func(p *TransportParameters) { p.InitialMaxData = saved.InitialMaxData - 1 },
			valid:  false,
		},
		{
			name:   "InitialMaxData increased",
			modify: func(p *TransportParameters) { p.InitialMaxData = saved.InitialMaxData + 1 },
			valid:  true,
		},
		{
			name:   "MaxBidiStreamNum reduced",
			modify: func(p *TransportParameters) { p.MaxBidiStreamNum = saved.MaxBidiStreamNum - 1 },
			valid:  false,
		},
		{
			name:   "MaxBidiStreamNum increased",
			modify: func(p *TransportParameters) { p.MaxBidiStreamNum = saved.MaxBidiStreamNum + 1 },
			valid:  true,
		},
		{
			name:   "MaxUniStreamNum reduced",
			modify: func(p *TransportParameters) { p.MaxUniStreamNum = saved.MaxUniStreamNum - 1 },
			valid:  false,
		},
		{
			name:   "MaxUniStreamNum increased",
			modify: func(p *TransportParameters) { p.MaxUniStreamNum = saved.MaxUniStreamNum + 1 },
			valid:  true,
		},
		{
			name:   "ActiveConnectionIDLimit changed",
			modify: func(p *TransportParameters) { p.ActiveConnectionIDLimit = 0 },
			valid:  false,
		},
		{
			name:   "MaxDatagramFrameSize increased",
			modify: func(p *TransportParameters) { p.MaxDatagramFrameSize = saved.MaxDatagramFrameSize + 1 },
			valid:  true,
		},
		{
			name:   "MaxDatagramFrameSize reduced",
			modify: func(p *TransportParameters) { p.MaxDatagramFrameSize = saved.MaxDatagramFrameSize - 1 },
			valid:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := *saved
			tt.modify(&p)
			require.Equal(t, tt.valid, p.ValidFor0RTT(saved))
		})
	}
	// initial_max_path_id is not remembered, and has no influence on 0-RTT
	t.Run("InitialMaxPathID", func(t *testing.T) {
		for _, savedHas := range []bool{false, true} {
			for _, has := range []bool{false, true} {
				s := *saved
				s.HasInitialMaxPathID = savedHas
				s.InitialMaxPathID = 5
				p := *saved
				p.HasInitialMaxPathID = has
				p.InitialMaxPathID = 1
				require.True(t, p.ValidFor0RTT(&s))
			}
		}
	})
	t.Run("ResetStreamAt enabled", func(t *testing.T) {
		p := *saved
		withoutResetStreamAt := *saved
		withoutResetStreamAt.EnableResetStreamAt = false
		require.True(t, p.ValidFor0RTT(&withoutResetStreamAt))
	})
}

func TestTransportParametersValidAfter0RTT(t *testing.T) {
	saved := &TransportParameters{
		InitialMaxStreamDataBidiLocal:  1,
		InitialMaxStreamDataBidiRemote: 2,
		InitialMaxStreamDataUni:        3,
		InitialMaxData:                 4,
		MaxBidiStreamNum:               5,
		MaxUniStreamNum:                6,
		ActiveConnectionIDLimit:        7,
		MaxDatagramFrameSize:           1000,
		EnableResetStreamAt:            true,
	}

	tests := []struct {
		name   string
		modify func(*TransportParameters)
		reject bool
	}{
		{
			name:   "no changes",
			modify: func(p *TransportParameters) {},
			reject: false,
		},
		{
			name:   "ResetStreamAt disabled",
			modify: func(p *TransportParameters) { p.EnableResetStreamAt = false },
			reject: true,
		},
		{
			name: "InitialMaxStreamDataBidiLocal reduced",
			modify: func(p *TransportParameters) {
				p.InitialMaxStreamDataBidiLocal = saved.InitialMaxStreamDataBidiLocal - 1
			},
			reject: true,
		},
		{
			name: "InitialMaxStreamDataBidiLocal increased",
			modify: func(p *TransportParameters) {
				p.InitialMaxStreamDataBidiLocal = saved.InitialMaxStreamDataBidiLocal + 1
			},
			reject: false,
		},
		{
			name: "InitialMaxStreamDataBidiRemote reduced",
			modify: func(p *TransportParameters) {
				p.InitialMaxStreamDataBidiRemote = saved.InitialMaxStreamDataBidiRemote - 1
			},
			reject: true,
		},
		{
			name: "InitialMaxStreamDataBidiRemote increased",
			modify: func(p *TransportParameters) {
				p.InitialMaxStreamDataBidiRemote = saved.InitialMaxStreamDataBidiRemote + 1
			},
			reject: false,
		},
		{
			name:   "InitialMaxStreamDataUni reduced",
			modify: func(p *TransportParameters) { p.InitialMaxStreamDataUni = saved.InitialMaxStreamDataUni - 1 },
			reject: true,
		},
		{
			name:   "InitialMaxStreamDataUni increased",
			modify: func(p *TransportParameters) { p.InitialMaxStreamDataUni = saved.InitialMaxStreamDataUni + 1 },
			reject: false,
		},
		{
			name:   "InitialMaxData reduced",
			modify: func(p *TransportParameters) { p.InitialMaxData = saved.InitialMaxData - 1 },
			reject: true,
		},
		{
			name:   "InitialMaxData increased",
			modify: func(p *TransportParameters) { p.InitialMaxData = saved.InitialMaxData + 1 },
			reject: false,
		},
		{
			name:   "MaxBidiStreamNum reduced",
			modify: func(p *TransportParameters) { p.MaxBidiStreamNum = saved.MaxBidiStreamNum - 1 },
			reject: true,
		},
		{
			name:   "MaxBidiStreamNum increased",
			modify: func(p *TransportParameters) { p.MaxBidiStreamNum = saved.MaxBidiStreamNum + 1 },
			reject: false,
		},
		{
			name:   "MaxUniStreamNum reduced",
			modify: func(p *TransportParameters) { p.MaxUniStreamNum = saved.MaxUniStreamNum - 1 },
			reject: true,
		},
		{
			name:   "MaxUniStreamNum increased",
			modify: func(p *TransportParameters) { p.MaxUniStreamNum = saved.MaxUniStreamNum + 1 },
			reject: false,
		},
		{
			name:   "ActiveConnectionIDLimit reduced",
			modify: func(p *TransportParameters) { p.ActiveConnectionIDLimit = saved.ActiveConnectionIDLimit - 1 },
			reject: true,
		},
		{
			name:   "ActiveConnectionIDLimit increased",
			modify: func(p *TransportParameters) { p.ActiveConnectionIDLimit = saved.ActiveConnectionIDLimit + 1 },
			reject: false,
		},
		{
			name:   "MaxDatagramFrameSize reduced",
			modify: func(p *TransportParameters) { p.MaxDatagramFrameSize = saved.MaxDatagramFrameSize - 1 },
			reject: true,
		},
		{
			name:   "MaxDatagramFrameSize increased",
			modify: func(p *TransportParameters) { p.MaxDatagramFrameSize = saved.MaxDatagramFrameSize + 1 },
			reject: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := *saved
			tt.modify(&p)
			if tt.reject {
				require.False(t, p.ValidForUpdate(saved))
			} else {
				require.True(t, p.ValidForUpdate(saved))
			}
		})
	}
	// initial_max_path_id is not remembered, and has no influence on 0-RTT
	t.Run("InitialMaxPathID", func(t *testing.T) {
		for _, savedHas := range []bool{false, true} {
			for _, has := range []bool{false, true} {
				s := *saved
				s.HasInitialMaxPathID = savedHas
				s.InitialMaxPathID = 5
				p := *saved
				p.HasInitialMaxPathID = has
				p.InitialMaxPathID = 1
				require.True(t, p.ValidForUpdate(&s))
			}
		}
	})
	t.Run("ResetStreamAt enabled", func(t *testing.T) {
		p := *saved
		withoutResetStreamAt := *saved
		withoutResetStreamAt.EnableResetStreamAt = false
		require.True(t, p.ValidForUpdate(&withoutResetStreamAt))
	})
}

func BenchmarkTransportParameters(b *testing.B) {
	b.Run("without preferred address", func(b *testing.B) { benchmarkTransportParameters(b, false) })
	b.Run("with preferred address", func(b *testing.B) { benchmarkTransportParameters(b, true) })
}

func benchmarkTransportParameters(b *testing.B, withPreferredAddress bool) {
	b.ReportAllocs()

	var token protocol.StatelessResetToken
	rand.Read(token[:])
	rcid := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xc0, 0xde})
	params := &TransportParameters{
		InitialMaxStreamDataBidiLocal:   protocol.ByteCount(getRandomValue()),
		InitialMaxStreamDataBidiRemote:  protocol.ByteCount(getRandomValue()),
		InitialMaxStreamDataUni:         protocol.ByteCount(getRandomValue()),
		InitialMaxData:                  protocol.ByteCount(getRandomValue()),
		MaxIdleTimeout:                  0xcafe * time.Second,
		MaxBidiStreamNum:                protocol.StreamNum(getRandomValueUpTo(uint64(protocol.MaxStreamCount))),
		MaxUniStreamNum:                 protocol.StreamNum(getRandomValueUpTo(uint64(protocol.MaxStreamCount))),
		DisableActiveMigration:          true,
		StatelessResetToken:             &token,
		OriginalDestinationConnectionID: protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
		InitialSourceConnectionID:       protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad}),
		RetrySourceConnectionID:         &rcid,
		AckDelayExponent:                13,
		MaxAckDelay:                     42 * time.Millisecond,
		ActiveConnectionIDLimit:         2 + getRandomValueUpTo(quicvarint.Max-2),
		MaxDatagramFrameSize:            protocol.ByteCount(getRandomValue()),
	}
	var token2 protocol.StatelessResetToken
	rand.Read(token2[:])
	if withPreferredAddress {
		var ip4 [4]byte
		var ip6 [16]byte
		rand.Read(ip4[:])
		rand.Read(ip6[:])
		params.PreferredAddress = &PreferredAddress{
			IPv4:                netip.AddrPortFrom(netip.AddrFrom4(ip4), 1234),
			IPv6:                netip.AddrPortFrom(netip.AddrFrom16(ip6), 4321),
			ConnectionID:        protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
			StatelessResetToken: token2,
		}
	}
	data := params.Marshal(protocol.PerspectiveServer)

	var p TransportParameters
	for b.Loop() {
		if err := p.Unmarshal(data, protocol.PerspectiveServer); err != nil {
			b.Fatal(err)
		}
		// check a few fields
		if p.DisableActiveMigration != params.DisableActiveMigration ||
			p.InitialMaxStreamDataBidiLocal != params.InitialMaxStreamDataBidiLocal ||
			*p.StatelessResetToken != *params.StatelessResetToken ||
			p.AckDelayExponent != params.AckDelayExponent {
			b.Fatalf("params mismatch: %v vs %v", p, params)
		}
		if withPreferredAddress && *p.PreferredAddress != *params.PreferredAddress {
			b.Fatalf("preferred address mismatch: %v vs %v", p.PreferredAddress, params.PreferredAddress)
		}
	}
}

func FuzzTransportParameters(f *testing.F) {
	corpus := ossfuzzseeds.New(f)

	savedParams := (&TransportParameters{
		InitialMaxStreamDataBidiLocal:  1234,
		InitialMaxStreamDataBidiRemote: 2345,
		InitialMaxStreamDataUni:        3456,
		InitialMaxData:                 4567,
		MaxBidiStreamNum:               1337,
		MaxUniStreamNum:                7331,
		ActiveConnectionIDLimit:        7,
		MaxDatagramFrameSize:           protocol.InvalidByteCount,
	}).MarshalForSessionTicket(nil)
	// address_discovery with the value 0 (the endpoint provides address observations)
	savedParamsWithAddressDiscovery := quicvarint.Append(slices.Clone(savedParams), uint64(addressDiscoveryParameterID))
	savedParamsWithAddressDiscovery = append(quicvarint.Append(savedParamsWithAddressDiscovery, 1), 0)
	zeroRTTParams := (&TransportParameters{
		StatelessResetToken:     &protocol.StatelessResetToken{},
		ActiveConnectionIDLimit: 7,
		MaxDatagramFrameSize:    1200,
	}).Marshal(protocol.PerspectiveServer)

	rcid := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xc0, 0xde})
	minAckDelay := 42 * time.Millisecond
	for _, seed := range []struct {
		Data      []byte
		SavedData []byte
	}{
		{(&TransportParameters{
			StatelessResetToken:     &protocol.StatelessResetToken{},
			ActiveConnectionIDLimit: 2,
		}).Marshal(protocol.PerspectiveServer), savedParams},
		{zeroRTTParams, savedParams},
		{(&TransportParameters{
			ActiveConnectionIDLimit: 2,
			RetrySourceConnectionID: &rcid,
		}).Marshal(protocol.PerspectiveClient), savedParams},
		{(&TransportParameters{
			EnableResetStreamAt:     true,
			RetrySourceConnectionID: &rcid,
			MinAckDelay:             &minAckDelay,
		}).Marshal(protocol.PerspectiveClient), savedParams},
		// initial_max_path_id
		{(&TransportParameters{
			ActiveConnectionIDLimit: 2,
			HasInitialMaxPathID:     true,
		}).Marshal(protocol.PerspectiveClient), savedParams},
		{(&TransportParameters{
			StatelessResetToken:     &protocol.StatelessResetToken{},
			ActiveConnectionIDLimit: 4,
			InitialMaxPathID:        protocol.MaxPathID,
			HasInitialMaxPathID:     true,
		}).Marshal(protocol.PerspectiveServer), savedParams},
		{(&TransportParameters{
			ActiveConnectionIDLimit: 2,
			InitialMaxPathID:        quicvarint.Max,
			HasInitialMaxPathID:     true,
		}).Marshal(protocol.PerspectiveClient), savedParams},
		// version_information
		{(&TransportParameters{
			ActiveConnectionIDLimit: 2,
			VersionInformation: &VersionInformation{
				ChosenVersion:     protocol.Version1,
				AvailableVersions: []protocol.Version{protocol.Version1, protocol.Version2},
			},
		}).Marshal(protocol.PerspectiveClient), savedParams},
		{(&TransportParameters{
			StatelessResetToken:     &protocol.StatelessResetToken{},
			ActiveConnectionIDLimit: 2,
			VersionInformation:      &VersionInformation{ChosenVersion: protocol.Version2},
		}).Marshal(protocol.PerspectiveServer), savedParams},
		// add_address, address_discovery and grease_quic_bit
		{(&TransportParameters{
			ActiveConnectionIDLimit: 2,
			HasInitialMaxPathID:     true,
			EnableAddAddress:        true,
			AddressDiscovery:        AddressDiscoveryProvideAndReceive,
			GreaseQUICBit:           true,
		}).Marshal(protocol.PerspectiveClient), savedParams},
		{(&TransportParameters{
			StatelessResetToken:     &protocol.StatelessResetToken{},
			ActiveConnectionIDLimit: 2,
			AddressDiscovery:        AddressDiscoveryReceive,
		}).Marshal(protocol.PerspectiveServer), savedParams},
		{(&TransportParameters{
			StatelessResetToken:     &protocol.StatelessResetToken{},
			ActiveConnectionIDLimit: 2,
			AddressDiscovery:        AddressDiscoveryProvide,
			GreaseQUICBit:           true,
		}).Marshal(protocol.PerspectiveServer), savedParamsWithAddressDiscovery},
		// session ticket
		{savedParams, savedParams},
		{savedParamsWithAddressDiscovery, savedParamsWithAddressDiscovery},
		// with preferred address
		{(&TransportParameters{
			StatelessResetToken:     &protocol.StatelessResetToken{},
			ActiveConnectionIDLimit: 2,
			PreferredAddress: &PreferredAddress{
				IPv4:                netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 42),
				IPv6:                netip.AddrPortFrom(netip.AddrFrom16([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}), 13),
				ConnectionID:        protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
				StatelessResetToken: protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
			},
		}).Marshal(protocol.PerspectiveServer), savedParams},
	} {
		corpus.Add(seed.Data, seed.SavedData)
	}

	f.Fuzz(func(t *testing.T, data, savedData []byte) {
		fuzzTransportParameters(t, data, protocol.PerspectiveClient)
		fuzzTransportParameters(t, data, protocol.PerspectiveServer)
		fuzzTransportParametersSessionTicket(t, data)
		fuzzTransportParameters0RTT(t, data, savedData)
	})
}

func fuzzTransportParameters(t *testing.T, data []byte, sentBy protocol.Perspective) {
	t.Helper()

	tp := &TransportParameters{}
	if err := tp.Unmarshal(data, sentBy); err != nil {
		return
	}
	_ = tp.String()
	checkTransportParameterInvariants(t, tp, sentBy)

	tp2 := &TransportParameters{}
	if err := tp2.Unmarshal(tp.Marshal(sentBy), sentBy); err != nil {
		t.Fatalf("error unmarshaling re-marshaled transport parameters: %s", err)
	}
	checkTransportParameterInvariants(t, tp2, sentBy)
	if tp2.HasInitialMaxPathID != tp.HasInitialMaxPathID || tp2.InitialMaxPathID != tp.InitialMaxPathID {
		t.Fatalf("initial_max_path_id changed: %t %d vs %t %d", tp.HasInitialMaxPathID, tp.InitialMaxPathID, tp2.HasInitialMaxPathID, tp2.InitialMaxPathID)
	}
	if tp2.EnableAddAddress != tp.EnableAddAddress || tp2.AddressDiscovery != tp.AddressDiscovery || tp2.GreaseQUICBit != tp.GreaseQUICBit {
		t.Fatalf("extension parameters changed: %s vs %s", tp, tp2)
	}
	if (tp.VersionInformation == nil) != (tp2.VersionInformation == nil) ||
		(tp.VersionInformation != nil && (tp.VersionInformation.ChosenVersion != tp2.VersionInformation.ChosenVersion ||
			!slices.Equal(tp.VersionInformation.AvailableVersions, tp2.VersionInformation.AvailableVersions))) {
		t.Fatalf("version_information changed: %v vs %v", tp.VersionInformation, tp2.VersionInformation)
	}
}

func fuzzTransportParametersSessionTicket(t *testing.T, data []byte) {
	t.Helper()

	tp := &TransportParameters{}
	if err := tp.UnmarshalFromSessionTicket(data); err != nil {
		return
	}
	_ = tp.String()
	if tp.HasInitialMaxPathID {
		t.Fatal("initial_max_path_id restored from a session ticket")
	}
	if tp.EnableAddAddress || tp.GreaseQUICBit || tp.VersionInformation != nil {
		t.Fatalf("connection-specific transport parameters restored from a session ticket: %s", tp)
	}
	b := tp.MarshalForSessionTicket(nil)
	tp2 := &TransportParameters{}
	if err := tp2.UnmarshalFromSessionTicket(b); err != nil {
		t.Fatalf("error unmarshaling re-marshaled session ticket transport parameters: %s", err)
	}
	if tp2.AddressDiscovery != tp.AddressDiscovery || tp2.EnableResetStreamAt != tp.EnableResetStreamAt {
		t.Fatalf("session ticket transport parameters changed: %s vs %s", tp, tp2)
	}
}

func fuzzTransportParameters0RTT(t *testing.T, data, savedData []byte) {
	t.Helper()

	tp := &TransportParameters{}
	if err := tp.Unmarshal(data, protocol.PerspectiveServer); err != nil {
		return
	}
	saved := &TransportParameters{}
	if err := saved.UnmarshalFromSessionTicket(savedData); err != nil {
		return
	}
	_ = tp.ValidFor0RTT(saved)
	_ = tp.ValidForUpdate(saved)
}

func checkTransportParameterInvariants(t *testing.T, tp *TransportParameters, sentBy protocol.Perspective) {
	t.Helper()

	if sentBy == protocol.PerspectiveClient && tp.StatelessResetToken != nil {
		t.Fatal("client's transport parameters contained stateless reset token")
	}
	if tp.MaxIdleTimeout < 0 {
		t.Fatalf("negative max_idle_timeout: %s", tp.MaxIdleTimeout)
	}
	if tp.AckDelayExponent > 20 {
		t.Fatalf("invalid ack_delay_exponent: %d", tp.AckDelayExponent)
	}
	if tp.MaxUDPPayloadSize < 1200 {
		t.Fatalf("invalid max_udp_payload_size: %d", tp.MaxUDPPayloadSize)
	}
	if tp.ActiveConnectionIDLimit < 2 {
		t.Fatalf("invalid active_connection_id_limit: %d", tp.ActiveConnectionIDLimit)
	}
	if tp.OriginalDestinationConnectionID.Len() > 20 {
		t.Fatalf("invalid original_destination_connection_id length: %s", tp.OriginalDestinationConnectionID)
	}
	if tp.InitialSourceConnectionID.Len() > 20 {
		t.Fatalf("invalid initial_source_connection_id length: %s", tp.InitialSourceConnectionID)
	}
	if tp.RetrySourceConnectionID != nil && tp.RetrySourceConnectionID.Len() > 20 {
		t.Fatalf("invalid retry_source_connection_id length: %s", tp.RetrySourceConnectionID)
	}
	if tp.PreferredAddress != nil && tp.PreferredAddress.ConnectionID.Len() > 20 {
		t.Fatalf("invalid preferred_address connection ID length: %s", tp.PreferredAddress.ConnectionID)
	}
	if tp.InitialMaxPathID > quicvarint.Max {
		t.Fatalf("invalid initial_max_path_id: %d", tp.InitialMaxPathID)
	}
	if !tp.HasInitialMaxPathID && tp.InitialMaxPathID != 0 {
		t.Fatalf("initial_max_path_id set, but not marked as received: %d", tp.InitialMaxPathID)
	}
	if vi := tp.VersionInformation; vi != nil {
		if vi.ChosenVersion == 0 || slices.Contains(vi.AvailableVersions, 0) {
			t.Fatalf("version_information contains version 0: %s", vi)
		}
		if sentBy == protocol.PerspectiveClient && !slices.Contains(vi.AvailableVersions, vi.ChosenVersion) {
			t.Fatalf("client's version_information doesn't contain the Chosen Version: %s", vi)
		}
	}
	if tp.AddressDiscovery > AddressDiscoveryProvideAndReceive {
		t.Fatalf("invalid address_discovery: %s", tp.AddressDiscovery)
	}
	if tp.MinAckDelay != nil {
		if *tp.MinAckDelay < 0 {
			t.Fatalf("negative min_ack_delay: %s", *tp.MinAckDelay)
		}
		if *tp.MinAckDelay > tp.MaxAckDelay {
			t.Fatalf("min_ack_delay (%s) is greater than max_ack_delay (%s)", *tp.MinAckDelay, tp.MaxAckDelay)
		}
	}
}
