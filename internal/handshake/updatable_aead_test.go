package handshake

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/fips140"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	mrand "math/rand/v2"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/internal/utils"
	"github.com/AeonDave/mp-quic-go/qlog"
	"github.com/AeonDave/mp-quic-go/qlogwriter"
	"github.com/AeonDave/mp-quic-go/testutils/events"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	msg = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
	ad  = "Donec in velit neque."
)

func randomCipherSuite() cipherSuite { return cipherSuites[mrand.IntN(len(cipherSuites))] }

func setupEndpoints(t *testing.T, serverRTTStats *utils.RTTStats) (client, server *updatableAEAD, serverEventRecorder *events.Recorder) {
	return setupEndpointsWithCipherSuite(t, randomCipherSuite(), serverRTTStats)
}

func setupEndpointsWithCipherSuite(t *testing.T, cs cipherSuite, serverRTTStats *utils.RTTStats) (client, server *updatableAEAD, serverEventRecorder *events.Recorder) {
	t.Helper()
	var eventRecorder events.Recorder

	trafficSecret1 := make([]byte, 16)
	trafficSecret2 := make([]byte, 16)
	rand.Read(trafficSecret1)
	rand.Read(trafficSecret2)

	client = newUpdatableAEAD(utils.NewRTTStats(), nil, utils.DefaultLogger, protocol.Version1)
	server = newUpdatableAEAD(serverRTTStats, &eventRecorder, utils.DefaultLogger, protocol.Version1)
	client.SetReadKey(cs, trafficSecret2)
	client.SetWriteKey(cs, trafficSecret1)
	server.SetReadKey(cs, trafficSecret1)
	server.SetWriteKey(cs, trafficSecret2)
	return client, server, &eventRecorder
}

func bothSides(ev qlogwriter.Event) []qlogwriter.Event {
	switch ev := ev.(type) {
	case qlog.KeyDiscarded:
		return []qlogwriter.Event{
			qlog.KeyDiscarded{
				KeyType:  qlog.KeyTypeClient1RTT,
				KeyPhase: ev.KeyPhase,
			},
			qlog.KeyDiscarded{
				KeyType:  qlog.KeyTypeServer1RTT,
				KeyPhase: ev.KeyPhase,
			},
		}
	case qlog.KeyUpdated:
		return []qlogwriter.Event{
			qlog.KeyUpdated{
				KeyType:  qlog.KeyTypeClient1RTT,
				KeyPhase: ev.KeyPhase,
				Trigger:  ev.Trigger,
			},
			qlog.KeyUpdated{
				KeyType:  qlog.KeyTypeServer1RTT,
				KeyPhase: ev.KeyPhase,
				Trigger:  ev.Trigger,
			},
		}
	default:
		panic("unexpected event type: " + ev.Name())
	}
}

func TestChaChaTestVector(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("ChaCha20-Poly1305 is not allowed in FIPS 140-3 mode")
	}

	testCases := []struct {
		name            string
		version         protocol.Version
		expectedPayload []byte
		expectedPacket  []byte
	}{
		{
			version:         protocol.Version1,
			expectedPayload: splitHexString(t, "655e5cd55c41f69080575d7999c25a5bfb"),
			expectedPacket:  splitHexString(t, "4cfe4189655e5cd55c41f69080575d7999c25a5bfb"),
		},
		{
			version:         protocol.Version2,
			expectedPayload: splitHexString(t, "0ae7b6b932bc27d786f4bc2bb20f2162ba"),
			expectedPacket:  splitHexString(t, "5558b1c60ae7b6b932bc27d786f4bc2bb20f2162ba"),
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("QUIC %s", tc.version), func(t *testing.T) {
			secret := splitHexString(t, "9ac312a7f877468ebe69422748ad00a1 5443f18203a07d6060f688f30f21632b")
			aead := newUpdatableAEAD(utils.NewRTTStats(), nil, nil, tc.version)
			chacha := getCipherSuite(tls.TLS_CHACHA20_POLY1305_SHA256)
			require.Equal(t, tls.TLS_CHACHA20_POLY1305_SHA256, chacha.ID)
			aead.SetWriteKey(chacha, secret)
			const pnOffset = 1
			header := splitHexString(t, "4200bff4")
			payloadOffset := len(header)
			plaintext := splitHexString(t, "01")
			payload := aead.Seal(nil, plaintext, 654360564, header)
			require.Equal(t, tc.expectedPayload, payload)
			// path 0 of the multipath extension uses the same nonce
			aead0 := newUpdatableAEAD(utils.NewRTTStats(), nil, nil, tc.version)
			aead0.SetWriteKey(chacha, secret)
			require.Equal(t, tc.expectedPayload, aead0.SealForPath(nil, plaintext, 0, 654360564, header))
			packet := append(header, payload...)
			aead.EncryptHeader(packet[pnOffset+4:pnOffset+4+16], &packet[0], packet[pnOffset:payloadOffset])
			require.Equal(t, tc.expectedPacket, packet)
		})
	}
}

func TestUpdatableAEADHeaderProtection(t *testing.T) {
	for _, v := range []protocol.Version{protocol.Version1, protocol.Version2} {
		for _, cs := range cipherSuites {
			t.Run(fmt.Sprintf("QUIC %s/%s", v, tls.CipherSuiteName(cs.ID)), func(t *testing.T) {
				trafficSecret1 := make([]byte, 16)
				trafficSecret2 := make([]byte, 16)
				rand.Read(trafficSecret1)
				rand.Read(trafficSecret2)

				client := newUpdatableAEAD(utils.NewRTTStats(), nil, utils.DefaultLogger, v)
				server := newUpdatableAEAD(utils.NewRTTStats(), nil, utils.DefaultLogger, v)
				client.SetReadKey(cs, trafficSecret2)
				client.SetWriteKey(cs, trafficSecret1)
				server.SetReadKey(cs, trafficSecret1)
				server.SetWriteKey(cs, trafficSecret2)

				var lastFiveBitsDifferent int
				for range 100 {
					sample := make([]byte, 16)
					rand.Read(sample)
					header := []byte{0xb5, 1, 2, 3, 4, 5, 6, 7, 8, 0xde, 0xad, 0xbe, 0xef}
					client.EncryptHeader(sample, &header[0], header[9:13])
					if header[0]&0x1f != 0xb5&0x1f {
						lastFiveBitsDifferent++
					}
					require.Equal(t, byte(0xb5&0xe0), header[0]&0xe0)
					require.Equal(t, []byte{1, 2, 3, 4, 5, 6, 7, 8}, header[1:9])
					require.NotEqual(t, []byte{0xde, 0xad, 0xbe, 0xef}, header[9:13])
					server.DecryptHeader(sample, &header[0], header[9:13])
					require.Equal(t, []byte{0xb5, 1, 2, 3, 4, 5, 6, 7, 8, 0xde, 0xad, 0xbe, 0xef}, header)
				}
				require.Greater(t, lastFiveBitsDifferent, 75)
			})
		}
	}
}

func TestUpdatableAEADEncryptDecryptMessage(t *testing.T) {
	for _, v := range []protocol.Version{protocol.Version1, protocol.Version2} {
		for _, cs := range cipherSuites {
			t.Run(fmt.Sprintf("QUIC %s/%s", v, tls.CipherSuiteName(cs.ID)), func(t *testing.T) {
				rttStats := utils.RTTStats{}
				trafficSecret1 := make([]byte, 16)
				trafficSecret2 := make([]byte, 16)
				rand.Read(trafficSecret1)
				rand.Read(trafficSecret2)

				client := newUpdatableAEAD(&rttStats, nil, utils.DefaultLogger, v)
				server := newUpdatableAEAD(&rttStats, nil, utils.DefaultLogger, v)
				client.SetReadKey(cs, trafficSecret2)
				client.SetWriteKey(cs, trafficSecret1)
				server.SetReadKey(cs, trafficSecret1)
				server.SetWriteKey(cs, trafficSecret2)

				msg := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")
				ad := []byte("Donec in velit neque.")

				encrypted := server.Seal(nil, msg, 0x1337, ad)

				opened, err := client.Open(nil, encrypted, monotime.Now(), 0x1337, protocol.KeyPhaseZero, ad)
				require.NoError(t, err)
				require.Equal(t, msg, opened)

				_, err = client.Open(nil, encrypted, monotime.Now(), 0x1337, protocol.KeyPhaseZero, []byte("wrong ad"))
				require.ErrorIs(t, err, ErrDecryptionFailed)

				_, err = client.Open(nil, encrypted, monotime.Now(), 0x42, protocol.KeyPhaseZero, ad)
				require.ErrorIs(t, err, ErrDecryptionFailed)
			})
		}
	}
}

func TestUpdatableAEADPacketNumbers(t *testing.T) {
	client, server, _ := setupEndpoints(t, utils.NewRTTStats())
	msg := []byte("Lorem ipsum")
	ad := []byte("Donec in velit neque.")

	encrypted := server.Seal(nil, msg, 0x1337, ad)
	require.Equal(t, protocol.PacketNumber(0x1337), server.FirstPacketNumber()) // make sure we save the first packet number
	_ = server.Seal(nil, msg, 0x1338, ad)
	require.Equal(t, protocol.PacketNumber(0x1337), server.FirstPacketNumber()) // make sure we save the first packet number

	// check that decoding the packet number works as expected
	_, err := client.Open(nil, encrypted[:len(encrypted)-1], monotime.Now(), 0x1337, protocol.KeyPhaseZero, ad)
	require.Error(t, err)
	require.Equal(t, protocol.PacketNumber(0x38), client.DecodePacketNumber(0x38, protocol.PacketNumberLen1))

	_, err = client.Open(nil, encrypted, monotime.Now(), 0x1337, protocol.KeyPhaseZero, ad)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(0x1338), client.DecodePacketNumber(0x38, protocol.PacketNumberLen1))
}

func TestAEADLimitReached(t *testing.T) {
	client, _, _ := setupEndpoints(t, utils.NewRTTStats())
	client.invalidPacketLimit = 10
	for i := range 9 {
		_, err := client.Open(nil, []byte("foobar"), monotime.Now(), protocol.PacketNumber(i), protocol.KeyPhaseZero, []byte("ad"))
		require.ErrorIs(t, err, ErrDecryptionFailed)
	}
	_, err := client.Open(nil, []byte("foobar"), monotime.Now(), 10, protocol.KeyPhaseZero, []byte("ad"))
	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.AEADLimitReached, transportErr.ErrorCode)
}

func TestKeyUpdates(t *testing.T) {
	client, server, _ := setupEndpoints(t, utils.NewRTTStats())

	now := monotime.Now()
	require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
	encrypted0 := server.Seal(nil, []byte(msg), 0x1337, []byte(ad))
	server.rollKeys()
	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
	encrypted1 := server.Seal(nil, []byte(msg), 0x1337, []byte(ad))
	require.NotEqual(t, encrypted0, encrypted1)

	_, err := client.Open(nil, encrypted1, now, 0x1337, protocol.KeyPhaseZero, []byte(ad))
	require.ErrorIs(t, err, ErrDecryptionFailed)

	client.rollKeys()
	decrypted, err := client.Open(nil, encrypted1, now, 0x1337, protocol.KeyPhaseOne, []byte(ad))
	require.NoError(t, err)
	require.Equal(t, msg, string(decrypted))
}

// func TestUpdatesKeysWhenReceivingPacketWithNextKeyPhase(t *testing.T) {
// 	rttStats := utils.RTTStats{}
// 	mockCtrl := gomock.NewController(t)
// 	serverTracer := mocklogging.NewMockConnectionTracer(mockCtrl)

// 	trafficSecret1 := make([]byte, 16)
// 	trafficSecret2 := make([]byte, 16)
// 	rand.Read(trafficSecret1)
// 	rand.Read(trafficSecret2)

// 	client := newUpdatableAEAD(&rttStats, nil, utils.DefaultLogger, protocol.Version1)
// 	server := newUpdatableAEAD(&rttStats, serverTracer, utils.DefaultLogger, protocol.Version1)
// 	client.SetReadKey(cs, trafficSecret2)
// 	client.SetWriteKey(cs, trafficSecret1)
// 	server.SetReadKey(cs, trafficSecret1)
// 	server.SetWriteKey(cs, trafficSecret2)

// 	now := monotime.Now()
// 	encrypted0 := client.Seal(nil, []byte(msg), 0x42, ad)
// 	decrypted, err := server.Open(nil, encrypted0, now, 0x42, protocol.KeyPhaseZero, ad)
// 	require.NoError(t, err)
// 	require.Equal(t, msg, decrypted)

// 	require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
// 	_ = server.Seal(nil, msg, 0x1, ad)

// 	client.rollKeys()
// 	encrypted1 := client.Seal(nil, msg, 0x43, ad)
// 	serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), true)
// 	decrypted, err = server.Open(nil, encrypted1, now, 0x43, protocol.KeyPhaseOne, ad)
// 	require.NoError(t, err)
// 	require.Equal(t, msg, decrypted)
// 	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
// }

func TestReorderedPacketAfterKeyUpdate(t *testing.T) {
	client, server, eventRecorder := setupEndpoints(t, utils.NewRTTStats())

	now := monotime.Now()
	encrypted01 := client.Seal(nil, []byte(msg), 0x42, []byte(ad))
	encrypted02 := client.Seal(nil, []byte(msg), 0x43, []byte(ad))
	_, err := server.Open(nil, encrypted01, now, 0x42, protocol.KeyPhaseZero, []byte(ad))
	require.NoError(t, err)
	_ = server.Seal(nil, []byte(msg), 0x1, []byte(ad))

	client.rollKeys()
	encrypted1 := client.Seal(nil, []byte(msg), 0x44, []byte(ad))
	require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
	_, err = server.Open(nil, encrypted1, now, 0x44, protocol.KeyPhaseOne, []byte(ad))
	require.NoError(t, err)
	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
	require.Equal(t,
		bothSides(qlog.KeyUpdated{Trigger: qlog.KeyUpdateRemote, KeyPhase: 1}),
		eventRecorder.Events(),
	)

	// now receive a reordered packet
	decrypted, err := server.Open(nil, encrypted02, now, 0x43, protocol.KeyPhaseZero, []byte(ad))
	require.NoError(t, err)
	require.Equal(t, msg, string(decrypted))
	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
}

func TestDropsKeys3PTOsAfterKeyUpdate(t *testing.T) {
	rttStats := utils.NewRTTStats()
	client, server, eventRecorder := setupEndpoints(t, rttStats)

	now := monotime.Now()
	rttStats.UpdateRTT(10*time.Millisecond, 0)
	pto := rttStats.PTO(true)
	encrypted01 := client.Seal(nil, []byte(msg), 0x42, []byte(ad))
	encrypted02 := client.Seal(nil, []byte(msg), 0x43, []byte(ad))
	_, err := server.Open(nil, encrypted01, now, 0x42, protocol.KeyPhaseZero, []byte(ad))
	require.NoError(t, err)
	_ = server.Seal(nil, []byte(msg), 0x1, []byte(ad))

	client.rollKeys()
	encrypted1 := client.Seal(nil, []byte(msg), 0x44, []byte(ad))
	require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
	_, err = server.Open(nil, encrypted1, now, 0x44, protocol.KeyPhaseOne, []byte(ad))
	require.NoError(t, err)
	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
	require.Equal(t,
		bothSides(qlog.KeyUpdated{KeyPhase: 1, Trigger: qlog.KeyUpdateRemote}),
		eventRecorder.Events(),
	)
	eventRecorder.Clear()

	// packet arrived too late, the key was already dropped
	_, err = server.Open(nil, encrypted02, now.Add(3*pto).Add(time.Nanosecond), 0x43, protocol.KeyPhaseZero, []byte(ad))
	require.ErrorIs(t, err, ErrKeysDropped)
	require.Equal(t,
		bothSides(qlog.KeyDiscarded{KeyPhase: 0}),
		eventRecorder.Events(),
	)
}

func TestAllowsFirstKeyUpdateImmediately(t *testing.T) {
	client, server, serverTracer := setupEndpoints(t, utils.NewRTTStats())
	client.rollKeys()
	encrypted := client.Seal(nil, []byte(msg), 0x1337, []byte(ad))

	// if decryption failed, we don't expect a key phase update
	_, err := server.Open(nil, encrypted[:len(encrypted)-1], monotime.Now(), 0x1337, protocol.KeyPhaseOne, []byte(ad))
	require.ErrorIs(t, err, ErrDecryptionFailed)

	// the key phase is updated on first successful decryption
	_, err = server.Open(nil, encrypted, monotime.Now(), 0x1337, protocol.KeyPhaseOne, []byte(ad))
	require.NoError(t, err)
	require.Equal(t,
		bothSides(qlog.KeyUpdated{KeyPhase: 1, Trigger: qlog.KeyUpdateRemote}),
		serverTracer.Events(),
	)
}

func TestRejectFrequentKeyUpdates(t *testing.T) {
	client, server, _ := setupEndpoints(t, utils.NewRTTStats())

	server.rollKeys()
	client.rollKeys()
	encrypted0 := client.Seal(nil, []byte(msg), 0x42, []byte(ad))
	_, err := server.Open(nil, encrypted0, monotime.Now(), 0x42, protocol.KeyPhaseOne, []byte(ad))
	require.NoError(t, err)

	client.rollKeys()
	encrypted1 := client.Seal(nil, []byte(msg), 0x42, []byte(ad))
	_, err = server.Open(nil, encrypted1, monotime.Now(), 0x42, protocol.KeyPhaseZero, []byte(ad))
	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.KeyUpdateError, transportErr.ErrorCode)
	require.Equal(t, "keys updated too quickly", transportErr.ErrorMessage)
}

func setKeyUpdateIntervals(t *testing.T, firstKeyUpdateInterval, keyUpdateInterval uint64) {
	reset := SetKeyUpdateInterval(keyUpdateInterval)
	t.Cleanup(reset)

	origFirstKeyUpdateInterval := FirstKeyUpdateInterval
	FirstKeyUpdateInterval = firstKeyUpdateInterval

	t.Cleanup(func() { FirstKeyUpdateInterval = origFirstKeyUpdateInterval })
}

func TestInitiateKeyUpdateAfterSendingMaxPackets(t *testing.T) {
	const firstKeyUpdateInterval = 5
	const keyUpdateInterval = 20
	setKeyUpdateIntervals(t, firstKeyUpdateInterval, keyUpdateInterval)

	client, server, eventRecorder := setupEndpoints(t, utils.NewRTTStats())
	server.SetHandshakeConfirmed()

	var pn protocol.PacketNumber
	// first key update
	for range firstKeyUpdateInterval {
		require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
		server.Seal(nil, []byte(msg), pn, []byte(ad))
		pn++
	}
	// the first update is allowed without receiving an acknowledgement
	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
	require.Equal(t,
		bothSides(qlog.KeyUpdated{KeyPhase: 1, Trigger: qlog.KeyUpdateLocal}),
		eventRecorder.Events(),
	)
	eventRecorder.Clear()

	// subsequent key update
	for range 2 * keyUpdateInterval {
		require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
		server.Seal(nil, []byte(msg), pn, []byte(ad))
		pn++
	}
	// no update allowed before receiving an acknowledgement for the current key phase
	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
	// receive an ACK for a packet sent in key phase 1
	client.rollKeys()
	b := client.Seal(nil, []byte("foobar"), 1, []byte("ad"))
	_, err := server.Open(nil, b, monotime.Now(), 1, protocol.KeyPhaseOne, []byte("ad"))
	require.NoError(t, err)
	require.NoError(t, server.SetLargestAcked(firstKeyUpdateInterval))
	require.Empty(t, eventRecorder.Events())

	require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
	require.Equal(t,
		append(
			bothSides(qlog.KeyDiscarded{KeyPhase: 0}),
			bothSides(qlog.KeyUpdated{KeyPhase: 2, Trigger: qlog.KeyUpdateLocal})...,
		),
		eventRecorder.Events(),
	)
}

func TestKeyUpdateEnforceACKKeyPhase(t *testing.T) {
	const firstKeyUpdateInterval = 5
	setKeyUpdateIntervals(t, firstKeyUpdateInterval, protocol.KeyUpdateInterval)

	_, server, eventRecorder := setupEndpoints(t, utils.NewRTTStats())
	server.SetHandshakeConfirmed()

	// First make sure that we update our keys.
	for i := range firstKeyUpdateInterval {
		pn := protocol.PacketNumber(i)
		require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
		server.Seal(nil, []byte(msg), pn, []byte(ad))
	}
	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
	require.Equal(t,
		bothSides(qlog.KeyUpdated{KeyPhase: 1, Trigger: qlog.KeyUpdateLocal}),
		eventRecorder.Events(),
	)
	eventRecorder.Clear()

	// Now that our keys are updated, send a packet using the new keys.
	const nextPN = firstKeyUpdateInterval + 1
	server.Seal(nil, []byte(msg), nextPN, []byte(ad))

	for i := range firstKeyUpdateInterval {
		// We haven't decrypted any packet in the new key phase yet.
		// This means that the ACK must have been sent in the old key phase.
		require.NoError(t, server.SetLargestAcked(protocol.PacketNumber(i)))
	}

	// We haven't decrypted any packet in the new key phase yet.
	// This means that the ACK must have been sent in the old key phase.
	err := server.SetLargestAcked(nextPN)
	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.KeyUpdateError, transportErr.ErrorCode)
	require.Equal(t, "received ACK for key phase 1, but peer didn't update keys", transportErr.ErrorMessage)
	require.Empty(t, eventRecorder.Events())
}

func TestKeyUpdateAfterReorderedACK(t *testing.T) {
	t.Run("without multipath", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			testKeyUpdateAfterReorderedACK(t, false)
		})
	})
	t.Run("with multipath", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			testKeyUpdateAfterReorderedACK(t, true)
		})
	})
}

// An ACK frame acknowledges a packet sent with the current keys,
// and a reordered ACK frame received afterwards only acknowledges packets sent with the previous keys.
func testKeyUpdateAfterReorderedACK(t *testing.T, multipath bool) {
	const firstKeyUpdateInterval = 5
	const keyUpdateInterval = 20
	setKeyUpdateIntervals(t, firstKeyUpdateInterval, keyUpdateInterval)

	const maxPTO = 100 * time.Millisecond
	client, server, serverEvents := setupEndpoints(t, utils.NewRTTStats())
	if multipath {
		client.EnableMultipath(func() time.Duration { return maxPTO })
		server.EnableMultipath(func() time.Duration { return maxPTO })
	}
	server.SetHandshakeConfirmed()

	var pn protocol.PacketNumber
	for range firstKeyUpdateInterval {
		require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
		server.Seal(nil, []byte(msg), pn, []byte(ad))
		pn++
	}
	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
	for range keyUpdateInterval {
		require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
		server.Seal(nil, []byte(msg), pn, []byte(ad))
		pn++
	}
	client.rollKeys()
	b := client.Seal(nil, []byte(msg), 1, []byte(ad))
	_, err := server.Open(nil, b, monotime.Now(), 1, protocol.KeyPhaseOne, []byte(ad))
	require.NoError(t, err)
	serverEvents.Clear()

	// an ACK frame acknowledges a packet sent in key phase 1
	require.NoError(t, server.SetLargestAcked(firstKeyUpdateInterval+1))
	// a reordered ACK frame only acknowledges packets sent in key phase 0
	require.NoError(t, server.SetLargestAcked(firstKeyUpdateInterval-1))

	if multipath {
		// The reordered ACK frame doesn't withdraw the permission to update the keys.
		// The next key update is initiated 3 PTOs after the first ACK frame.
		time.Sleep(3*maxPTO - time.Nanosecond)
		require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
		time.Sleep(time.Nanosecond)
	} else {
		// Without the multipath extension, the next key update is only initiated
		// if the most recent ACK frame acknowledges a packet sent in key phase 1.
		require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
		require.Empty(t, serverEvents.Events())
		require.NoError(t, server.SetLargestAcked(firstKeyUpdateInterval+2))
	}
	require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
	require.Equal(t,
		append(
			bothSides(qlog.KeyDiscarded{KeyPhase: 0}),
			bothSides(qlog.KeyUpdated{KeyPhase: 2, Trigger: qlog.KeyUpdateLocal})...,
		),
		serverEvents.Events(),
	)
}

func TestKeyUpdateAfterOpeningMaxPackets(t *testing.T) {
	const firstKeyUpdateInterval = 5
	const keyUpdateInterval = 20
	setKeyUpdateIntervals(t, firstKeyUpdateInterval, keyUpdateInterval)

	client, server, eventRecorder := setupEndpoints(t, utils.NewRTTStats())
	server.SetHandshakeConfirmed()

	msg := []byte("message")
	ad := []byte("additional data")

	// first key update
	var pn protocol.PacketNumber
	for range firstKeyUpdateInterval {
		require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
		encrypted := client.Seal(nil, msg, pn, ad)
		_, err := server.Open(nil, encrypted, monotime.Now(), pn, protocol.KeyPhaseZero, ad)
		require.NoError(t, err)
		pn++
	}

	// the first update is allowed without receiving an acknowledgement
	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
	require.Equal(t,
		bothSides(qlog.KeyUpdated{KeyPhase: 1, Trigger: qlog.KeyUpdateLocal}),
		eventRecorder.Events(),
	)
	eventRecorder.Clear()

	// subsequent key update
	client.rollKeys()
	for range keyUpdateInterval {
		require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
		encrypted := client.Seal(nil, msg, pn, ad)
		_, err := server.Open(nil, encrypted, monotime.Now(), pn, protocol.KeyPhaseOne, ad)
		require.NoError(t, err)
		pn++
	}

	// No update allowed before receiving an acknowledgement for the current key phase
	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
	server.Seal(nil, msg, 1, ad)
	require.NoError(t, server.SetLargestAcked(firstKeyUpdateInterval+1))
	require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
	require.Equal(t,
		append(
			bothSides(qlog.KeyDiscarded{KeyPhase: 0}),
			bothSides(qlog.KeyUpdated{KeyPhase: 2, Trigger: qlog.KeyUpdateLocal})...,
		),
		eventRecorder.Events(),
	)
}

func TestKeyUpdateKeyPhaseSkipping(t *testing.T) {
	const firstKeyUpdateInterval = 5
	const keyUpdateInterval = 20
	setKeyUpdateIntervals(t, firstKeyUpdateInterval, keyUpdateInterval)

	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(10*time.Millisecond, 0)
	client, server, eventRecorder := setupEndpoints(t, rttStats)
	server.SetHandshakeConfirmed()

	now := monotime.Now()
	data1 := client.Seal(nil, []byte(msg), 1, []byte(ad))
	_, err := server.Open(nil, data1, now, 1, protocol.KeyPhaseZero, []byte(ad))
	require.NoError(t, err)
	for i := range firstKeyUpdateInterval {
		pn := protocol.PacketNumber(i)
		require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
		server.Seal(nil, []byte(msg), pn, []byte(ad))
		require.NoError(t, server.SetLargestAcked(pn))
	}
	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
	require.Equal(t,
		bothSides(qlog.KeyUpdated{KeyPhase: 1, Trigger: qlog.KeyUpdateLocal}),
		eventRecorder.Events(),
	)
	eventRecorder.Clear()

	// The server never received a packet at key phase 1.
	// Make sure the key phase 0 is still there at a much later point.
	data2 := client.Seal(nil, []byte(msg), 2, []byte(ad))
	_, err = server.Open(nil, data2, now.Add(10*rttStats.PTO(true)), 2, protocol.KeyPhaseZero, []byte(ad))
	require.NoError(t, err)
	require.Empty(t, eventRecorder.Events())
}

func TestFastKeyUpdatesByPeer(t *testing.T) {
	const firstKeyUpdateInterval = 5
	const keyUpdateInterval = 20
	setKeyUpdateIntervals(t, firstKeyUpdateInterval, keyUpdateInterval)

	client, server, eventRecorder := setupEndpoints(t, utils.NewRTTStats())
	server.SetHandshakeConfirmed()

	var pn protocol.PacketNumber
	for range firstKeyUpdateInterval {
		require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
		server.Seal(nil, []byte(msg), pn, []byte(ad))
		pn++
	}
	b := client.Seal(nil, []byte("foobar"), 1, []byte("ad"))
	_, err := server.Open(nil, b, monotime.Now(), 1, protocol.KeyPhaseZero, []byte("ad"))
	require.NoError(t, err)
	require.NoError(t, server.SetLargestAcked(0))
	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
	require.Equal(t,
		bothSides(qlog.KeyUpdated{KeyPhase: 1, Trigger: qlog.KeyUpdateLocal}),
		eventRecorder.Events(),
	)
	eventRecorder.Clear()

	// Send and receive an acknowledgement for a packet in key phase 1.
	// We are now running a timer to drop the keys with 3 PTO.
	server.Seal(nil, []byte(msg), pn, []byte(ad))
	client.rollKeys()
	dataKeyPhaseOne := client.Seal(nil, []byte(msg), 2, []byte(ad))
	now := monotime.Now()
	_, err = server.Open(nil, dataKeyPhaseOne, now, 2, protocol.KeyPhaseOne, []byte(ad))
	require.NoError(t, err)
	require.NoError(t, server.SetLargestAcked(pn))
	// Now the client sends us a packet in key phase 2, forcing us to update keys before the 3 PTO period is over.
	// This mean that we need to drop the keys for key phase 0 immediately.
	client.rollKeys()
	dataKeyPhaseTwo := client.Seal(nil, []byte(msg), 3, []byte(ad))

	_, err = server.Open(nil, dataKeyPhaseTwo, now, 3, protocol.KeyPhaseZero, []byte(ad))
	require.NoError(t, err)
	require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
	require.Equal(t,
		append(
			bothSides(qlog.KeyDiscarded{KeyPhase: 0}),
			bothSides(qlog.KeyUpdated{KeyPhase: 2, Trigger: qlog.KeyUpdateRemote})...,
		),
		eventRecorder.Events(),
	)
}

func TestFastKeyUpdateByUs(t *testing.T) {
	const firstKeyUpdateInterval = 5
	const keyUpdateInterval = 20
	setKeyUpdateIntervals(t, firstKeyUpdateInterval, keyUpdateInterval)

	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(10*time.Millisecond, 0)
	client, server, eventRecorder := setupEndpoints(t, rttStats)
	server.SetHandshakeConfirmed()

	// send so many packets that we initiate the first key update
	for i := range firstKeyUpdateInterval {
		pn := protocol.PacketNumber(i)
		require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
		server.Seal(nil, []byte(msg), pn, []byte(ad))
	}
	b := client.Seal(nil, []byte("foobar"), 1, []byte("ad"))
	_, err := server.Open(nil, b, monotime.Now(), 1, protocol.KeyPhaseZero, []byte("ad"))
	require.NoError(t, err)
	require.NoError(t, server.SetLargestAcked(0))
	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
	require.Equal(t,
		bothSides(qlog.KeyUpdated{KeyPhase: 1, Trigger: qlog.KeyUpdateLocal}),
		eventRecorder.Events(),
	)
	eventRecorder.Clear()

	// send so many packets that we initiate the next key update
	for i := keyUpdateInterval; i < 2*keyUpdateInterval; i++ {
		pn := protocol.PacketNumber(i)
		require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
		server.Seal(nil, []byte(msg), pn, []byte(ad))
	}
	client.rollKeys()
	b = client.Seal(nil, []byte("foobar"), 2, []byte("ad"))
	now := monotime.Now()
	_, err = server.Open(nil, b, now, 2, protocol.KeyPhaseOne, []byte("ad"))
	require.NoError(t, err)
	require.NoError(t, server.SetLargestAcked(keyUpdateInterval))
	require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
	require.Equal(t,
		append(
			bothSides(qlog.KeyDiscarded{KeyPhase: 0}),
			bothSides(qlog.KeyUpdated{KeyPhase: 2, Trigger: qlog.KeyUpdateLocal})...,
		),
		eventRecorder.Events(),
	)
	eventRecorder.Clear()

	// We haven't received an ACK for a packet sent in key phase 2 yet.
	// Make sure we canceled the timer to drop the previous key phase.
	b = client.Seal(nil, []byte("foobar"), 3, []byte("ad"))
	_, err = server.Open(nil, b, now.Add(10*rttStats.PTO(true)), 3, protocol.KeyPhaseOne, []byte("ad"))
	require.NoError(t, err)
	require.Empty(t, eventRecorder.Events())
}

func TestIVForPath(t *testing.T) {
	iv := splitHexString(t, "6b26114b9cba2b63a9e8dd4f")
	require.Equal(t, iv, ivForPath(iv, 0))
	require.Equal(t, splitHexString(t, "6b2611489cba2b63a9e8dd4f"), ivForPath(iv, 3))
	require.Equal(t, splitHexString(t, "94d9eeb49cba2b63a9e8dd4f"), ivForPath(iv, protocol.MaxPathID))
	require.Equal(t, splitHexString(t, "6b26114b9cba2b63a9e8dd4f"), iv) // the IV is not modified
	// longer IVs: the path-and-packet-number is left-padded with zeros
	require.Equal(t,
		splitHexString(t, "000102030405060708090a0b0c0d0e0f"),
		ivForPath(splitHexString(t, "000102030405060408090a0b0c0d0e0f"), 3),
	)
	require.Panics(t, func() { ivForPath(iv, protocol.MaxPathID+1) })
	require.Panics(t, func() { ivForPath(iv[:8], 1) })
}

// pathPPNNonce calculates the nonce defined in Section 2.4 of draft-ietf-quic-multipath for a 12-byte IV:
// the IV XORed with the path ID (32 bits), two zero bits and the packet number (62 bits).
func pathPPNNonce(iv []byte, pathID protocol.PathID, pn protocol.PacketNumber) []byte {
	var ppn [12]byte
	binary.BigEndian.PutUint32(ppn[:4], uint32(pathID))
	binary.BigEndian.PutUint64(ppn[4:], uint64(pn))
	nonce := make([]byte, 12)
	subtle.XORBytes(nonce, iv, ppn[:])
	return nonce
}

func TestMultipathNonceTestVector(t *testing.T) {
	// draft-ietf-quic-multipath, Section 2.4, Figure 3
	iv := splitHexString(t, "6b26114b9cba2b63a9e8dd4f")
	const pathID = 3
	const pn = 54321
	expectedNonce := splitHexString(t, "6b2611489cba2b63a9e8097e")
	require.Equal(t, expectedNonce, pathPPNNonce(iv, pathID, pn))

	suite := getCipherSuite(tls.TLS_AES_128_GCM_SHA256)
	secret := make([]byte, suite.Hash.Size())
	rand.Read(secret)
	a := newUpdatableAEAD(utils.NewRTTStats(), nil, utils.DefaultLogger, protocol.Version1)
	a.SetWriteKey(suite, secret)
	// use the IV of the test vector
	a.sendKeys.iv = iv
	a.path0.sendAEAD = nil

	block, err := aes.NewCipher(a.sendKeys.key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	require.Equal(t,
		gcm.Seal(nil, expectedNonce, []byte(msg), []byte(ad)),
		a.SealForPath(nil, []byte(msg), pathID, pn, []byte(ad)),
	)
	// path 0 uses the nonce defined in RFC 9001
	nonce0 := splitHexString(t, "6b26114b9cba2b63a9e8097e")
	require.Equal(t,
		gcm.Seal(nil, nonce0, []byte(msg), []byte(ad)),
		a.SealForPath(nil, []byte(msg), 0, pn, []byte(ad)),
	)
}

func TestMultipathNonce(t *testing.T) {
	for _, v := range []protocol.Version{protocol.Version1, protocol.Version2} {
		for _, cs := range cipherSuites {
			t.Run(fmt.Sprintf("QUIC %s/%s", v, tls.CipherSuiteName(cs.ID)), func(t *testing.T) {
				secret := make([]byte, cs.Hash.Size())
				rand.Read(secret)
				sealer := newUpdatableAEAD(utils.NewRTTStats(), nil, utils.DefaultLogger, v)
				sealer.SetWriteKey(cs, secret)
				opener := newUpdatableAEAD(utils.NewRTTStats(), nil, utils.DefaultLogger, v)
				opener.SetReadKey(cs, secret)

				// derive the key and the IV (RFC 9001, Section 5.1 and RFC 9369, Section 3.3.2)
				keyLabel, ivLabel := "quic key", "quic iv"
				if v == protocol.Version2 {
					keyLabel, ivLabel = "quicv2 key", "quicv2 iv"
				}
				key := hkdfExpandLabel(cs.Hash, secret, []byte{}, keyLabel, cs.KeyLen)
				iv := hkdfExpandLabel(cs.Hash, secret, []byte{}, ivLabel, 12)
				var aead cipher.AEAD
				switch cs.ID {
				case tls.TLS_CHACHA20_POLY1305_SHA256:
					var err error
					aead, err = chacha20poly1305.New(key)
					require.NoError(t, err)
				default:
					block, err := aes.NewCipher(key)
					require.NoError(t, err)
					aead, err = cipher.NewGCM(block)
					require.NoError(t, err)
				}

				for _, pathID := range []protocol.PathID{0, 1, 3, 0xdeadbeef, protocol.MaxPathID} {
					for _, pn := range []protocol.PacketNumber{0, 54321, 1<<62 - 1} {
						sealed := sealer.SealForPath(nil, []byte(msg), pathID, pn, []byte(ad))
						require.Equal(t, aead.Seal(nil, pathPPNNonce(iv, pathID, pn), []byte(msg), []byte(ad)), sealed)
						opened, err := opener.OpenForPath(nil, sealed, monotime.Now(), pathID, pn, protocol.KeyPhaseZero, []byte(ad))
						require.NoError(t, err)
						require.Equal(t, []byte(msg), opened)
					}
				}
			})
		}
	}
}

func TestSealOpenForPathZero(t *testing.T) {
	for _, v := range []protocol.Version{protocol.Version1, protocol.Version2} {
		for _, cs := range cipherSuites {
			t.Run(fmt.Sprintf("QUIC %s/%s", v, tls.CipherSuiteName(cs.ID)), func(t *testing.T) {
				secret := make([]byte, cs.Hash.Size())
				rand.Read(secret)
				sealer := newUpdatableAEAD(utils.NewRTTStats(), nil, utils.DefaultLogger, v)
				sealer.SetWriteKey(cs, secret)
				sealer0 := newUpdatableAEAD(utils.NewRTTStats(), nil, utils.DefaultLogger, v)
				sealer0.SetWriteKey(cs, secret)
				opener := newUpdatableAEAD(utils.NewRTTStats(), nil, utils.DefaultLogger, v)
				opener.SetReadKey(cs, secret)
				opener0 := newUpdatableAEAD(utils.NewRTTStats(), nil, utils.DefaultLogger, v)
				opener0.SetReadKey(cs, secret)

				for _, pn := range []protocol.PacketNumber{0x1337, 0x1338, 0x10000} {
					sealed := sealer.Seal(nil, []byte(msg), pn, []byte(ad))
					require.Equal(t, sealed, sealer0.SealForPath(nil, []byte(msg), 0, pn, []byte(ad)))

					opened, err := opener.Open(nil, sealed, monotime.Now(), pn, protocol.KeyPhaseZero, []byte(ad))
					require.NoError(t, err)
					opened0, err := opener0.OpenForPath(nil, sealed, monotime.Now(), 0, pn, protocol.KeyPhaseZero, []byte(ad))
					require.NoError(t, err)
					require.Equal(t, opened, opened0)
					require.Equal(t,
						opener.DecodePacketNumber(0x42, protocol.PacketNumberLen1),
						opener0.DecodePacketNumberForPath(0, 0x42, protocol.PacketNumberLen1),
					)
				}
				// the path ID 0 methods and the methods without path ID share the state
				require.Equal(t, protocol.PacketNumber(0x10042), opener0.DecodePacketNumber(0x42, protocol.PacketNumberLen1))
				require.Equal(t, protocol.PacketNumber(0x10042), opener.DecodePacketNumberForPath(0, 0x42, protocol.PacketNumberLen1))
			})
		}
	}
}

func TestMultipathPacketsDontOpenOnOtherPaths(t *testing.T) {
	client, server, _ := setupEndpoints(t, utils.NewRTTStats())
	sealed := client.SealForPath(nil, []byte(msg), 3, 42, []byte(ad))

	_, err := server.Open(nil, sealed, monotime.Now(), 42, protocol.KeyPhaseZero, []byte(ad))
	require.ErrorIs(t, err, ErrDecryptionFailed)
	require.Equal(t, uint64(1), server.invalidPacketCount)
	for i, pathID := range []protocol.PathID{0, 2} {
		_, err := server.OpenForPath(nil, sealed, monotime.Now(), pathID, 42, protocol.KeyPhaseZero, []byte(ad))
		require.ErrorIs(t, err, ErrDecryptionFailed)
		// every packet is decrypted at most once
		require.Equal(t, uint64(i+2), server.invalidPacketCount)
	}
	// no state is kept for a path if the first packet received on it can't be opened
	require.NotContains(t, server.paths, protocol.PathID(2))
	opened, err := server.OpenForPath(nil, sealed, monotime.Now(), 3, 42, protocol.KeyPhaseZero, []byte(ad))
	require.NoError(t, err)
	require.Equal(t, []byte(msg), opened)
	require.Equal(t, uint64(3), server.invalidPacketCount)
	require.Contains(t, server.paths, protocol.PathID(3))
	// a packet that can't be opened doesn't remove the state of a path
	_, err = server.OpenForPath(nil, sealed[:len(sealed)-1], monotime.Now(), 3, 43, protocol.KeyPhaseZero, []byte(ad))
	require.ErrorIs(t, err, ErrDecryptionFailed)
	require.Contains(t, server.paths, protocol.PathID(3))
	require.Equal(t, protocol.PacketNumber(42), server.paths[3].highestRcvdPN)
}

// The state that the sender keeps for a path is not removed when a packet received on the path can't be opened.
func TestMultipathFailedOpenKeepsSendState(t *testing.T) {
	client, server, _ := setupEndpoints(t, utils.NewRTTStats())
	sealed := server.SealForPath(nil, []byte(msg), 2, 0, []byte(ad))
	require.Contains(t, server.paths, protocol.PathID(2))
	_, err := server.OpenForPath(nil, []byte("garbage, too short to be a packet"), monotime.Now(), 2, 0, protocol.KeyPhaseZero, []byte(ad))
	require.ErrorIs(t, err, ErrDecryptionFailed)
	require.Contains(t, server.paths, protocol.PathID(2))
	opened, err := client.OpenForPath(nil, sealed, monotime.Now(), 2, 0, protocol.KeyPhaseZero, []byte(ad))
	require.NoError(t, err)
	require.Equal(t, []byte(msg), opened)
}

func TestDecodePacketNumberForPath(t *testing.T) {
	client, server, _ := setupEndpoints(t, utils.NewRTTStats())

	sealed := client.SealForPath(nil, []byte(msg), 1, 0x10000, []byte(ad))
	// can't decode the packet number if decryption failed
	_, err := server.OpenForPath(nil, sealed[:len(sealed)-1], monotime.Now(), 1, 0x10000, protocol.KeyPhaseZero, []byte(ad))
	require.ErrorIs(t, err, ErrDecryptionFailed)
	require.Equal(t, protocol.PacketNumber(0x38), server.DecodePacketNumberForPath(1, 0x38, protocol.PacketNumberLen1))

	_, err = server.OpenForPath(nil, sealed, monotime.Now(), 1, 0x10000, protocol.KeyPhaseZero, []byte(ad))
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(0x10038), server.DecodePacketNumberForPath(1, 0x38, protocol.PacketNumberLen1))
	// the packet number spaces of the other paths are not affected
	require.Equal(t, protocol.PacketNumber(0x38), server.DecodePacketNumberForPath(2, 0x38, protocol.PacketNumberLen1))
	require.Equal(t, protocol.PacketNumber(0x38), server.DecodePacketNumberForPath(0, 0x38, protocol.PacketNumberLen1))
	require.Equal(t, protocol.PacketNumber(0x38), server.DecodePacketNumber(0x38, protocol.PacketNumberLen1))
	require.NotContains(t, server.paths, protocol.PathID(2))

	sealed = client.SealForPath(nil, []byte(msg), 2, 0x137, []byte(ad))
	_, err = server.OpenForPath(nil, sealed, monotime.Now(), 2, 0x137, protocol.KeyPhaseZero, []byte(ad))
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(0x138), server.DecodePacketNumberForPath(2, 0x38, protocol.PacketNumberLen1))
	require.Equal(t, protocol.PacketNumber(0x10038), server.DecodePacketNumberForPath(1, 0x38, protocol.PacketNumberLen1))
	require.Equal(t, protocol.PacketNumber(0x38), server.DecodePacketNumberForPath(0, 0x38, protocol.PacketNumberLen1))
}

func TestSelectReceiveKey(t *testing.T) {
	const current = protocol.KeyPhaseZero
	const other = protocol.KeyPhaseOne
	const invalid = protocol.InvalidPacketNumber

	for _, tc := range []struct {
		name                    string
		kp                      protocol.KeyPhaseBit
		pn                      protocol.PacketNumber
		firstRcvdWithCurrentKey protocol.PacketNumber
		havePrevKeys            bool
		expected                receiveKey
	}{
		{name: "current key phase", kp: current, pn: 10, firstRcvdWithCurrentKey: 20, havePrevKeys: true, expected: receiveKeyCurrent},
		{name: "current key phase, no packets with current keys", kp: current, pn: 10, firstRcvdWithCurrentKey: invalid, havePrevKeys: true, expected: receiveKeyCurrent},
		{name: "lower packet number", kp: other, pn: 10, firstRcvdWithCurrentKey: 20, havePrevKeys: true, expected: receiveKeyPrevious},
		{name: "lower packet number, previous keys dropped", kp: other, pn: 10, firstRcvdWithCurrentKey: 20, havePrevKeys: false, expected: receiveKeyPrevious},
		{name: "higher packet number", kp: other, pn: 30, firstRcvdWithCurrentKey: 20, havePrevKeys: true, expected: receiveKeyNext},
		{name: "higher packet number, previous keys dropped", kp: other, pn: 30, firstRcvdWithCurrentKey: 20, havePrevKeys: false, expected: receiveKeyNext},
		{name: "no packets with current keys, previous keys retained", kp: other, pn: 30, firstRcvdWithCurrentKey: invalid, havePrevKeys: true, expected: receiveKeyPrevious},
		{name: "no packets with current keys, previous keys dropped", kp: other, pn: 30, firstRcvdWithCurrentKey: invalid, havePrevKeys: false, expected: receiveKeyNext},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, selectReceiveKey(tc.kp, current, tc.pn, tc.firstRcvdWithCurrentKey, tc.havePrevKeys))
		})
	}
}

type multipathTestPacket struct {
	pathID protocol.PathID
	pn     protocol.PacketNumber
	kp     protocol.KeyPhaseBit
	data   []byte
}

func sealForPath(a *updatableAEAD, pathID protocol.PathID, pn protocol.PacketNumber) multipathTestPacket {
	return multipathTestPacket{
		pathID: pathID,
		pn:     pn,
		kp:     a.keyPhase.Bit(),
		data:   a.SealForPath(nil, []byte(msg), pathID, pn, []byte(ad)),
	}
}

func openForPath(t *testing.T, a *updatableAEAD, p multipathTestPacket, rcvTime monotime.Time) error {
	t.Helper()
	opened, err := a.OpenForPath(nil, p.data, rcvTime, p.pathID, p.pn, p.kp, []byte(ad))
	if err == nil {
		require.Equal(t, []byte(msg), opened)
	}
	return err
}

func setupMultipathEndpoints(t *testing.T, serverRTTStats *utils.RTTStats, maxPTO time.Duration) (client, server *updatableAEAD, serverEventRecorder *events.Recorder) {
	t.Helper()
	client, server, serverEventRecorder = setupEndpoints(t, serverRTTStats)
	client.EnableMultipath(func() time.Duration { return maxPTO })
	server.EnableMultipath(func() time.Duration { return maxPTO })
	return client, server, serverEventRecorder
}

func TestMultipathKeyUpdateWithReorderingOnOtherPath(t *testing.T) {
	const firstKeyUpdateInterval = 5
	setKeyUpdateIntervals(t, firstKeyUpdateInterval, protocol.KeyUpdateInterval)

	client, server, serverEvents := setupMultipathEndpoints(t, utils.NewRTTStats(), time.Second)
	server.SetHandshakeConfirmed()
	now := monotime.Now()

	var clientPNs, serverPNs [3]protocol.PacketNumber
	send := func(sender *updatableAEAD, pns *[3]protocol.PacketNumber, pathID protocol.PathID) multipathTestPacket {
		p := sealForPath(sender, pathID, pns[pathID])
		pns[pathID]++
		return p
	}

	// both endpoints use paths 0, 1 and 2
	for pathID := range protocol.PathID(3) {
		require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
		require.NoError(t, openForPath(t, client, send(server, &serverPNs, pathID), now))
		require.NoError(t, openForPath(t, server, send(client, &clientPNs, pathID), now))
	}
	// packets in key phase 0 that are delayed on path 2 (server to client) and on path 1 (client to server)
	delayedServerPackets := []multipathTestPacket{send(server, &serverPNs, 2), send(server, &serverPNs, 2)}
	delayedClientPacket := send(client, &clientPNs, 1)
	// the first packet sent on path 3 is delayed as well
	delayedOnNewPath := sealForPath(server, 3, 0)

	// the server initiates a key update
	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
	require.Equal(t,
		bothSides(qlog.KeyUpdated{KeyPhase: 1, Trigger: qlog.KeyUpdateLocal}),
		serverEvents.Events(),
	)
	serverEvents.Clear()
	require.NoError(t, openForPath(t, client, send(server, &serverPNs, 0), now))
	require.Equal(t, protocol.KeyPhaseOne, client.keyPhase.Bit())
	require.NoError(t, openForPath(t, client, send(server, &serverPNs, 1), now))

	// path 2 didn't receive any packet in the new key phase, the delayed packets are opened with the previous keys
	for _, p := range delayedServerPackets {
		require.Equal(t, protocol.KeyPhaseZero, p.kp)
		require.NoError(t, openForPath(t, client, p, now))
	}
	require.NoError(t, openForPath(t, client, delayedOnNewPath, now))
	require.Equal(t, protocol.KeyPhaseOne, client.keyPhase.Bit())
	require.NoError(t, openForPath(t, client, send(server, &serverPNs, 2), now))

	// the client responds on path 2
	require.NoError(t, openForPath(t, server, send(client, &clientPNs, 2), now))
	// the delayed packet of the client on path 1 is opened with the previous keys
	require.NoError(t, openForPath(t, server, delayedClientPacket, now))
	require.NoError(t, openForPath(t, server, send(client, &clientPNs, 1), now))
	require.NoError(t, openForPath(t, server, send(client, &clientPNs, 0), now))
	require.Equal(t, protocol.KeyPhaseOne, server.keyPhase.Bit())
	require.Empty(t, serverEvents.Events())
	require.Zero(t, server.invalidPacketCount)
	require.Zero(t, client.invalidPacketCount)
}

func TestMultipathPeerKeyUpdateOnPathWithoutCurrentKeyPackets(t *testing.T) {
	rttStats := utils.NewRTTStats()
	const maxPTO = time.Second
	client, server, serverEvents := setupMultipathEndpoints(t, rttStats, maxPTO)
	now := monotime.Now()

	// the server receives packets on paths 0 and 1
	require.NoError(t, openForPath(t, server, sealForPath(client, 0, 0), now))
	require.NoError(t, openForPath(t, server, sealForPath(client, 1, 0), now))
	delayed := sealForPath(client, 1, 1)

	// the client updates its keys and sends the first packet with the new keys on path 2
	client.rollKeys()
	require.NoError(t, openForPath(t, server, sealForPath(client, 2, 0), now))
	require.Equal(t, protocol.KeyPhaseOne, server.keyPhase.Bit())
	require.Equal(t,
		bothSides(qlog.KeyUpdated{KeyPhase: 1, Trigger: qlog.KeyUpdateRemote}),
		serverEvents.Events(),
	)
	serverEvents.Clear()
	// paths 0 and 1 didn't receive any packets with the new keys yet
	require.NoError(t, openForPath(t, server, sealForPath(client, 0, 1), now))
	require.NoError(t, openForPath(t, server, delayed, now))

	// The server sends packets with the new keys, which allows the client to update its keys again.
	require.NoError(t, openForPath(t, client, sealForPath(server, 0, 0), now))
	client.rollKeys()
	// Path 1 didn't receive any packet in key phase 1 yet.
	// As long as the keys of key phase 0 are retained, the key phase bit selects them,
	// and the packet is decrypted only once.
	_, err := server.OpenForPath(nil, sealForPath(client, 1, 2).data, now, 1, 2, protocol.KeyPhaseZero, []byte(ad))
	require.ErrorIs(t, err, ErrDecryptionFailed)
	require.Equal(t, uint64(1), server.invalidPacketCount)

	// After 3 times the largest PTO, the keys of key phase 0 are dropped,
	// and a packet arriving on a path without packets in the current key phase triggers a key update.
	require.NoError(t, openForPath(t, server, sealForPath(client, 1, 3), now.Add(3*maxPTO+time.Nanosecond)))
	require.Equal(t, protocol.KeyPhaseZero, server.keyPhase.Bit())
	require.Equal(t,
		append(
			bothSides(qlog.KeyDiscarded{KeyPhase: 0}),
			bothSides(qlog.KeyUpdated{KeyPhase: 2, Trigger: qlog.KeyUpdateRemote})...,
		),
		serverEvents.Events(),
	)
}

func TestMultipathKeyUpdateErrorForOldKeysOnHigherPacketNumber(t *testing.T) {
	t.Run("current keys after old keys on the same path", func(t *testing.T) {
		testMultipathKeyUpdateErrorForOldKeysOnHigherPacketNumber(t, true, 2, true)
	})
	t.Run("current keys after old keys on another path", func(t *testing.T) {
		testMultipathKeyUpdateErrorForOldKeysOnHigherPacketNumber(t, true, 1, false)
	})
	// RFC 9001, Section 6.4 requires a KEY_UPDATE_ERROR without the multipath extension as well.
	// Single-path connections don't detect it yet, this subtest documents this known gap.
	t.Run("without multipath", func(t *testing.T) {
		testMultipathKeyUpdateErrorForOldKeysOnHigherPacketNumber(t, false, 2, false)
	})
}

func testMultipathKeyUpdateErrorForOldKeysOnHigherPacketNumber(t *testing.T, multipath bool, newKeysPath protocol.PathID, expectError bool) {
	client, server, _ := setupEndpoints(t, utils.NewRTTStats())
	if multipath {
		client.EnableMultipath(func() time.Duration { return time.Second })
	}
	now := monotime.Now()

	oldKeysPath := protocol.PathID(2)
	if !multipath {
		oldKeysPath = 0
		newKeysPath = 0
	}
	// The server uses the new keys for a lower packet number than a packet protected with the old keys.
	oldKeys := sealForPath(server, oldKeysPath, 50)
	server.rollKeys()
	newKeys := sealForPath(server, newKeysPath, 40)
	require.NoError(t, openForPath(t, client, sealForPath(server, 0, 60), now))
	require.Equal(t, protocol.KeyPhaseOne, client.keyPhase.Bit())
	require.NoError(t, openForPath(t, client, oldKeys, now))

	err := openForPath(t, client, newKeys, now)
	if !expectError {
		require.NoError(t, err)
		return
	}
	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.KeyUpdateError, transportErr.ErrorCode)
	require.Equal(t, "old keys used for a higher packet number", transportErr.ErrorMessage)
}

func TestMultipathKeyUpdateErrorForOldKeysAfterNewKeys(t *testing.T) {
	t.Run("with multipath", func(t *testing.T) {
		testMultipathKeyUpdateErrorForOldKeysAfterNewKeys(t, true)
	})
	// RFC 9001, Section 6.4 requires a KEY_UPDATE_ERROR without the multipath extension as well.
	// Single-path connections don't detect it yet, these subtests document this known gap.
	t.Run("without multipath", func(t *testing.T) {
		testMultipathKeyUpdateErrorForOldKeysAfterNewKeys(t, false)
	})
}

// The peer sends packets 55 (new keys), 58 (old keys) and 60 (new keys),
// i.e. it uses older keys for a higher packet number. The packets are received out of order.
func testMultipathKeyUpdateErrorForOldKeysAfterNewKeys(t *testing.T, multipath bool) {
	setup := func(t *testing.T) (client *updatableAEAD, p55, p58, p60 multipathTestPacket) {
		client, server, _ := setupEndpoints(t, utils.NewRTTStats())
		if multipath {
			client.EnableMultipath(func() time.Duration { return time.Second })
		}
		p58 = sealForPath(server, 0, 58)
		server.rollKeys()
		p55 = sealForPath(server, 0, 55)
		p60 = sealForPath(server, 0, 60)
		require.NoError(t, openForPath(t, client, p60, monotime.Now()))
		require.Equal(t, protocol.KeyPhaseOne, client.keyPhase.Bit())
		return client, p55, p58, p60
	}

	t.Run("old keys received first", func(t *testing.T) {
		client, p55, p58, _ := setup(t)
		require.NoError(t, openForPath(t, client, p58, monotime.Now()))
		err := openForPath(t, client, p55, monotime.Now())
		if !multipath {
			// known gap: RFC 9001, Section 6.4 requires a KEY_UPDATE_ERROR
			require.NoError(t, err)
			return
		}
		var transportErr *qerr.TransportError
		require.ErrorAs(t, err, &transportErr)
		require.Equal(t, qerr.KeyUpdateError, transportErr.ErrorCode)
	})

	t.Run("new keys received first", func(t *testing.T) {
		client, p55, p58, _ := setup(t)
		require.NoError(t, openForPath(t, client, p55, monotime.Now()))
		err := openForPath(t, client, p58, monotime.Now())
		if !multipath {
			// known gap: RFC 9001, Section 6.4 requires a KEY_UPDATE_ERROR
			require.NoError(t, err)
			return
		}
		// Packet 58 has a higher packet number than packet 55, which was protected with the current keys.
		// It is therefore decrypted with the next keys, never with the previous keys.
		require.ErrorIs(t, err, ErrDecryptionFailed)
		require.Equal(t, protocol.KeyPhaseOne, client.keyPhase.Bit())
	})
}

func TestMultipathKeyUpdateErrorForNextKeysOnLowerPacketNumber(t *testing.T) {
	client, server, _ := setupMultipathEndpoints(t, utils.NewRTTStats(), time.Second)
	now := monotime.Now()

	require.NoError(t, openForPath(t, client, sealForPath(server, 1, 90), now))
	p100 := sealForPath(server, 1, 100)
	server.rollKeys()
	// a packet with a lower packet number is protected with the next keys
	p95 := sealForPath(server, 1, 95)
	require.NoError(t, openForPath(t, client, p100, now))
	err := openForPath(t, client, p95, now)
	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.KeyUpdateError, transportErr.ErrorCode)
	require.Equal(t, "old keys used for a higher packet number", transportErr.ErrorMessage)
}

func TestMultipathKeysUpdatedTooQuickly(t *testing.T) {
	t.Run("no packet sent with the current keys", func(t *testing.T) {
		testMultipathKeysUpdatedTooQuickly(t, false)
	})
	t.Run("packet sent with the current keys on another path", func(t *testing.T) {
		testMultipathKeysUpdatedTooQuickly(t, true)
	})
}

func testMultipathKeysUpdatedTooQuickly(t *testing.T, sentWithCurrentKeys bool) {
	client, server, _ := setupMultipathEndpoints(t, utils.NewRTTStats(), time.Second)
	now := monotime.Now()

	client.rollKeys()
	require.NoError(t, openForPath(t, server, sealForPath(client, 1, 0), now))
	require.Equal(t, protocol.KeyPhaseOne, server.keyPhase.Bit())
	if sentWithCurrentKeys {
		server.SealForPath(nil, []byte(msg), 2, 0, []byte(ad))
	}

	client.rollKeys()
	err := openForPath(t, server, sealForPath(client, 1, 1), now)
	if sentWithCurrentKeys {
		require.NoError(t, err)
		require.Equal(t, protocol.KeyPhaseZero, server.keyPhase.Bit())
		return
	}
	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.KeyUpdateError, transportErr.ErrorCode)
	require.Equal(t, "keys updated too quickly", transportErr.ErrorMessage)
}

func TestMultipathKeyUpdateEnforceACKKeyPhase(t *testing.T) {
	client, server, _ := setupMultipathEndpoints(t, utils.NewRTTStats(), time.Second)
	now := monotime.Now()

	for pathID := range protocol.PathID(3) {
		server.SealForPath(nil, []byte(msg), pathID, 10, []byte(ad))
	}
	server.rollKeys()
	server.SealForPath(nil, []byte(msg), 1, 11, []byte(ad))

	// packets sent with the old keys
	require.NoError(t, server.SetLargestAckedForPath(1, 10, now))
	require.NoError(t, server.SetLargestAckedForPath(0, 10, now))
	// nothing was sent on path 2 with the new keys
	require.NoError(t, server.SetLargestAckedForPath(2, 100, now))
	// nothing was ever sent on path 5
	require.NoError(t, server.SetLargestAckedForPath(5, 100, now))
	require.False(t, server.currentKeyAcked)

	// The peer acknowledged a packet sent with the new keys, but didn't send any packet with the new keys yet.
	err := server.SetLargestAckedForPath(1, 11, now)
	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.KeyUpdateError, transportErr.ErrorCode)
	require.Equal(t, "received ACK for key phase 1, but peer didn't update keys", transportErr.ErrorMessage)

	// once the peer sent a packet with the new keys (on any path), the ACK is valid
	client.rollKeys()
	require.NoError(t, openForPath(t, server, sealForPath(client, 2, 0), now))
	require.NoError(t, server.SetLargestAckedForPath(1, 11, now))
	require.True(t, server.currentKeyAcked)
}

func TestMultipathKeyUpdateSpacing(t *testing.T) {
	t.Run("with multipath", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			testMultipathKeyUpdateSpacing(t, true, false, false)
		})
	})
	t.Run("PTO increasing", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			testMultipathKeyUpdateSpacing(t, true, true, false)
		})
	})
	t.Run("approaching the confidentiality limit", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			testMultipathKeyUpdateSpacing(t, true, false, true)
		})
	})
	t.Run("without multipath", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			testMultipathKeyUpdateSpacing(t, false, false, false)
		})
	})
}

func testMultipathKeyUpdateSpacing(t *testing.T, multipath, increasePTO, manyPackets bool) {
	const firstKeyUpdateInterval = 5
	const keyUpdateInterval = 20
	setKeyUpdateIntervals(t, firstKeyUpdateInterval, keyUpdateInterval)

	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(10*time.Millisecond, 0)
	client, server, serverEvents := setupEndpoints(t, rttStats)
	maxPTO := 100 * time.Millisecond
	if multipath {
		server.EnableMultipath(func() time.Duration { return maxPTO })
		client.EnableMultipath(func() time.Duration { return maxPTO })
	}
	server.SetHandshakeConfirmed()

	var pns [2]protocol.PacketNumber
	send := func(pathID protocol.PathID) multipathTestPacket {
		p := sealForPath(server, pathID, pns[pathID])
		pns[pathID]++
		return p
	}
	// with the multipath extension, packets are sent on paths 0 and 1, otherwise only on path 0
	pathFor := func(i int) protocol.PathID {
		if !multipath {
			return 0
		}
		return protocol.PathID(i % 2)
	}

	// the first key update is initiated without waiting
	for i := range firstKeyUpdateInterval {
		require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
		send(pathFor(i))
	}
	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
	serverEvents.Clear()

	for i := range keyUpdateInterval {
		require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
		require.NoError(t, openForPath(t, client, send(pathFor(i)), monotime.Now()))
	}
	require.Equal(t, protocol.KeyPhaseOne, client.keyPhase.Bit())
	require.NoError(t, openForPath(t, server, sealForPath(client, 0, 0), monotime.Now()))
	// no key update before a packet sent with the current keys is acknowledged
	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
	ackedPath := pathFor(1)
	require.NoError(t, server.SetLargestAckedForPath(ackedPath, pns[ackedPath]-1, monotime.Now()))
	if manyPackets {
		server.numSentWithCurrentKey = maxPacketsDelayingKeyUpdate
	}

	if multipath && !manyPackets {
		spacing := 3 * maxPTO
		if increasePTO {
			maxPTO *= 2
			spacing = 3 * maxPTO
		}
		// the spacing is measured from the first acknowledgment
		time.Sleep(maxPTO)
		require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
		require.NoError(t, server.SetLargestAckedForPath(0, pns[0]-1, monotime.Now()))
		time.Sleep(spacing - maxPTO - time.Nanosecond)
		require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
		require.Empty(t, serverEvents.Events())
		time.Sleep(time.Nanosecond)
	}
	require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
	require.Equal(t,
		append(
			bothSides(qlog.KeyDiscarded{KeyPhase: 0}),
			bothSides(qlog.KeyUpdated{KeyPhase: 2, Trigger: qlog.KeyUpdateLocal})...,
		),
		serverEvents.Events(),
	)
}

func TestMultipathKeyDropTimerUsesLargestPTO(t *testing.T) {
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(10*time.Millisecond, 0)
	const maxPTO = time.Second
	require.Less(t, 3*rttStats.PTO(true), maxPTO)
	client, server, serverEvents := setupMultipathEndpoints(t, rttStats, maxPTO)
	now := monotime.Now()

	delayed1 := sealForPath(client, 0, 0x40)
	delayed2 := sealForPath(client, 0, 0x41)
	require.NoError(t, openForPath(t, server, sealForPath(client, 0, 0x42), now))
	client.rollKeys()
	require.NoError(t, openForPath(t, server, sealForPath(client, 0, 0x43), now))
	require.Equal(t, protocol.KeyPhaseOne, server.keyPhase.Bit())
	serverEvents.Clear()

	// the PTO of the connection would already have dropped the keys
	require.NoError(t, openForPath(t, server, delayed1, now.Add(3*rttStats.PTO(true)+time.Nanosecond)))
	require.Empty(t, serverEvents.Events())
	err := openForPath(t, server, delayed2, now.Add(3*maxPTO+time.Nanosecond))
	require.ErrorIs(t, err, ErrKeysDropped)
	require.Equal(t, bothSides(qlog.KeyDiscarded{KeyPhase: 0}), serverEvents.Events())
}

func TestMultipathKeyDropTimerStartsOnFirstPacketWithNewKeys(t *testing.T) {
	const maxPTO = time.Second
	client, server, serverEvents := setupMultipathEndpoints(t, utils.NewRTTStats(), maxPTO)
	now := monotime.Now()

	delayed := []multipathTestPacket{sealForPath(client, 1, 0x10), sealForPath(client, 2, 0x10)}
	// the server initiates a key update
	server.rollKeys()
	require.NoError(t, openForPath(t, client, sealForPath(server, 0, 0), now))
	require.Equal(t, protocol.KeyPhaseOne, client.keyPhase.Bit())

	// The first packet with the new keys is received on path 0, which starts the key drop timer.
	require.NoError(t, openForPath(t, server, sealForPath(client, 0, 0x20), now))
	serverEvents.Clear()
	// Packets with the new keys received later on other paths don't restart it.
	require.NoError(t, openForPath(t, server, sealForPath(client, 1, 0x11), now.Add(2*maxPTO)))
	require.NoError(t, openForPath(t, server, sealForPath(client, 2, 0x11), now.Add(2*maxPTO)))
	require.Empty(t, serverEvents.Events())

	// the keys are dropped on all paths
	for _, p := range delayed {
		require.ErrorIs(t, openForPath(t, server, p, now.Add(3*maxPTO+time.Nanosecond)), ErrKeysDropped)
	}
	require.Equal(t, bothSides(qlog.KeyDiscarded{KeyPhase: 0}), serverEvents.Events())
}

func TestMultipathKeyUpdateErrorForPacketsReceivedBeforeKeyUpdate(t *testing.T) {
	client, server, _ := setupMultipathEndpoints(t, utils.NewRTTStats(), time.Second)
	now := monotime.Now()

	// path 1 receives a packet with the old keys
	p100 := sealForPath(server, 1, 100)
	server.rollKeys()
	p95 := sealForPath(server, 1, 95)
	require.NoError(t, openForPath(t, client, p100, now))
	// the key update happens on path 0
	require.NoError(t, openForPath(t, client, sealForPath(server, 0, 0), now))
	require.Equal(t, protocol.KeyPhaseOne, client.keyPhase.Bit())

	err := openForPath(t, client, p95, now)
	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.KeyUpdateError, transportErr.ErrorCode)
}

func TestMultipathAEADLimitReached(t *testing.T) {
	client, _, _ := setupMultipathEndpoints(t, utils.NewRTTStats(), time.Second)
	client.invalidPacketLimit = 10
	for i := range 9 {
		pathID := protocol.PathID(i % 4)
		_, err := client.OpenForPath(nil, []byte("foobar"), monotime.Now(), pathID, protocol.PacketNumber(i), protocol.KeyPhaseZero, []byte("ad"))
		require.ErrorIs(t, err, ErrDecryptionFailed)
	}
	_, err := client.OpenForPath(nil, []byte("foobar"), monotime.Now(), 5, 10, protocol.KeyPhaseZero, []byte("ad"))
	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.AEADLimitReached, transportErr.ErrorCode)
}

func TestMultipathKeyUpdateCountsPacketsOnAllPaths(t *testing.T) {
	const firstKeyUpdateInterval = 30
	setKeyUpdateIntervals(t, firstKeyUpdateInterval, protocol.KeyUpdateInterval)

	t.Run("sending", func(t *testing.T) {
		_, server, _ := setupMultipathEndpoints(t, utils.NewRTTStats(), time.Second)
		server.SetHandshakeConfirmed()
		for i := range firstKeyUpdateInterval {
			require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
			server.SealForPath(nil, []byte(msg), protocol.PathID(i%3), protocol.PacketNumber(i/3), []byte(ad))
		}
		require.Equal(t, uint64(firstKeyUpdateInterval), server.numSentWithCurrentKey)
		require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
	})

	t.Run("receiving", func(t *testing.T) {
		client, server, _ := setupMultipathEndpoints(t, utils.NewRTTStats(), time.Second)
		server.SetHandshakeConfirmed()
		for i := range firstKeyUpdateInterval {
			require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
			p := sealForPath(client, protocol.PathID(i%3), protocol.PacketNumber(i/3))
			require.NoError(t, openForPath(t, server, p, monotime.Now()))
		}
		require.Equal(t, uint64(firstKeyUpdateInterval), server.numRcvdWithCurrentKey)
		require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
	})
}

func TestMultipathDropPath(t *testing.T) {
	client, server, _ := setupMultipathEndpoints(t, utils.NewRTTStats(), time.Second)
	now := monotime.Now()

	for pathID := range protocol.PathID(3) {
		require.NoError(t, openForPath(t, server, sealForPath(client, pathID, 0x1000), now))
		server.SealForPath(nil, []byte(msg), pathID, 0x2000, []byte(ad))
	}
	server.rollKeys()
	server.SealForPath(nil, []byte(msg), 1, 0x2001, []byte(ad))
	require.Contains(t, server.paths, protocol.PathID(1))

	server.DropPath(1)
	require.NotContains(t, server.paths, protocol.PathID(1))
	require.Equal(t, protocol.PacketNumber(0x42), server.DecodePacketNumberForPath(1, 0x42, protocol.PacketNumberLen1))
	// the packet sent on path 1 with the new keys is forgotten
	require.NoError(t, server.SetLargestAckedForPath(1, 0x2001, now))
	// the other paths are not affected
	require.Equal(t, protocol.PacketNumber(0x1042), server.DecodePacketNumberForPath(2, 0x42, protocol.PacketNumberLen1))
	require.Equal(t, protocol.PacketNumber(0x1042), server.DecodePacketNumberForPath(0, 0x42, protocol.PacketNumberLen1))
	require.NoError(t, openForPath(t, server, sealForPath(client, 2, 0x1001), now))

	server.DropPath(0)
	require.Equal(t, protocol.PacketNumber(0x42), server.DecodePacketNumberForPath(0, 0x42, protocol.PacketNumberLen1))
	require.Equal(t, protocol.PacketNumber(0x1042), server.DecodePacketNumberForPath(2, 0x42, protocol.PacketNumberLen1))
}

func TestMultipathInterleavedPathsAcrossKeyUpdates(t *testing.T) {
	for _, cs := range cipherSuites {
		t.Run(tls.CipherSuiteName(cs.ID), func(t *testing.T) {
			if fips140.Enabled() && cs.ID != tls.TLS_CHACHA20_POLY1305_SHA256 {
				// In FIPS 140-3 mode, the AES-GCM AEAD enforces strictly increasing nonces.
				// Packets of different paths can therefore not be sealed with the same AEAD.
				secret := make([]byte, cs.Hash.Size())
				rand.Read(secret)
				aead := createAEAD(cs, secret, protocol.Version1)
				var nonce [8]byte
				binary.BigEndian.PutUint64(nonce[:], 10)
				aead.Seal(nil, nonce[:], []byte(msg), []byte(ad))
				binary.BigEndian.PutUint64(nonce[:], 0)
				require.Panics(t, func() { aead.Seal(nil, nonce[:], []byte(msg), []byte(ad)) })
			}

			client, server, _ := setupEndpointsWithCipherSuite(t, cs, utils.NewRTTStats())
			client.EnableMultipath(func() time.Duration { return time.Second })
			server.EnableMultipath(func() time.Duration { return time.Second })
			now := monotime.Now()

			// the packet number spaces of the paths overlap
			clientPNs := [3]protocol.PacketNumber{1000, 0, 500}
			serverPNs := [3]protocol.PacketNumber{0, 2000, 10}
			exchange := func() {
				for pathID := range protocol.PathID(3) {
					require.NoError(t, openForPath(t, server, sealForPath(client, pathID, clientPNs[pathID]), now))
					clientPNs[pathID]++
					require.NoError(t, openForPath(t, client, sealForPath(server, pathID, serverPNs[pathID]), now))
					serverPNs[pathID]++
				}
			}

			for range 10 {
				exchange()
			}
			client.rollKeys()
			for range 10 {
				exchange()
			}
			require.Equal(t, protocol.KeyPhaseOne, server.keyPhase.Bit())
			server.rollKeys()
			for range 10 {
				exchange()
			}
			require.Equal(t, protocol.KeyPhaseZero, client.keyPhase.Bit())
			require.Zero(t, server.invalidPacketCount)
			require.Zero(t, client.invalidPacketCount)
		})
	}
}

func getClientAndServer() (client, server *updatableAEAD) {
	trafficSecret1 := make([]byte, 16)
	trafficSecret2 := make([]byte, 16)
	rand.Read(trafficSecret1)
	rand.Read(trafficSecret2)

	cs := cipherSuites[0]
	rttStats := utils.NewRTTStats()
	client = newUpdatableAEAD(rttStats, nil, utils.DefaultLogger, protocol.Version1)
	server = newUpdatableAEAD(rttStats, nil, utils.DefaultLogger, protocol.Version1)
	client.SetReadKey(cs, trafficSecret2)
	client.SetWriteKey(cs, trafficSecret1)
	server.SetReadKey(cs, trafficSecret1)
	server.SetWriteKey(cs, trafficSecret2)
	return
}

func BenchmarkPacketEncryption(b *testing.B) {
	client, _ := getClientAndServer()
	const l = 1200
	src := make([]byte, l)
	rand.Read(src)
	ad := make([]byte, 32)
	rand.Read(ad)

	var pn protocol.PacketNumber
	for b.Loop() {
		src = client.Seal(src[:0], src[:l], pn, ad)
		pn++
	}
}

func BenchmarkPacketDecryption(b *testing.B) {
	client, server := getClientAndServer()
	const l = 1200
	src := make([]byte, l)
	dst := make([]byte, l)
	rand.Read(src)
	ad := make([]byte, 32)
	rand.Read(ad)
	src = client.Seal(src[:0], src[:l], 1337, ad)

	for b.Loop() {
		if _, err := server.Open(dst[:0], src, 0, 1337, protocol.KeyPhaseZero, ad); err != nil {
			b.Fatalf("opening failed: %v", err)
		}
	}
}

func BenchmarkRollKeys(b *testing.B) {
	client, _ := getClientAndServer()

	for b.Loop() {
		client.rollKeys()
	}
	if int(client.keyPhase) != b.N {
		b.Fatal("didn't roll keys often enough")
	}
}

// The next 1-RTT secret is derived using the label "quic ku" for QUIC version 1,
// and "quicv2 ku" for QUIC version 2 (section 3.3.2 of RFC 9369).
func TestKeyUpdateLabel(t *testing.T) {
	for _, tc := range []struct {
		version protocol.Version
		label   string
	}{
		{version: protocol.Version1, label: "quic ku"},
		{version: protocol.Version2, label: "quicv2 ku"},
	} {
		t.Run(tc.version.String(), func(t *testing.T) {
			cs := getCipherSuite(tls.TLS_AES_128_GCM_SHA256)
			secret := make([]byte, cs.Hash.Size())
			rand.Read(secret)
			a := newUpdatableAEAD(utils.NewRTTStats(), nil, utils.DefaultLogger, tc.version)
			a.SetReadKey(cs, secret)
			a.SetWriteKey(cs, secret)
			expected := hkdfExpandLabel(cs.Hash, secret, []byte{}, tc.label, cs.Hash.Size())
			require.Equal(t, expected, a.nextRcvTrafficSecret)
			require.Equal(t, expected, a.nextSendTrafficSecret)

			// after a key update, the AEAD uses keys derived from the next secret
			other := newUpdatableAEAD(utils.NewRTTStats(), nil, utils.DefaultLogger, tc.version)
			other.SetReadKey(cs, expected)
			other.SetWriteKey(cs, expected)
			a.rollKeys()
			sealed := a.Seal(nil, []byte(msg), 0x1337, []byte(ad))
			opened, err := other.Open(nil, sealed, monotime.Now(), 0x1337, protocol.KeyPhaseZero, []byte(ad))
			require.NoError(t, err)
			require.Equal(t, msg, string(opened))
		})
	}
}

// Once the confidentiality limit is reached, the keys are updated.
// If the keys can't be updated, they are not used anymore (section 6.6 of RFC 9001).
func TestConfidentialityLimitReached(t *testing.T) {
	client, _, _ := setupEndpoints(t, utils.NewRTTStats())
	client.confidentialityLimit = 10
	for i := range 9 {
		client.Seal(nil, []byte(msg), protocol.PacketNumber(i), []byte(ad))
		require.False(t, client.ConfidentialityLimitReached())
	}
	client.Seal(nil, []byte(msg), 9, []byte(ad))
	// the handshake is not confirmed yet, so the keys can't be updated
	require.True(t, client.ConfidentialityLimitReached())

	client.SetHandshakeConfirmed()
	require.False(t, client.ConfidentialityLimitReached())
	require.Equal(t, protocol.KeyPhaseOne, client.KeyPhase())
	require.False(t, client.ConfidentialityLimitReached())
}
