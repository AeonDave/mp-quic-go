package handshake

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/internal/utils"
	"github.com/AeonDave/mp-quic-go/internal/wire"
	"github.com/AeonDave/mp-quic-go/qlog"
	"github.com/AeonDave/mp-quic-go/qlogwriter"
	"github.com/AeonDave/mp-quic-go/quicvarint"
)

type quicVersionContextKey struct{}

var QUICVersionContextKey = &quicVersionContextKey{}

const clientSessionStateRevision = 5

type cryptoSetup struct {
	tlsConf *tls.Config
	conn    *tls.QUICConn

	// The post-handshake messages received from the server that were not completely received yet,
	// see checkPostHandshakeMessages (client only).
	postHandshakeData []byte

	events []Event

	// The version in use for the connection.
	// It differs from chosenVersion after compatible version negotiation (RFC 9368).
	version protocol.Version
	// The client's Chosen Version, i.e. the version of the client's first flight.
	// 0-RTT packets always use this version (section 4.1 of RFC 9369).
	chosenVersion protocol.Version
	// For the client: the versions the client supports, sorted by preference.
	// For the server: the versions the server prefers for compatible version negotiation,
	// sorted by preference. If empty, the server uses the client's Chosen Version.
	versions []protocol.Version
	// set by the client, if this connection attempt was started in response to a Version Negotiation packet
	reactedToVersionNegotiation bool
	// Did we write data at the Initial encryption level?
	// For the server, this is a HelloRetryRequest, if it happens before receiving the transport parameters.
	wroteInitialData bool
	// For the server: the first ClientHello, until it was received completely.
	clientHello []byte
	// For the server: set once the first ClientHello was received completely.
	parsedClientHello bool
	// For the server: the client's Version Information, once the Negotiated Version was selected.
	negotiatedVersionInfo *wire.VersionInformation
	// the connection ID used to derive the Initial keys
	initialConnID protocol.ConnectionID

	ourParams  *wire.TransportParameters
	peerParams *wire.TransportParameters

	zeroRTTParameters *wire.TransportParameters
	allow0RTT         bool
	// Server only: records that a session ticket is used for 0-RTT, see NewCryptoSetupServer.
	useTicketFor0RTT func(SessionTicketID, time.Time) bool

	rttStats *utils.RTTStats

	qlogger qlogwriter.Recorder
	logger  utils.Logger

	perspective protocol.Perspective

	handshakeCompleteTime time.Time

	zeroRTTOpener LongHeaderOpener // only set for the server
	zeroRTTSealer LongHeaderSealer // only set for the client

	initialOpener LongHeaderOpener
	initialSealer LongHeaderSealer
	// After switching to a different version, the server keeps the Initial keys of the client's Chosen Version
	// until it drops the Initial keys (section 4.1 of RFC 9369).
	chosenVersionInitialOpener LongHeaderOpener
	// Before the client learns the Negotiated Version, it might receive Initial packets of another compatible version.
	candidateVersion       protocol.Version
	candidateInitialOpener LongHeaderOpener

	handshakeOpener LongHeaderOpener
	handshakeSealer LongHeaderSealer

	used0RTT atomic.Bool

	// the cipher suite negotiated by TLS, set when the first keys are installed
	suite cipherSuite

	aead          *updatableAEAD
	has1RTTSealer bool
	has1RTTOpener bool
}

var _ CryptoSetup = &cryptoSetup{}

// NewCryptoSetupClient creates a new crypto setup for the client.
// The version is the client's Chosen Version, versions are the versions supported by the client,
// sorted by preference.
// reactedToVersionNegotiation is set if this connection attempt was started in response to a Version Negotiation packet.
// These are needed to validate the server's version_information transport parameter (section 4 of RFC 9368).
func NewCryptoSetupClient(
	connID protocol.ConnectionID,
	tp *wire.TransportParameters,
	tlsConf *tls.Config,
	enable0RTT bool,
	rttStats *utils.RTTStats,
	qlogger qlogwriter.Recorder,
	logger utils.Logger,
	version protocol.Version,
	versions []protocol.Version,
	reactedToVersionNegotiation bool,
) CryptoSetup {
	cs := newCryptoSetup(
		connID,
		tp,
		rttStats,
		qlogger,
		logger,
		protocol.PerspectiveClient,
		version,
	)
	cs.versions = versions
	cs.reactedToVersionNegotiation = reactedToVersionNegotiation

	tlsConf = setupConfigForClient(tlsConf)
	if tlsConf.ClientSessionCache != nil {
		// Session tickets are specific to a QUIC version (section 5 of RFC 9369).
		tlsConf = tlsConf.Clone()
		tlsConf.ClientSessionCache = &versionedSessionCache{ClientSessionCache: tlsConf.ClientSessionCache, cs: cs}
	}
	cs.tlsConf = tlsConf
	cs.allow0RTT = enable0RTT

	cs.conn = tls.QUICClient(&tls.QUICConfig{
		TLSConfig:           tlsConf,
		EnableSessionEvents: true,
	})
	cs.conn.SetTransportParameters(cs.ourParams.Marshal(protocol.PerspectiveClient))

	return cs
}

// NewCryptoSetupServer creates a new crypto setup for the server.
// The version is the version of the client's first flight.
// If preferredVersions is not empty, the server performs compatible version negotiation (section 2.3 of RFC 9368),
// selecting the first of the preferredVersions that the client's first flight is compatible with.
// The CryptoSetup then emits an EventVersionNegotiated, if it switched to a different version.
//
// If allow0RTT is set, useTicketFor0RTT is called for every session ticket that a client uses for 0-RTT, with the ID
// and the issue time of the ticket, before accepting 0-RTT. It returns false if the ticket must not be used for 0-RTT,
// because it was already used, which protects against the replay of 0-RTT data (section 9.2 of RFC 9001,
// section 8 of RFC 8446). If it is nil, 0-RTT is rejected.
func NewCryptoSetupServer(
	connID protocol.ConnectionID,
	localAddr, remoteAddr net.Addr,
	tp *wire.TransportParameters,
	tlsConf *tls.Config,
	allow0RTT bool,
	useTicketFor0RTT func(SessionTicketID, time.Time) bool,
	rttStats *utils.RTTStats,
	qlogger qlogwriter.Recorder,
	logger utils.Logger,
	version protocol.Version,
	preferredVersions []protocol.Version,
) CryptoSetup {
	cs := newCryptoSetup(
		connID,
		tp,
		rttStats,
		qlogger,
		logger,
		protocol.PerspectiveServer,
		version,
	)
	cs.allow0RTT = allow0RTT
	cs.useTicketFor0RTT = useTicketFor0RTT
	cs.versions = preferredVersions

	tlsConf = setupConfigForServer(tlsConf, localAddr, remoteAddr)
	tlsConf = restrictSessionTicketsToVersion(tlsConf, version)

	cs.tlsConf = tlsConf
	cs.conn = tls.QUICServer(getQUICConfig(tlsConf, localAddr, remoteAddr))
	return cs
}

func newCryptoSetup(
	connID protocol.ConnectionID,
	tp *wire.TransportParameters,
	rttStats *utils.RTTStats,
	qlogger qlogwriter.Recorder,
	logger utils.Logger,
	perspective protocol.Perspective,
	version protocol.Version,
) *cryptoSetup {
	initialSealer, initialOpener := NewInitialAEAD(connID, perspective, version)
	if qlogger != nil {
		qlogger.RecordEvent(qlog.KeyUpdated{
			Trigger: qlog.KeyUpdateTLS,
			KeyType: encLevelToKeyType(protocol.EncryptionInitial, protocol.PerspectiveClient),
		})
		qlogger.RecordEvent(qlog.KeyUpdated{
			Trigger: qlog.KeyUpdateTLS,
			KeyType: encLevelToKeyType(protocol.EncryptionInitial, protocol.PerspectiveServer),
		})
	}
	return &cryptoSetup{
		initialSealer: initialSealer,
		initialOpener: initialOpener,
		initialConnID: connID,
		aead:          newUpdatableAEAD(rttStats, qlogger, logger, version),
		events:        make([]Event, 0, 16),
		ourParams:     tp,
		rttStats:      rttStats,
		qlogger:       qlogger,
		logger:        logger,
		perspective:   perspective,
		version:       version,
		chosenVersion: version,
	}
}

func (h *cryptoSetup) ChangeConnectionID(id protocol.ConnectionID) {
	h.initialConnID = id
	h.candidateVersion = 0
	h.candidateInitialOpener = nil
	h.installInitialKeys()
}

// installInitialKeys derives the Initial keys for the current version and connection ID.
func (h *cryptoSetup) installInitialKeys() {
	initialSealer, initialOpener := NewInitialAEAD(h.initialConnID, h.perspective, h.version)
	h.initialSealer = initialSealer
	h.initialOpener = initialOpener
	if h.qlogger != nil {
		h.qlogger.RecordEvent(qlog.KeyUpdated{
			Trigger: qlog.KeyUpdateTLS,
			KeyType: encLevelToKeyType(protocol.EncryptionInitial, protocol.PerspectiveClient),
		})
		h.qlogger.RecordEvent(qlog.KeyUpdated{
			Trigger: qlog.KeyUpdateTLS,
			KeyType: encLevelToKeyType(protocol.EncryptionInitial, protocol.PerspectiveServer),
		})
	}
}

// SwitchVersion is called by the client when it learns the Negotiated Version of compatible version negotiation,
// i.e. when it receives the first Initial packet with a version that differs from the client's Chosen Version
// (section 4.1 of RFC 9369).
// It must be called before the CRYPTO frames of this packet are handled.
func (h *cryptoSetup) SwitchVersion(v protocol.Version) {
	if h.perspective == protocol.PerspectiveServer {
		panic("cryptoSetup BUG: SwitchVersion called for the server")
	}
	if v == h.version {
		return
	}
	h.switchVersion(v)
	h.candidateVersion = 0
	h.candidateInitialOpener = nil
}

func (h *cryptoSetup) switchVersion(v protocol.Version) {
	if h.handshakeOpener != nil || h.handshakeSealer != nil {
		panic("cryptoSetup BUG: switching version after installing Handshake keys")
	}
	h.logger.Debugf("Switching from QUIC version %s to %s", h.version, v)
	prevOpener := h.initialOpener
	if h.perspective == protocol.PerspectiveServer && h.version == h.chosenVersion {
		// Packets from the client might still use the Chosen Version.
		h.chosenVersionInitialOpener = h.initialOpener
	}
	h.version = v
	// The Handshake and 1-RTT keys are derived using the Negotiated Version.
	h.aead.version = v
	h.installInitialKeys()
	// The packet number space of the Initial packets continues.
	continuePacketNumberSpace(h.initialOpener, prevOpener, h.candidateInitialOpener)
}

func (h *cryptoSetup) SetLargest1RTTAcked(pn protocol.PacketNumber) error {
	return h.aead.SetLargestAcked(pn)
}

// SetLargest1RTTAckedForPath is called when the peer acknowledges 1-RTT packets sent on a path.
func (h *cryptoSetup) SetLargest1RTTAckedForPath(pathID protocol.PathID, pn protocol.PacketNumber, now monotime.Time) error {
	return h.aead.SetLargestAckedForPath(pathID, pn, now)
}

// EnableMultipath enables the multipath extension (draft-ietf-quic-multipath) for the 1-RTT keys.
// It is called after receiving the peer's transport parameters, if both endpoints advertised the
// initial_max_path_id transport parameter. At that point, the cipher suite has been negotiated.
// maxPTO returns the largest PTO among all paths.
func (h *cryptoSetup) EnableMultipath(maxPTO func() time.Duration) error {
	if h.suite.ID == 0 {
		return &qerr.TransportError{
			ErrorCode:    qerr.InternalError,
			ErrorMessage: "cipher suite not negotiated yet",
		}
	}
	// Section 2.1 of draft-ietf-quic-multipath:
	// Cipher suites with a nonce shorter than 12 bytes cannot be used together with the multipath extension.
	if h.suite.IVLen() < minMultipathNonceLength {
		return &qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: fmt.Sprintf("cipher suite %s can't be used with multipath", tls.CipherSuiteName(h.suite.ID)),
		}
	}
	h.aead.EnableMultipath(maxPTO)
	return nil
}

// DropPath drops the 1-RTT packet protection state of a path.
func (h *cryptoSetup) DropPath(pathID protocol.PathID) {
	h.aead.DropPath(pathID)
}

func (h *cryptoSetup) StartHandshake(ctx context.Context) error {
	err := h.conn.Start(context.WithValue(ctx, QUICVersionContextKey, h.version))
	if err != nil {
		return wrapError(err)
	}
	for {
		ev := h.conn.NextEvent()
		if err := h.handleEvent(ev); err != nil {
			return wrapError(err)
		}
		if ev.Kind == tls.QUICNoEvent {
			break
		}
	}
	if h.perspective == protocol.PerspectiveClient {
		if h.zeroRTTSealer != nil && h.zeroRTTParameters != nil {
			h.logger.Debugf("Doing 0-RTT.")
			h.events = append(h.events, Event{Kind: EventRestoredTransportParameters, TransportParameters: h.zeroRTTParameters})
		} else {
			h.logger.Debugf("Not doing 0-RTT. Has sealer: %t, has params: %t", h.zeroRTTSealer != nil, h.zeroRTTParameters != nil)
		}
	}
	return nil
}

// Close closes the crypto setup.
// It aborts the handshake, if it is still running.
func (h *cryptoSetup) Close() error {
	return h.conn.Close()
}

// HandleMessage handles a TLS handshake message.
// It is called by the crypto streams when a new message is available.
func (h *cryptoSetup) HandleMessage(data []byte, encLevel protocol.EncryptionLevel) error {
	if err := h.handleMessage(data, encLevel); err != nil {
		return wrapError(err)
	}
	return nil
}

func (h *cryptoSetup) handleMessage(data []byte, encLevel protocol.EncryptionLevel) error {
	if h.perspective == protocol.PerspectiveServer && encLevel == protocol.EncryptionInitial && !h.parsedClientHello {
		if err := h.negotiateVersionFromClientHello(data); err != nil {
			return err
		}
	}
	if h.perspective == protocol.PerspectiveClient && encLevel == protocol.Encryption1RTT {
		if err := h.checkPostHandshakeMessages(data); err != nil {
			return err
		}
	}
	if err := h.conn.HandleData(encLevel.ToTLSEncryptionLevel(), data); err != nil {
		return err
	}
	for {
		ev := h.conn.NextEvent()
		if err := h.handleEvent(ev); err != nil {
			return err
		}
		if ev.Kind == tls.QUICNoEvent {
			return nil
		}
	}
}

// checkPostHandshakeMessages checks the TLS messages that the server sends after the handshake, before
// crypto/tls processes them. crypto/tls rejects the following messages with other errors than RFC 9001 requires:
//   - a CertificateRequest: post-handshake client authentication is not allowed (section 4.4 of RFC 9001),
//   - a NewSessionTicket with an early_data extension whose max_early_data_size is not 0xffffffff
//     (section 4.6.1 of RFC 9001).
//
// Both are a PROTOCOL_VIOLATION.
func (h *cryptoSetup) checkPostHandshakeMessages(data []byte) error {
	h.postHandshakeData = append(h.postHandshakeData, data...)
	for len(h.postHandshakeData) >= 4 {
		msgLen := 4 + (int(h.postHandshakeData[1])<<16 | int(h.postHandshakeData[2])<<8 | int(h.postHandshakeData[3]))
		if len(h.postHandshakeData) < msgLen {
			return nil
		}
		msg := h.postHandshakeData[:msgLen]
		switch msg[0] {
		case typeCertificateRequest:
			return &qerr.TransportError{
				ErrorCode:    qerr.ProtocolViolation,
				ErrorMessage: "received a post-handshake CertificateRequest",
			}
		case typeNewSessionTicket:
			if size, ok := newSessionTicketMaxEarlyDataSize(msg); ok && size != 0xffffffff {
				return &qerr.TransportError{
					ErrorCode:    qerr.ProtocolViolation,
					ErrorMessage: fmt.Sprintf("invalid max_early_data_size in NewSessionTicket: %d", size),
				}
			}
		}
		h.postHandshakeData = h.postHandshakeData[msgLen:]
	}
	if len(h.postHandshakeData) == 0 {
		h.postHandshakeData = nil
	}
	return nil
}

func (h *cryptoSetup) handleEvent(ev tls.QUICEvent) (err error) {
	switch ev.Kind {
	case tls.QUICNoEvent:
		return nil
	case tls.QUICSetReadSecret:
		h.setReadKey(ev.Level, ev.Suite, ev.Data)
		return nil
	case tls.QUICSetWriteSecret:
		h.setWriteKey(ev.Level, ev.Suite, ev.Data)
		return nil
	case tls.QUICTransportParameters:
		return h.handleTransportParameters(ev.Data)
	case tls.QUICTransportParametersRequired:
		h.conn.SetTransportParameters(h.ourParams.Marshal(h.perspective))
		return nil
	case tls.QUICRejectedEarlyData:
		h.rejected0RTT()
		return nil
	case tls.QUICWriteData:
		h.writeRecord(ev.Level, ev.Data)
		return nil
	case tls.QUICHandshakeDone:
		h.handshakeComplete()
		return nil
	case tls.QUICStoreSession:
		if h.perspective == protocol.PerspectiveServer {
			panic("cryptoSetup BUG: unexpected QUICStoreSession event for the server")
		}
		ev.SessionState.Extra = append(
			ev.SessionState.Extra,
			addSessionStateExtraPrefix(h.marshalDataForSessionState(ev.SessionState.EarlyData)),
		)
		return h.conn.StoreSession(ev.SessionState)
	case tls.QUICResumeSession:
		var allowEarlyData bool
		switch h.perspective {
		case protocol.PerspectiveClient:
			// for clients, this event occurs when a session ticket is selected
			allowEarlyData = h.handleDataFromSessionState(
				findSessionStateExtraData(ev.SessionState.Extra),
				ev.SessionState.EarlyData,
			)
		case protocol.PerspectiveServer:
			// for servers, this event occurs when receiving the client's session ticket
			allowEarlyData = h.handleSessionTicket(
				findSessionStateExtraData(ev.SessionState.Extra),
				ev.SessionState.EarlyData,
			)
		}
		if ev.SessionState.EarlyData {
			ev.SessionState.EarlyData = allowEarlyData
		}
		return nil
	case tls.QUICErrorEvent:
		return ev.Err
	default:
		// Unknown events should be ignored.
		// crypto/tls will ensure that this is safe to do.
		// See the discussion following https://github.com/golang/go/issues/68124#issuecomment-2187042510 for details.
		return nil
	}
}

func (h *cryptoSetup) NextEvent() Event {
	if len(h.events) == 0 {
		return Event{Kind: EventNoEvent}
	}
	ev := h.events[0]
	h.events = h.events[1:]
	return ev
}

func (h *cryptoSetup) handleTransportParameters(data []byte) error {
	var tp wire.TransportParameters
	if err := tp.Unmarshal(data, h.perspective.Opposite()); err != nil {
		return err
	}
	var negotiatedVersion protocol.Version
	switch h.perspective {
	case protocol.PerspectiveServer:
		v, err := h.negotiateVersion(tp.VersionInformation)
		if err != nil {
			return err
		}
		negotiatedVersion = v
	case protocol.PerspectiveClient:
		if err := h.validateVersionInformation(tp.VersionInformation); err != nil {
			return err
		}
	}
	h.peerParams = &tp
	h.events = append(h.events, Event{Kind: EventReceivedTransportParameters, TransportParameters: h.peerParams})
	if negotiatedVersion != 0 && negotiatedVersion != h.version {
		h.switchVersion(negotiatedVersion)
		h.events = append(h.events, Event{Kind: EventVersionNegotiated, Version: negotiatedVersion})
	}
	return nil
}

// must be called after receiving the transport parameters
func (h *cryptoSetup) marshalDataForSessionState(earlyData bool) []byte {
	b := make([]byte, 0, 256)
	b = quicvarint.Append(b, clientSessionStateRevision)
	if earlyData {
		// only save the transport parameters for 0-RTT enabled session tickets
		return h.peerParams.MarshalForSessionTicket(b)
	}
	return b
}

func (h *cryptoSetup) handleDataFromSessionState(data []byte, earlyData bool) (allowEarlyData bool) {
	tp, err := decodeDataFromSessionState(data, earlyData)
	if err != nil {
		h.logger.Debugf("Restoring of transport parameters from session ticket failed: %s", err.Error())
		return
	}
	// The session ticket might have been saved from a connection that allowed 0-RTT,
	// and therefore contain transport parameters.
	// Only use them if 0-RTT is actually used on the new connection.
	if tp != nil && h.allow0RTT {
		h.zeroRTTParameters = tp
		return true
	}
	return false
}

func decodeDataFromSessionState(b []byte, earlyData bool) (*wire.TransportParameters, error) {
	ver, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, err
	}
	b = b[l:]
	if ver != clientSessionStateRevision {
		return nil, fmt.Errorf("mismatching version. Got %d, expected %d", ver, clientSessionStateRevision)
	}
	if !earlyData {
		return nil, nil
	}
	var tp wire.TransportParameters
	if err := tp.UnmarshalFromSessionTicket(b); err != nil {
		return nil, err
	}
	return &tp, nil
}

func (h *cryptoSetup) getDataForSessionTicket() []byte {
	// After compatible version negotiation, the ticket belongs to the Negotiated Version (section 5 of RFC 9369).
	return newSessionTicket(h.version, h.ourParams, time.Now()).Marshal()
}

// GetSessionTicket generates a new session ticket.
// Due to limitations in crypto/tls, it's only possible to generate a single session ticket per connection.
// It is only valid for the server.
func (h *cryptoSetup) GetSessionTicket() ([]byte, error) {
	if err := h.conn.SendSessionTicket(tls.QUICSessionTicketOptions{
		EarlyData: h.allow0RTT,
		Extra:     [][]byte{addSessionStateExtraPrefix(h.getDataForSessionTicket())},
	}); err != nil {
		// Session tickets might be disabled by tls.Config.SessionTicketsDisabled.
		// We can't check h.tlsConfig here, since the actual config might have been obtained from
		// the GetConfigForClient callback.
		// See https://github.com/golang/go/issues/62032.
		// This error assertion can be removed once we drop support for Go 1.25.
		if strings.Contains(err.Error(), "session ticket keys unavailable") {
			return nil, nil
		}
		return nil, err
	}
	// If session tickets are disabled, NextEvent will immediately return QUICNoEvent,
	// and we will return a nil ticket.
	var ticket []byte
	for {
		ev := h.conn.NextEvent()
		if ev.Kind == tls.QUICNoEvent {
			break
		}
		if ev.Kind == tls.QUICWriteData && ev.Level == tls.QUICEncryptionLevelApplication {
			if ticket != nil {
				h.logger.Errorf("unexpected multiple session tickets")
				continue
			}
			ticket = ev.Data
		} else {
			h.logger.Errorf("unexpected event: %v", ev.Kind)
		}
	}
	return ticket, nil
}

// handleSessionTicket is called for the server when receiving the client's session ticket.
// It reads parameters from the session ticket and checks whether to accept 0-RTT if the session ticket enabled 0-RTT.
// Note that the fact that the session ticket allows 0-RTT doesn't mean that the actual TLS handshake enables 0-RTT:
// A client may use a 0-RTT enabled session to resume a TLS session without using 0-RTT.
func (h *cryptoSetup) handleSessionTicket(data []byte, using0RTT bool) (allowEarlyData bool) {
	var t sessionTicket
	if err := t.Unmarshal(data); err != nil {
		h.logger.Debugf("Unmarshalling session ticket failed: %s", err.Error())
		return false
	}
	if !using0RTT {
		return false
	}
	// Session tickets are specific to a QUIC version (section 5 of RFC 9369).
	// Tickets of other versions are usually rejected by the UnwrapSession callback already.
	if t.Version != h.chosenVersion {
		h.logger.Debugf("Session ticket was issued for QUIC version %s. Rejecting 0-RTT.", t.Version)
		return false
	}
	valid := h.ourParams.ValidFor0RTT(t.Parameters)
	if !valid {
		h.logger.Debugf("Transport parameters changed. Rejecting 0-RTT.")
		return false
	}
	if !h.allow0RTT {
		h.logger.Debugf("0-RTT not allowed. Rejecting 0-RTT.")
		return false
	}
	// This needs to be the last check: the ticket can't be used for 0-RTT again.
	if h.useTicketFor0RTT == nil || !h.useTicketFor0RTT(t.ID, t.Issued) {
		h.logger.Debugf("Session ticket can't be used for 0-RTT (already used, or too old). Rejecting 0-RTT.")
		return false
	}
	return true
}

// rejected0RTT is called for the client when the server rejects 0-RTT.
func (h *cryptoSetup) rejected0RTT() {
	h.logger.Debugf("0-RTT was rejected. Dropping 0-RTT keys.")

	had0RTTKeys := h.zeroRTTSealer != nil
	h.zeroRTTSealer = nil

	if had0RTTKeys {
		h.events = append(h.events, Event{Kind: EventDiscard0RTTKeys})
	}
}

func (h *cryptoSetup) setReadKey(el tls.QUICEncryptionLevel, suiteID uint16, trafficSecret []byte) {
	suite := getCipherSuite(suiteID)
	h.suite = suite
	var ev EventKind
	//nolint:exhaustive // The TLS stack doesn't export Initial keys.
	switch el {
	case tls.QUICEncryptionLevelEarly:
		ev = EventReceived0RTTReadKeys
		if h.perspective == protocol.PerspectiveClient {
			panic("Received 0-RTT read key for the client")
		}
		// 0-RTT packets use the client's Chosen Version (section 4.1 of RFC 9369).
		h.zeroRTTOpener = newLongHeaderOpener(
			createAEAD(suite, trafficSecret, h.chosenVersion),
			newHeaderProtector(suite, trafficSecret, true, h.chosenVersion),
		)
		h.used0RTT.Store(true)
		if h.logger.Debug() {
			h.logger.Debugf("Installed 0-RTT Read keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
	case tls.QUICEncryptionLevelHandshake:
		ev = EventReceivedHandshakeReadKeys
		h.handshakeOpener = newLongHeaderOpener(
			createAEAD(suite, trafficSecret, h.version),
			newHeaderProtector(suite, trafficSecret, true, h.version),
		)
		if h.logger.Debug() {
			h.logger.Debugf("Installed Handshake Read keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
	case tls.QUICEncryptionLevelApplication:
		ev = EventReceived1RTTReadKeys
		h.aead.SetReadKey(suite, trafficSecret)
		h.has1RTTOpener = true
		if h.logger.Debug() {
			h.logger.Debugf("Installed 1-RTT Read keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
	default:
		panic("unexpected read encryption level")
	}
	h.events = append(h.events, Event{Kind: ev})
	if h.qlogger != nil {
		h.qlogger.RecordEvent(qlog.KeyUpdated{
			Trigger: qlog.KeyUpdateTLS,
			KeyType: encLevelToKeyType(protocol.FromTLSEncryptionLevel(el), h.perspective.Opposite()),
		})
	}
}

func (h *cryptoSetup) setWriteKey(el tls.QUICEncryptionLevel, suiteID uint16, trafficSecret []byte) {
	suite := getCipherSuite(suiteID)
	h.suite = suite
	//nolint:exhaustive // The TLS stack doesn't export Initial keys.
	switch el {
	case tls.QUICEncryptionLevelEarly:
		if h.perspective == protocol.PerspectiveServer {
			panic("Received 0-RTT write key for the server")
		}
		// 0-RTT packets use the client's Chosen Version (section 4.1 of RFC 9369).
		h.zeroRTTSealer = newLongHeaderSealer(
			createAEAD(suite, trafficSecret, h.chosenVersion),
			newHeaderProtector(suite, trafficSecret, true, h.chosenVersion),
		)
		if h.logger.Debug() {
			h.logger.Debugf("Installed 0-RTT Write keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
		if h.qlogger != nil {
			h.qlogger.RecordEvent(qlog.KeyUpdated{
				Trigger: qlog.KeyUpdateTLS,
				KeyType: encLevelToKeyType(protocol.Encryption0RTT, h.perspective),
			})
		}
		// don't set used0RTT here. 0-RTT might still get rejected.
		return
	case tls.QUICEncryptionLevelHandshake:
		h.handshakeSealer = newLongHeaderSealer(
			createAEAD(suite, trafficSecret, h.version),
			newHeaderProtector(suite, trafficSecret, true, h.version),
		)
		if h.logger.Debug() {
			h.logger.Debugf("Installed Handshake Write keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
	case tls.QUICEncryptionLevelApplication:
		h.aead.SetWriteKey(suite, trafficSecret)
		h.has1RTTSealer = true
		if h.logger.Debug() {
			h.logger.Debugf("Installed 1-RTT Write keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
		if h.zeroRTTSealer != nil {
			// Once we receive handshake keys, we know that 0-RTT was not rejected.
			h.used0RTT.Store(true)
			h.zeroRTTSealer = nil
			h.logger.Debugf("Dropping 0-RTT keys.")
			if h.qlogger != nil {
				h.qlogger.RecordEvent(qlog.KeyDiscarded{KeyType: qlog.KeyTypeClient0RTT})
			}
		}
	default:
		panic("unexpected write encryption level")
	}
	if h.qlogger != nil {
		h.qlogger.RecordEvent(qlog.KeyUpdated{
			Trigger: qlog.KeyUpdateTLS,
			KeyType: encLevelToKeyType(protocol.FromTLSEncryptionLevel(el), h.perspective),
		})
	}
}

// writeRecord is called when TLS writes data
func (h *cryptoSetup) writeRecord(encLevel tls.QUICEncryptionLevel, p []byte) {
	//nolint:exhaustive // handshake records can only be written for Initial and Handshake.
	switch encLevel {
	case tls.QUICEncryptionLevelInitial:
		h.wroteInitialData = true
		h.events = append(h.events, Event{Kind: EventWriteInitialData, Data: p})
	case tls.QUICEncryptionLevelHandshake:
		h.events = append(h.events, Event{Kind: EventWriteHandshakeData, Data: p})
	case tls.QUICEncryptionLevelApplication:
		panic("unexpected write")
	default:
		panic(fmt.Sprintf("unexpected write encryption level: %s", encLevel))
	}
}

func (h *cryptoSetup) DiscardInitialKeys() {
	dropped := h.initialOpener != nil
	h.initialOpener = nil
	h.initialSealer = nil
	h.chosenVersionInitialOpener = nil
	h.candidateVersion = 0
	h.candidateInitialOpener = nil
	if dropped {
		h.logger.Debugf("Dropping Initial keys.")
		if h.qlogger != nil {
			h.qlogger.RecordEvent(qlog.KeyDiscarded{KeyType: qlog.KeyTypeClientInitial})
			h.qlogger.RecordEvent(qlog.KeyDiscarded{KeyType: qlog.KeyTypeServerInitial})
		}
	}
}

func (h *cryptoSetup) handshakeComplete() {
	h.handshakeCompleteTime = time.Now()
	h.events = append(h.events, Event{Kind: EventHandshakeComplete})
}

func (h *cryptoSetup) SetHandshakeConfirmed() {
	h.aead.SetHandshakeConfirmed()
	// drop Handshake keys
	var dropped bool
	if h.handshakeOpener != nil {
		h.handshakeOpener = nil
		h.handshakeSealer = nil
		dropped = true
	}
	if dropped {
		h.logger.Debugf("Dropping Handshake keys.")
		if h.qlogger != nil {
			h.qlogger.RecordEvent(qlog.KeyDiscarded{KeyType: qlog.KeyTypeClientHandshake})
			h.qlogger.RecordEvent(qlog.KeyDiscarded{KeyType: qlog.KeyTypeServerHandshake})
		}
	}
}

func (h *cryptoSetup) GetInitialSealer() (LongHeaderSealer, error) {
	if h.initialSealer == nil {
		return nil, ErrKeysDropped
	}
	return h.initialSealer, nil
}

func (h *cryptoSetup) Get0RTTSealer() (LongHeaderSealer, error) {
	if h.zeroRTTSealer == nil {
		return nil, ErrKeysDropped
	}
	return h.zeroRTTSealer, nil
}

func (h *cryptoSetup) GetHandshakeSealer() (LongHeaderSealer, error) {
	if h.handshakeSealer == nil {
		if h.initialSealer == nil {
			return nil, ErrKeysDropped
		}
		return nil, ErrKeysNotYetAvailable
	}
	return h.handshakeSealer, nil
}

func (h *cryptoSetup) Get1RTTSealer() (ShortHeaderSealer, error) {
	if !h.has1RTTSealer {
		return nil, ErrKeysNotYetAvailable
	}
	if h.aead.ConfidentialityLimitReached() {
		return nil, ErrConfidentialityLimitReached
	}
	return h.aead, nil
}

// GetInitialOpener returns the opener for Initial packets of version v.
func (h *cryptoSetup) GetInitialOpener(v protocol.Version) (LongHeaderOpener, error) {
	if h.initialOpener == nil {
		return nil, ErrKeysDropped
	}
	if v == h.version {
		return h.initialOpener, nil
	}
	switch h.perspective {
	case protocol.PerspectiveServer:
		// The client might send Initial packets using its Chosen Version
		// until it learns the Negotiated Version (section 4.1 of RFC 9369).
		if v == h.chosenVersion && h.chosenVersionInitialOpener != nil {
			return h.chosenVersionInitialOpener, nil
		}
	case protocol.PerspectiveClient:
		// The client learns the Negotiated Version by observing the first long header Version field
		// that differs from its Chosen Version (section 4.1 of RFC 9369).
		// This is only possible before the Handshake keys are installed.
		if h.handshakeOpener == nil && h.version == h.chosenVersion && protocol.IsCompatibleVersion(h.version, v) {
			if h.candidateVersion != v {
				_, opener := NewInitialAEAD(h.initialConnID, h.perspective, v)
				continuePacketNumberSpace(opener, h.initialOpener)
				h.candidateVersion = v
				h.candidateInitialOpener = opener
			}
			return h.candidateInitialOpener, nil
		}
	}
	return nil, ErrUnexpectedVersion
}

func (h *cryptoSetup) Get0RTTOpener() (LongHeaderOpener, error) {
	if h.zeroRTTOpener == nil {
		if h.initialOpener != nil {
			return nil, ErrKeysNotYetAvailable
		}
		// if the initial opener is also not available, the keys were already dropped
		return nil, ErrKeysDropped
	}
	return h.zeroRTTOpener, nil
}

func (h *cryptoSetup) GetHandshakeOpener() (LongHeaderOpener, error) {
	if h.handshakeOpener == nil {
		if h.initialOpener != nil {
			return nil, ErrKeysNotYetAvailable
		}
		// if the initial opener is also not available, the keys were already dropped
		return nil, ErrKeysDropped
	}
	return h.handshakeOpener, nil
}

func (h *cryptoSetup) Get1RTTOpener() (ShortHeaderOpener, error) {
	if h.zeroRTTOpener != nil && time.Since(h.handshakeCompleteTime) > 3*h.rttStats.PTO(true) {
		h.zeroRTTOpener = nil
		h.logger.Debugf("Dropping 0-RTT keys.")
		if h.qlogger != nil {
			h.qlogger.RecordEvent(qlog.KeyDiscarded{KeyType: qlog.KeyTypeClient0RTT})
		}
	}

	if !h.has1RTTOpener {
		return nil, ErrKeysNotYetAvailable
	}
	return h.aead, nil
}

func (h *cryptoSetup) ConnectionState() ConnectionState {
	return ConnectionState{
		ConnectionState: h.conn.ConnectionState(),
		Used0RTT:        h.used0RTT.Load(),
	}
}

func wrapError(err error) error {
	if alertErr, ok := errors.AsType[tls.AlertError](err); ok {
		return qerr.NewLocalCryptoError(uint8(alertErr), err)
	}
	// errors returned when processing the transport parameters, e.g. a TRANSPORT_PARAMETER_ERROR
	if transportErr, ok := errors.AsType[*qerr.TransportError](err); ok {
		return transportErr
	}
	return &qerr.TransportError{ErrorCode: qerr.InternalError, ErrorMessage: err.Error()}
}

func encLevelToKeyType(encLevel protocol.EncryptionLevel, pers protocol.Perspective) qlog.KeyType {
	if pers == protocol.PerspectiveServer {
		switch encLevel {
		case protocol.EncryptionInitial:
			return qlog.KeyTypeServerInitial
		case protocol.EncryptionHandshake:
			return qlog.KeyTypeServerHandshake
		case protocol.Encryption0RTT:
			return qlog.KeyTypeServer0RTT
		case protocol.Encryption1RTT:
			return qlog.KeyTypeServer1RTT
		default:
			return ""
		}
	}
	switch encLevel {
	case protocol.EncryptionInitial:
		return qlog.KeyTypeClientInitial
	case protocol.EncryptionHandshake:
		return qlog.KeyTypeClientHandshake
	case protocol.Encryption0RTT:
		return qlog.KeyTypeClient0RTT
	case protocol.Encryption1RTT:
		return qlog.KeyTypeClient1RTT
	default:
		return ""
	}
}
