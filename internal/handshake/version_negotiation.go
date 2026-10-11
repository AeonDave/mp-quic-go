package handshake

import (
	"fmt"
	"slices"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/internal/wire"

	"golang.org/x/crypto/cryptobyte"
)

// TLS handshake message types and extensions (RFC 8446) that are parsed outside of crypto/tls.
const (
	typeClientHello        = 1
	typeNewSessionTicket   = 4
	typeCertificateRequest = 13

	extensionEarlyData = 42
	// the TLS extension carrying the QUIC transport parameters (section 8.2 of RFC 9001)
	quicTransportParametersExtension = 0x39
)

func versionNegotiationError(format string, a ...any) error {
	return &qerr.TransportError{
		ErrorCode:    qerr.VersionNegotiationErrorCode,
		ErrorMessage: fmt.Sprintf(format, a...),
	}
}

// negotiateVersion is called by the server when it receives the client's Version Information.
// It validates the Version Information, and selects the Negotiated Version (sections 2.3 and 4 of RFC 9368).
// The Version Information sent to the client is updated accordingly.
func (h *cryptoSetup) negotiateVersion(vi *wire.VersionInformation) (protocol.Version, error) {
	// Servers may complete the handshake if the Version Information is missing.
	if vi == nil {
		return h.version, nil
	}
	// The client's Chosen Version must match the version of the client's first flight.
	if vi.ChosenVersion != h.chosenVersion {
		return 0, versionNegotiationError("client's Chosen Version (%s) doesn't match the version in use (%s)", vi.ChosenVersion, h.chosenVersion)
	}
	// The version was already selected using the first ClientHello, before a HelloRetryRequest.
	// The second ClientHello must carry the same Version Information.
	if h.negotiatedVersionInfo != nil {
		if !slices.Equal(vi.AvailableVersions, h.negotiatedVersionInfo.AvailableVersions) {
			return 0, versionNegotiationError("client's Version Information changed after the HelloRetryRequest")
		}
		return h.version, nil
	}
	// Only switch the version if the client can learn the Negotiated Version from our Version Information.
	if len(h.versions) == 0 || h.ourParams.VersionInformation == nil {
		return h.version, nil
	}
	// The version is usually selected using the first ClientHello (see negotiateVersionFromClientHello).
	// If that wasn't possible, and the server sent a HelloRetryRequest, it already sent CRYPTO frames
	// using the client's Chosen Version. The client takes this as the Negotiated Version (section 4.1 of RFC 9369).
	if h.wroteInitialData {
		return h.version, nil
	}
	h.negotiatedVersionInfo = vi
	v := protocol.ChooseCompatibleVersion(h.versions, vi.ChosenVersion, vi.AvailableVersions)
	if v != h.version {
		params := *h.ourParams
		params.VersionInformation = &wire.VersionInformation{
			ChosenVersion:     v,
			AvailableVersions: h.ourParams.VersionInformation.AvailableVersions,
		}
		h.ourParams = &params
	}
	return v, nil
}

// negotiateVersionFromClientHello is called by the server for the CRYPTO data received in Initial packets,
// before the data is passed to crypto/tls, until the first ClientHello was received completely.
// If crypto/tls sends a HelloRetryRequest, it only provides the client's transport parameters after
// receiving the second ClientHello. Since the HelloRetryRequest is sent using the Negotiated Version
// (section 4.1 of RFC 9369), the Negotiated Version is selected using the Version Information of the
// first ClientHello.
func (h *cryptoSetup) negotiateVersionFromClientHello(data []byte) error {
	h.clientHello = append(h.clientHello, data...)
	if len(h.clientHello) < 4 {
		return nil
	}
	msgLen := 4 + (int(h.clientHello[1])<<16 | int(h.clientHello[2])<<8 | int(h.clientHello[3]))
	if len(h.clientHello) < msgLen {
		return nil
	}
	msg := h.clientHello[:msgLen]
	h.clientHello = nil
	h.parsedClientHello = true

	// If the ClientHello or the transport parameters are invalid, the error is reported
	// when crypto/tls processes the ClientHello.
	sessionID, b, ok := parseClientHello(msg)
	if !ok {
		return nil
	}
	// QUIC doesn't use the TLS middlebox compatibility mode (section 8.4 of RFC 9001).
	if len(sessionID) > 0 {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "ClientHello with a legacy_session_id",
		}
	}
	// Only a server configured with its preferred versions switches versions.
	if b == nil || len(h.versions) == 0 || h.ourParams.VersionInformation == nil {
		return nil
	}
	var tp wire.TransportParameters
	if err := tp.Unmarshal(b, protocol.PerspectiveClient); err != nil {
		return nil
	}
	v, err := h.negotiateVersion(tp.VersionInformation)
	if err != nil {
		return err
	}
	if v != h.version {
		h.switchVersion(v)
		h.events = append(h.events, Event{Kind: EventVersionNegotiated, Version: v})
	}
	return nil
}

// clientHelloTransportParameters returns the quic_transport_parameters extension of a ClientHello message
// (section 4.1.2 of RFC 8446).
func clientHelloTransportParameters(msg []byte) ([]byte, bool) {
	_, tp, ok := parseClientHello(msg)
	return tp, ok && tp != nil
}

// parseClientHello returns the legacy_session_id and the quic_transport_parameters extension of a ClientHello
// message (section 4.1.2 of RFC 8446). The transport parameters are nil if the extension is missing.
func parseClientHello(msg []byte) (sessionID, transportParameters []byte, ok bool) {
	s := cryptobyte.String(msg)
	var msgType uint8
	var body cryptobyte.String
	if !s.ReadUint8(&msgType) || msgType != typeClientHello || !s.ReadUint24LengthPrefixed(&body) {
		return nil, nil, false
	}
	var legacyVersion uint16
	var random []byte
	var session, cipherSuites, compressionMethods, extensions cryptobyte.String
	if !body.ReadUint16(&legacyVersion) ||
		!body.ReadBytes(&random, 32) ||
		!body.ReadUint8LengthPrefixed(&session) ||
		!body.ReadUint16LengthPrefixed(&cipherSuites) ||
		!body.ReadUint8LengthPrefixed(&compressionMethods) ||
		!body.ReadUint16LengthPrefixed(&extensions) {
		return nil, nil, false
	}
	for !extensions.Empty() {
		var typ uint16
		var data cryptobyte.String
		if !extensions.ReadUint16(&typ) || !extensions.ReadUint16LengthPrefixed(&data) {
			return nil, nil, false
		}
		if typ == quicTransportParametersExtension {
			return session, append([]byte{}, data...), true
		}
	}
	return session, nil, true
}

// newSessionTicketMaxEarlyDataSize returns the max_early_data_size of the early_data extension of a
// NewSessionTicket message (section 4.6.1 of RFC 8446). It returns false if the message doesn't contain the
// extension, or can't be parsed. crypto/tls reports parsing errors.
func newSessionTicketMaxEarlyDataSize(msg []byte) (uint32, bool) {
	s := cryptobyte.String(msg)
	var msgType uint8
	var body cryptobyte.String
	if !s.ReadUint8(&msgType) || msgType != typeNewSessionTicket || !s.ReadUint24LengthPrefixed(&body) {
		return 0, false
	}
	var lifetime, ageAdd uint32
	var nonce, ticket, extensions cryptobyte.String
	if !body.ReadUint32(&lifetime) ||
		!body.ReadUint32(&ageAdd) ||
		!body.ReadUint8LengthPrefixed(&nonce) ||
		!body.ReadUint16LengthPrefixed(&ticket) ||
		!body.ReadUint16LengthPrefixed(&extensions) {
		return 0, false
	}
	for !extensions.Empty() {
		var typ uint16
		var data cryptobyte.String
		if !extensions.ReadUint16(&typ) || !extensions.ReadUint16LengthPrefixed(&data) {
			return 0, false
		}
		if typ == extensionEarlyData {
			var size uint32
			if !data.ReadUint32(&size) || !data.Empty() {
				return 0, false
			}
			return size, true
		}
	}
	return 0, false
}

// validateVersionInformation is called by the client when it receives the server's transport parameters.
// It implements the version downgrade prevention of section 4 of RFC 9368.
func (h *cryptoSetup) validateVersionInformation(vi *wire.VersionInformation) error {
	if vi == nil {
		// The server can't have switched to a different version without sending its Version Information.
		if h.version != h.chosenVersion {
			return versionNegotiationError("missing version_information after switching to %s", h.version)
		}
		if !h.reactedToVersionNegotiation {
			return nil
		}
		// Section 8 of RFC 9368: Special handling for QUIC version 1.
		if h.version != protocol.Version1 {
			return versionNegotiationError("missing version_information after Version Negotiation")
		}
		vi = &wire.VersionInformation{
			ChosenVersion:     protocol.Version1,
			AvailableVersions: []protocol.Version{protocol.Version1},
		}
	}

	offered := []protocol.Version{h.chosenVersion}
	if h.ourParams.VersionInformation != nil {
		offered = h.ourParams.VersionInformation.AvailableVersions
	}
	if !slices.Contains(offered, vi.ChosenVersion) {
		return versionNegotiationError("server's Chosen Version (%s) wasn't offered (%s)", vi.ChosenVersion, offered)
	}
	// The client learned the Negotiated Version from the long header Version field.
	if vi.ChosenVersion != h.version {
		return versionNegotiationError("server's Chosen Version (%s) doesn't match the Negotiated Version (%s)", vi.ChosenVersion, h.version)
	}
	if !h.reactedToVersionNegotiation {
		return nil
	}
	// We would have attempted the same version if the Version Negotiation packet had listed
	// the server's Available Versions and the Negotiated Version.
	if len(vi.AvailableVersions) == 0 {
		return versionNegotiationError("empty Available Versions after Version Negotiation")
	}
	versions := append(slices.Clone(vi.AvailableVersions), vi.ChosenVersion)
	if v, ok := protocol.ChooseSupportedVersion(h.versions, versions); !ok || v != h.chosenVersion {
		return versionNegotiationError("version downgrade detected: attempted %s, server supports %s", h.chosenVersion, vi.AvailableVersions)
	}
	return nil
}
