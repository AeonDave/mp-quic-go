package quic

import (
	"fmt"
	"slices"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/wire"
	"github.com/AeonDave/mp-quic-go/qlog"
)

// acceptsVersion says if a long header packet is processed, based on its version.
// Packets using a version other than the version in use are only processed during compatible version
// negotiation (RFC 9368).
func (c *Conn) acceptsVersion(hdr *wire.Header) bool {
	// 0-RTT packets always use the client's Chosen Version (section 4.1 of RFC 9369).
	if hdr.Type == protocol.PacketType0RTT {
		return hdr.Version == c.chosenVersion
	}
	if hdr.Version == c.version {
		return true
	}
	switch c.perspective {
	case protocol.PerspectiveServer:
		// After switching to a different version, the client might still send Initial packets using its Chosen Version,
		// until it learns the Negotiated Version. Handshake and 1-RTT packets must use the Negotiated Version.
		return hdr.Type == protocol.PacketTypeInitial && hdr.Version == c.chosenVersion
	case protocol.PerspectiveClient:
		// The client learns the Negotiated Version by observing the first long header Version field that differs from the
		// Chosen Version. The server sends Retry packets using the Chosen Version (section 4.1 of RFC 9369).
		return !c.knowsNegotiatedVersion && hdr.Type == protocol.PacketTypeInitial && slices.Contains(c.compatibleVersions, hdr.Version)
	default:
		return false
	}
}

// switchVersion is called by the client when it learns the Negotiated Version from the first Initial packet
// using a version different from the Chosen Version.
func (c *Conn) switchVersion(v protocol.Version) {
	c.knowsNegotiatedVersion = true
	c.cryptoStreamHandler.SwitchVersion(v)
	c.setVersion(v)
}

// setVersion sets the version in use for the connection, after compatible version negotiation.
func (c *Conn) setVersion(v protocol.Version) {
	c.logger.Infof("Switching to QUIC version %s (compatible version negotiation).", v)
	c.version = v
	c.connStateMutex.Lock()
	c.connState.Version = v
	c.connStateMutex.Unlock()
	// If the client switches when receiving the first packet, the version is logged when handling that packet,
	// unless this connection was started in response to a Version Negotiation packet.
	if c.qlogger != nil && (c.receivedFirstPacket || c.versionNegotiated) {
		var clientVersions, serverVersions []Version
		switch c.perspective {
		case protocol.PerspectiveClient:
			clientVersions = c.config.Versions
		case protocol.PerspectiveServer:
			serverVersions = c.config.Versions
		}
		c.qlogger.RecordEvent(qlog.VersionInformation{
			ChosenVersion:  v,
			ClientVersions: clientVersions,
			ServerVersions: serverVersions,
		})
	}
}

// versionedTokenStoreKey returns the key used for the TokenStore.
// Tokens are specific to the QUIC version of the connection that received them (section 5 of RFC 9369).
// The key for QUIC version 1 is the server name (or address), as before tokens were scoped to versions.
func versionedTokenStoreKey(key string, v protocol.Version) string {
	if v == protocol.Version1 {
		return key
	}
	return fmt.Sprintf("%s|quic-version=%#x", key, uint32(v))
}
