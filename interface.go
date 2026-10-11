package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/handshake"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/qlogwriter"
)

// The StreamID is the ID of a QUIC stream.
type StreamID = protocol.StreamID

// A Version is a QUIC version number.
type Version = protocol.Version

const (
	// Version1 is RFC 9000
	Version1 = protocol.Version1
	// Version2 is RFC 9369
	Version2 = protocol.Version2
)

// SupportedVersions returns the support versions, sorted in descending order of preference.
func SupportedVersions() []Version {
	// clone the slice to prevent the caller from modifying the slice
	return slices.Clone(protocol.SupportedVersions)
}

// PathID identifies a network path.
type PathID = protocol.PathID

// InvalidPathID represents an unspecified path.
const InvalidPathID PathID = protocol.InvalidPathID

// PacketNumber is a QUIC packet number.
type PacketNumber = protocol.PacketNumber

// ByteCount is a QUIC byte count.
type ByteCount = protocol.ByteCount

// EncryptionLevel is the QUIC encryption level.
type EncryptionLevel = protocol.EncryptionLevel

// PathInfo describes a path used for sending.
type PathInfo struct {
	// ID is the path ID. Both endpoints use the same path ID for a path.
	ID         PathID
	LocalAddr  net.Addr
	RemoteAddr net.Addr
	IfIndex    int

	// State, Status and PeerStatus are only set for paths of IETF Multipath QUIC.
	State PathState
	// Status is the status set using [Path.SetStatus] or [Conn.SetPathStatus].
	Status PathStatus
	// PeerStatus is the status that the peer signaled for the path.
	PeerStatus PathStatus
	// ObservedAddr is the address that the peer observed for this endpoint on the path, using QUIC Address Discovery
	// (see Config.RequestObservedAddress). It is the zero value if the peer didn't report an address for the path.
	ObservedAddr netip.AddrPort
}

// isBackup says if the application or the peer marked the path as a backup path.
func (p *PathInfo) isBackup() bool {
	return p.Status == PathStatusBackup || p.PeerStatus == PathStatusBackup
}

// PathState is the state of a path of IETF Multipath QUIC.
type PathState uint8

const (
	// PathStateValidating means that the path is being validated (section 3.1 of draft-ietf-quic-multipath-21).
	// Only the frames needed to validate the path and acknowledgments are sent on it.
	PathStateValidating PathState = iota
	// PathStateActive means that the path was validated. It can be used for sending.
	PathStateActive
	// PathStateAbandoned means that the path was abandoned (section 3.4 of draft-ietf-quic-multipath-21).
	// No packets are sent on it anymore. Its state is kept for a while, since packets might still arrive on it.
	PathStateAbandoned
)

func (s PathState) String() string {
	switch s {
	case PathStateValidating:
		return "validating"
	case PathStateActive:
		return "active"
	case PathStateAbandoned:
		return "abandoned"
	default:
		return fmt.Sprintf("PathState(%d)", uint8(s))
	}
}

// PathStatus is the status of a path of IETF Multipath QUIC,
// see section 3.3 of draft-ietf-quic-multipath-21.
type PathStatus uint8

const (
	// PathStatusUnknown means that no status was set for the path.
	// The path is used like an available path.
	PathStatusUnknown PathStatus = iota
	// PathStatusAvailable means that the path can be used for sending.
	PathStatusAvailable
	// PathStatusBackup means that the path should only be used for sending if no available path can be used.
	PathStatusBackup
)

func (s PathStatus) String() string {
	switch s {
	case PathStatusUnknown:
		return "unknown"
	case PathStatusAvailable:
		return "available"
	case PathStatusBackup:
		return "backup"
	default:
		return fmt.Sprintf("PathStatus(%d)", uint8(s))
	}
}

// PathSelectionContext provides context for path selection.
type PathSelectionContext struct {
	Now               time.Time
	AckOnly           bool
	HasRetransmission bool
	BytesInFlight     ByteCount
	// PathCongestion returns the congestion window and the bytes in flight of a path.
	// ok is false if no packet was sent on the path yet.
	// A path whose congestion window is full should only be used for ACK-only packets and retransmissions.
	// It is nil if the information is not available.
	PathCongestion func(PathID) (congestionWindow, bytesInFlight ByteCount, ok bool)
	// Paths are the paths that the packet can be sent on, in ascending order of their path IDs:
	// the active paths that can send a packet now, i.e. that are neither congestion nor pacing limited.
	// Backup paths are only included if no other active path can be used (section 3.3 of
	// draft-ietf-quic-multipath-21), and paths that potentially failed only if no other active path is left.
	// If SelectPath returns a path that is not one of them, the connection selects the path itself.
	// The slice must not be retained after SelectPath returns.
	Paths []PathInfo
}

// AdvertisedAddress is an address that the peer advertised using the address advertisement extension
// (see Config.EnableAddressAdvertisement).
type AdvertisedAddress struct {
	// ID is the address ID chosen by the peer.
	// If the peer advertises another address for the same ID, it replaces the previous address.
	ID uint64
	// Addr is the address.
	Addr netip.AddrPort
}

// MultipathAddressObserver is an optional interface of a MultipathController.
// OnAddressAdvertised is called when the peer advertised a new address using the address advertisement extension
// (see Config.EnableAddressAdvertisement), or a new address for an address ID it advertised before.
// It is called from the connection's run loop, and must not block.
type MultipathAddressObserver interface {
	OnAddressAdvertised(AdvertisedAddress)
}

// MultipathController selects the paths of IETF Multipath QUIC that packets are sent on.
// Configuring a controller enables IETF Multipath QUIC (draft-ietf-quic-multipath-21).
//
// The connection opens, validates and closes the paths: the path of a received packet is identified by its
// connection ID. The connection calls SelectPath for every packet carrying data, passing the paths that can be used
// in the PathSelectionContext, and it informs the controller about the paths using the optional methods
// EnableMultipath, RegisterPath (when a path becomes active), ValidatePath, RemovePath (when a path is abandoned),
// UpdatePathState, OnPacketSent, OnPacketAcked and OnPacketLost (or the methods of [MultipathObserver]).
type MultipathController interface {
	SelectPath(PathSelectionContext) (PathInfo, bool)
}

// ReinjectionTargetContext provides context for selecting a reinjection target.
type ReinjectionTargetContext struct {
	Now            time.Time
	OriginalPathID PathID
	Candidates     []PathInfo
	Packet         *PacketReinjectionInfo
}

// MultipathReinjectionTargetSelector allows overriding reinjection target selection.
// Implement this on your MultipathController to customize reinjection path choice.
type MultipathReinjectionTargetSelector interface {
	SelectReinjectionTarget(ReinjectionTargetContext) (PathID, bool)
}

// MultipathScheduler provides advanced path scheduling capabilities.
// This is an optional extension to MultipathController.
type MultipathScheduler interface {
	MultipathController
	// GetScheduler returns the underlying PathScheduler if available.
	GetScheduler() PathScheduler
}

// MultipathObserver receives per-packet events with path information.
type MultipathObserver interface {
	OnPacketSent(PathEvent)
	OnPacketAcked(PathEvent)
	OnPacketLost(PathEvent)
}

// PathEvent reports a packet lifecycle event for a specific path.
type PathEvent struct {
	PathID          PathID
	PacketNumber    PacketNumber
	PacketSize      ByteCount
	EncryptionLevel EncryptionLevel
	AckEliciting    bool
	IsPathProbe     bool
	IsPathMTUProbe  bool
	IsDuplicate     bool // True if the packet duplicates frames sent on another path
	SentAt          time.Time
	EventAt         time.Time
	SmoothedRTT     time.Duration
	RTTVar          time.Duration
	// CongestionWindow and BytesInFlight of the path, if known
	CongestionWindow ByteCount
	BytesInFlight    ByteCount
}

// ExtensionFrameHandler allows parsing of custom frame types.
type ExtensionFrameHandler interface {
	HandleFrame(ctx ExtensionFrameContext) (int, error)
}

// ExtensionFrameContext provides context for a custom frame.
type ExtensionFrameContext struct {
	FrameType       uint64
	EncryptionLevel EncryptionLevel
	Version         Version
	Data            []byte // frame payload without the type varint
}

// MultipathCongestionControl is the congestion control algorithm used on multipath connections.
type MultipathCongestionControl uint8

const (
	// MultipathCongestionControlReno is the default: every path has its own congestion controller, the Reno
	// controller that quic-go uses for single-path connections (slow start, an increase of one datagram per window
	// in congestion avoidance, a multiplicative decrease of 0.7 as in CUBIC, and pacing).
	// The controllers are not coupled (section 5.3 of draft-ietf-quic-multipath-21).
	MultipathCongestionControlReno MultipathCongestionControl = iota
	// MultipathCongestionControlOLIA uses the coupled OLIA congestion controller.
	// Every path has its own controller, coupled to the controllers of the other paths,
	// and these controllers limit the sending rate.
	// The OLIA controller of path 0 takes over when the handshake completes,
	// continuing with the congestion window and the recovery state of the NewReno controller used until then.
	MultipathCongestionControlOLIA
)

// RawFrame represents a custom frame payload with optional callbacks.
type RawFrame struct {
	FrameType        uint64
	Data             []byte // payload without the frame type varint
	NonAckEliciting  bool
	RetransmitOnLoss bool
	OnAcked          func()
	OnLost           func()
}

// A ClientToken is a token received by the client.
// It can be used to skip address validation on future connection attempts.
type ClientToken struct {
	data []byte
	rtt  time.Duration
}

type TokenStore interface {
	// Pop searches for a ClientToken associated with the given key.
	// Since tokens are not supposed to be reused, it must remove the token from the cache.
	// It returns nil when no token is found.
	Pop(key string) (token *ClientToken)

	// Put adds a token to the cache with the given key. It might get called
	// multiple times in a connection.
	Put(key string, token *ClientToken)
}

// Err0RTTRejected can be returned by methods such as:
//   - [Conn.OpenStream], [Conn.OpenStreamSync], [Conn.OpenUniStream], and [Conn.OpenUniStreamSync]
//   - [Conn.AcceptStream] and [Conn.AcceptUniStream]
//   - [Stream.Read] and [Stream.Write]
//
// when the server rejects a 0-RTT connection attempt.
var Err0RTTRejected = errors.New("0-RTT rejected")

// ErrWouldBlock is returned by [SendStream.TryWriteAll] if the entire slice can't be queued immediately.
var ErrWouldBlock = errors.New("operation would block")

// ErrWriteLimitReached is returned by [SendStream.WriteWithLimit] when its limiter prevents accepting the entire slice.
var ErrWriteLimitReached = errors.New("write limit reached")

// QUICVersionContextKey can be used to find out the QUIC version of a TLS handshake from the
// context returned by [tls.ClientHelloInfo.Context].
var QUICVersionContextKey = handshake.QUICVersionContextKey

// StatelessResetKey is a key used to derive stateless reset tokens.
type StatelessResetKey [32]byte

// TokenGeneratorKey is a key used to encrypt session resumption tokens.
type TokenGeneratorKey = handshake.TokenProtectorKey

// A ConnectionID is a QUIC Connection ID, as defined in RFC 9000.
// It is not able to handle QUIC Connection IDs longer than 20 bytes,
// as they are allowed by RFC 8999.
type ConnectionID = protocol.ConnectionID

// ConnectionIDFromBytes interprets b as a [ConnectionID]. It panics if b is
// longer than 20 bytes.
func ConnectionIDFromBytes(b []byte) ConnectionID {
	return protocol.ParseConnectionID(b)
}

// A ConnectionIDGenerator allows the application to take control over the generation of Connection IDs.
// Connection IDs generated by an implementation must be of constant length.
type ConnectionIDGenerator interface {
	// GenerateConnectionID generates a new Connection ID.
	// Generated Connection IDs must be unique and observers should not be able to correlate two Connection IDs.
	// A connection must never issue the same connection ID twice (section 5.1 of RFC 9000), so the generator must
	// never return a connection ID that it returned before.
	GenerateConnectionID() (ConnectionID, error)

	// ConnectionIDLen returns the length of Connection IDs generated by this implementation.
	// Implementations must return constant-length Connection IDs with lengths between 0 and 20 bytes.
	// A length of 0 can only be used when an endpoint doesn't need to multiplex connections during migration.
	ConnectionIDLen() int
}

// Config contains all configuration data needed for a QUIC server or client.
type Config struct {
	// GetConfigForClient is called for incoming connections.
	// If the error is not nil, the connection attempt is refused.
	GetConfigForClient func(info *ClientInfo) (*Config, error)
	// The QUIC versions that can be negotiated, sorted by preference (descending).
	// If not set, it uses all versions available.
	// A client uses the first version for its first flight (unless InitialVersion is set), and offers the versions
	// that this first flight is compatible with (QUIC version 1 and 2 are compatible with each other) for compatible
	// version negotiation (RFC 9368), sorted by preference.
	// A server only switches to a different compatible version if Versions is set: it then selects the first
	// version that the client offered. Otherwise, the server uses the version of the client's first flight.
	Versions []Version
	// InitialVersion is the QUIC version that a client uses for its first flight. It must be one of Versions.
	// If not set, the first version of Versions is used.
	// It allows a client to start with a version that most servers support, while preferring another compatible
	// version: with Versions set to QUIC version 2 and 1, and InitialVersion set to QUIC version 1, the client
	// starts with version 1, and asks the server to switch to version 2 (section 3 of RFC 9368).
	// Servers don't use it.
	InitialVersion Version
	// HandshakeIdleTimeout is the idle timeout before completion of the handshake.
	// If we don't receive any packet from the peer within this time, the connection attempt is aborted.
	// Additionally, if the handshake doesn't complete in twice this time, the connection attempt is also aborted.
	// If this value is zero, the timeout is set to 5 seconds.
	HandshakeIdleTimeout time.Duration
	// MaxIdleTimeout is the maximum duration that may pass without any incoming network activity.
	// The actual value for the idle timeout is the minimum of this value and the peer's.
	// This value only applies after the handshake has completed.
	// If the timeout is exceeded, the connection is closed.
	// If this value is zero, the timeout is set to 30 seconds.
	MaxIdleTimeout time.Duration
	// The TokenStore stores tokens received from the server.
	// Tokens are used to skip address validation on future connection attempts.
	// The key used to store tokens is the ServerName from the tls.Config, if set
	// otherwise the token is associated with the server's IP address.
	TokenStore TokenStore
	// InitialStreamReceiveWindow is the initial size of the stream-level flow control window for receiving data.
	// If the application is consuming data quickly enough, the flow control auto-tuning algorithm
	// will increase the window up to MaxStreamReceiveWindow.
	// If this value is zero, it will default to 512 KB.
	// Values larger than the maximum varint (quicvarint.Max) will be clipped to that value.
	InitialStreamReceiveWindow uint64
	// MaxStreamReceiveWindow is the maximum stream-level flow control window for receiving data.
	// If this value is zero, it will default to 6 MB.
	// Values larger than the maximum varint (quicvarint.Max) will be clipped to that value.
	MaxStreamReceiveWindow uint64
	// InitialConnectionReceiveWindow is the initial size of the stream-level flow control window for receiving data.
	// If the application is consuming data quickly enough, the flow control auto-tuning algorithm
	// will increase the window up to MaxConnectionReceiveWindow.
	// If this value is zero, it will default to 512 KB.
	// Values larger than the maximum varint (quicvarint.Max) will be clipped to that value.
	InitialConnectionReceiveWindow uint64
	// MaxConnectionReceiveWindow is the connection-level flow control window for receiving data.
	// If this value is zero, it will default to 15 MB.
	// Values larger than the maximum varint (quicvarint.Max) will be clipped to that value.
	MaxConnectionReceiveWindow uint64
	// AllowConnectionWindowIncrease is called every time the connection flow controller attempts
	// to increase the connection flow control window.
	// If set, the caller can prevent an increase of the window. Typically, it would do so to
	// limit the memory usage.
	// To avoid deadlocks, it is not valid to call other functions on the connection or on streams
	// in this callback.
	AllowConnectionWindowIncrease func(conn *Conn, delta uint64) bool
	// MaxIncomingStreams is the maximum number of concurrent bidirectional streams that a peer is allowed to open.
	// If not set, it will default to 100.
	// If set to a negative value, it doesn't allow any bidirectional streams.
	// Values larger than 2^60 will be clipped to that value.
	MaxIncomingStreams int64
	// MaxIncomingUniStreams is the maximum number of concurrent unidirectional streams that a peer is allowed to open.
	// If not set, it will default to 100.
	// If set to a negative value, it doesn't allow any unidirectional streams.
	// Values larger than 2^60 will be clipped to that value.
	MaxIncomingUniStreams int64
	// KeepAlivePeriod defines whether this peer will periodically send a packet to keep the connection alive.
	// If set to 0, then no keep alive is sent. Otherwise, the keep alive is sent on that period (or at most
	// every half of MaxIdleTimeout, whichever is smaller).
	KeepAlivePeriod time.Duration
	// InitialPacketSize is the initial size (and the lower limit) for packets sent.
	// Under most circumstances, it is not necessary to manually set this value,
	// since path MTU discovery quickly finds the path's MTU.
	// If set too high, the path might not support packets of that size, leading to a timeout of the QUIC handshake.
	// Values below 1200 are invalid.
	InitialPacketSize uint16
	// DisablePathMTUDiscovery disables Path MTU Discovery (RFC 8899).
	// This allows the sending of QUIC packets that fully utilize the available MTU of the path.
	// Path MTU discovery is only available on systems that allow setting of the Don't Fragment (DF) bit.
	DisablePathMTUDiscovery bool
	// Allow0RTT allows the application to decide if a 0-RTT connection attempt should be accepted.
	// Only valid for the server.
	Allow0RTT bool
	// ZeroRTTReplayCache protects the server against the replay of 0-RTT data (section 9.2 of RFC 9001):
	// it accepts 0-RTT at most once for every session ticket. It is used if Allow0RTT is set.
	// If nil, a cache created with NewZeroRTTReplayCache(DefaultZeroRTTReplayWindow, DefaultZeroRTTReplayCacheSize)
	// is used, which is shared by all listeners of a Transport. It only protects this server: servers sharing
	// session ticket keys, and a server that is restarted, should share a cache.
	// Only valid for the server.
	ZeroRTTReplayCache ZeroRTTReplayCache
	// Enable QUIC datagram support (RFC 9221).
	EnableDatagrams bool
	// Enable QUIC Stream Resets with Partial Delivery.
	// See https://datatracker.ietf.org/doc/html/draft-ietf-quic-reliable-stream-reset-11.
	// The reset_stream_at transport parameter is sent with the final code point (0x1d) and the code point of
	// draft-07 (0x17f7586d2cb571). The extension is used if the peer sent either one of them.
	EnableStreamResetPartialDelivery bool
	// EnableQUICBitGreasing enables Greasing the QUIC Bit (RFC 9287). The grease_quic_bit transport parameter is sent,
	// and packets with the QUIC Bit (the second-most significant bit of the first byte) set to 0 are accepted.
	// If the peer sent the transport parameter as well, the QUIC Bit of every packet sent after processing the peer's
	// transport parameters is set to a random value.
	// Short header packets with the QUIC Bit set to 0 are then handled by the connection that their connection ID
	// belongs to, instead of being returned by Transport.ReadNonQUICPacket. It shouldn't be enabled if the peer sends
	// packets of other protocols to the same socket, especially with zero-length connection IDs.
	// For a server, the Config passed to Listen decides if Initial packets with the QUIC Bit set to 0 are accepted
	// (a client only sends them to a server that enabled the extension in a previous connection), and the Config
	// returned by GetConfigForClient decides for all other packets.
	EnableQUICBitGreasing bool
	// RequestObservedAddress enables QUIC Address Discovery (draft-ietf-quic-address-discovery-01), and asks the
	// peer to report the address it observes for this endpoint on every path, i.e. the reflexive transport address,
	// using OBSERVED_ADDRESS frames.
	// The reported addresses are returned by Conn.ObservedAddr, and in the ObservedAddr field of PathInfo.
	// The peer might report a wrong address (see section 6.1 of the draft).
	RequestObservedAddress bool
	// ProvideObservedAddress enables QUIC Address Discovery (draft-ietf-quic-address-discovery-01), and offers to
	// report the address observed for the peer. If the peer asks for it, an OBSERVED_ADDRESS frame is sent on
	// every path, including the path used for the handshake, and when the peer's address on a path changes.
	// It should not be set if the endpoint can't observe the peer's address, e.g. behind a proxy or a load balancer
	// that changes the addresses of packets (section 6.2 of the draft).
	ProvideObservedAddress bool
	// MaxPaths is the number of paths of IETF Multipath QUIC that can be in use at the same time,
	// including the path used during the handshake: the initial_max_path_id transport parameter is MaxPaths-1.
	// If set to 0, it defaults to 3. Values larger than 64 are reduced to 64.
	// It only applies if a multipath controller is configured.
	// With MaxPaths 1, initial_max_path_id is 0, which enables the extension without allowing additional paths
	// (section 2.1 of draft-ietf-quic-multipath-21). Some implementations (picoquic) only enable the extension if
	// both endpoints send a value larger than 0, and close the connection when they receive the frames of the
	// extension. To use a single path without the extension, don't configure a multipath controller.
	MaxPaths int
	// MultipathController enables path-aware scheduling and packet mapping.
	// A controller keeps per-connection state, so it is only used by one connection at a time.
	// If it is already used by another connection, the built-in controllers are cloned (without their paths),
	// and multipath is disabled for other controllers.
	// Use MultipathControllerFactory to create a controller per connection, e.g. on a server.
	MultipathController MultipathController
	// MultipathControllerFactory creates the multipath controller of a connection.
	// If set, it takes precedence over MultipathController.
	MultipathControllerFactory func() MultipathController
	// MultipathCongestionControl selects the congestion control used on multipath connections.
	// It defaults to MultipathCongestionControlReno.
	MultipathCongestionControl MultipathCongestionControl
	// MultipathDuplicationPolicy enables packet duplication across paths.
	// Every path has its own packet number space: the selected frames are copied,
	// and the copies are sent in separate packets on other paths. They are never retransmitted.
	MultipathDuplicationPolicy *MultipathDuplicationPolicy
	// MultipathReinjectionPolicy enables packet reinjection on alternate paths.
	MultipathReinjectionPolicy *MultipathReinjectionPolicy
	// MultipathAutoPaths automatically creates additional paths from the local addresses after the handshake.
	// Only clients open paths, so this has no effect for servers.
	// A path to the server address of the first path is opened from every local address
	// other than the one of the first path, up to MaxPaths paths in total (see Conn.AddPathFromAddr).
	// This requires a socket bound to an unspecified address, or a MultiSocketManager.
	// No paths are opened to the server address of the first path if the server disabled active migration.
	// If the address advertisement extension is used (see EnableAddressAdvertisement), a path is also opened to
	// every address advertised by the server that uses the address family of the server address of the first path,
	// from the local address of the first path, within the same limit.
	MultipathAutoPaths bool
	// EnableAddressAdvertisement enables the address advertisement extension of this module (ADD_ADDRESS frames),
	// which is only used together with IETF Multipath QUIC. It is negotiated separately, using a transport parameter
	// that is only sent if the initial_max_path_id transport parameter is sent as well.
	// If both endpoints enable it, an endpoint can advertise its addresses using Conn.AdvertiseAddress.
	// The addresses advertised by the peer are returned by Conn.PeerAdvertisedAddresses.
	// Only clients open paths: a client can open paths to the addresses advertised by the server
	// (see MultipathAutoPaths and Conn.AddPathFromAddr). A server only records the addresses advertised by the client.
	EnableAddressAdvertisement bool
	// MultipathAutoAdvertise makes a server advertise its local addresses using ADD_ADDRESS frames, once the handshake
	// completed: the addresses in MultipathAutoAddrs, or the addresses of the local interfaces of the address family
	// used by the client, except for the local address used during the handshake. They are advertised with the port of
	// the connection's socket, which needs to be bound to an unspecified address.
	// It only has an effect if the address advertisement extension is used (see EnableAddressAdvertisement),
	// and it has no effect for clients.
	MultipathAutoAdvertise bool
	// MultipathAutoAddrs optionally overrides auto-discovered local addresses.
	MultipathAutoAddrs []net.IP
	// ExtensionFrameHandler enables parsing of custom frame types.
	ExtensionFrameHandler ExtensionFrameHandler

	Tracer func(ctx context.Context, isClient bool, connID ConnectionID) qlogwriter.Trace

	// set by populateConfig if Versions was set by the application
	versionsConfigured bool
	// The cache used by the server: ZeroRTTReplayCache, or the default cache of the Transport.
	zeroRTTReplayCache ZeroRTTReplayCache
}

// ClientInfo contains information about an incoming connection attempt.
type ClientInfo struct {
	// RemoteAddr is the remote address on the Initial packet.
	// Unless AddrVerified is set, the address is not yet verified, and could be a spoofed IP address.
	RemoteAddr net.Addr
	// AddrVerified reports whether the remote address was verified by a valid address validation token,
	// including a token received in a NEW_TOKEN frame.
	// The Retry mechanism costs one network roundtrip and is only used when
	// [Transport.VerifySourceAddress] requests it.
	AddrVerified bool
}

// ConnectionState records basic details about a QUIC connection.
type ConnectionState struct {
	// TLS contains information about the TLS connection state, incl. the tls.ConnectionState.
	TLS tls.ConnectionState
	// SupportsDatagrams indicates support for QUIC datagrams (RFC 9221).
	SupportsDatagrams struct {
		// Remote is true if the peer advertised datagram support.
		// Local is true if datagram support was enabled via Config.EnableDatagrams.
		Remote, Local bool
	}
	// SupportsMultipath is true if IETF Multipath QUIC (draft-ietf-quic-multipath-21) is used:
	// a multipath controller is configured, and both endpoints advertised the initial_max_path_id transport parameter.
	SupportsMultipath bool
	// SupportsAddressAdvertisement is true if the address advertisement extension (ADD_ADDRESS) is used:
	// IETF Multipath QUIC is used, and both endpoints enabled the extension (see Config.EnableAddressAdvertisement).
	// It is only set once the handshake completed.
	SupportsAddressAdvertisement bool
	// SupportsAddressDiscovery describes the use of QUIC Address Discovery (draft-ietf-quic-address-discovery-01).
	// It is only set once the handshake completed.
	SupportsAddressDiscovery struct {
		// Send is true if this endpoint reports the address it observes for the peer:
		// Config.ProvideObservedAddress is set, and the peer requested address observations.
		// Receive is true if the peer reports the address it observes for this endpoint (see Conn.ObservedAddr):
		// Config.RequestObservedAddress is set, and the peer offered to provide address observations.
		Send, Receive bool
	}
	// SupportsStreamResetPartialDelivery indicates support for QUIC Stream Resets with Partial Delivery.
	SupportsStreamResetPartialDelivery struct {
		// Remote is true if the peer advertised support.
		// Local is true if support was enabled via Config.EnableStreamResetPartialDelivery.
		Remote, Local bool
	}
	// SupportsQUICBitGreasing indicates support for Greasing the QUIC Bit (RFC 9287).
	// The QUIC Bit of the packets sent is only greased if Remote is true and Local is true.
	SupportsQUICBitGreasing struct {
		// Remote is true if the peer sent the grease_quic_bit transport parameter.
		// Local is true if support was enabled via Config.EnableQUICBitGreasing.
		Remote, Local bool
	}
	// Used0RTT says if 0-RTT resumption was used.
	Used0RTT bool
	// Version is the QUIC version of the QUIC connection.
	Version Version
	// GSO says if generic segmentation offload is used.
	GSO bool
}
