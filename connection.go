package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/handshake"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/internal/utils"
	"github.com/AeonDave/mp-quic-go/internal/utils/ringbuffer"
	"github.com/AeonDave/mp-quic-go/internal/wire"
	"github.com/AeonDave/mp-quic-go/qlog"
	"github.com/AeonDave/mp-quic-go/qlogwriter"
	"github.com/AeonDave/mp-quic-go/quicvarint"
)

type unpacker interface {
	UnpackLongHeader(hdr *wire.Header, data []byte) (*unpackedPacket, error)
	// UnpackShortHeader unpacks a 1-RTT packet received on a path of IETF Multipath QUIC.
	// Without IETF Multipath QUIC, the path ID is 0.
	UnpackShortHeader(rcvTime monotime.Time, data []byte, pathID protocol.PathID) (protocol.PacketNumber, protocol.PacketNumberLen, protocol.KeyPhaseBit, []byte, error)
}

type cryptoStreamHandler interface {
	StartHandshake(context.Context) error
	ChangeConnectionID(protocol.ConnectionID)
	SwitchVersion(protocol.Version)
	SetLargest1RTTAcked(protocol.PacketNumber) error
	SetLargest1RTTAckedForPath(protocol.PathID, protocol.PacketNumber, monotime.Time) error
	EnableMultipath(maxPTO func() time.Duration) error
	DropPath(protocol.PathID)
	SetHandshakeConfirmed()
	GetSessionTicket() ([]byte, error)
	NextEvent() handshake.Event
	DiscardInitialKeys()
	HandleMessage([]byte, protocol.EncryptionLevel) error
	io.Closer
	ConnectionState() handshake.ConnectionState
}

type receivedPacket struct {
	buffer *packetBuffer

	remoteAddr net.Addr
	rcvTime    monotime.Time
	data       []byte

	ecn protocol.ECN

	info packetInfo // only valid if the contained IP address is valid

	// The Transport that received the packet, if known.
	// A client uses it to answer PATH_CHALLENGE frames on the path they were received on.
	transport *Transport
}

type receivedPacketWithChecksum struct {
	receivedPacket
	checksum qlog.DatagramPayloadChecksum
}

func (p *receivedPacket) Size() protocol.ByteCount { return protocol.ByteCount(len(p.data)) }

func (p *receivedPacket) Clone() *receivedPacket {
	return &receivedPacket{
		remoteAddr: p.remoteAddr,
		rcvTime:    p.rcvTime,
		data:       p.data,
		buffer:     p.buffer,
		ecn:        p.ecn,
		info:       p.info,
		transport:  p.transport,
	}
}

type connRunner interface {
	Add(protocol.ConnectionID, packetHandler) bool
	Remove(protocol.ConnectionID)
	ReplaceWithClosed([]protocol.ConnectionID, []byte, time.Duration)
	AddResetToken(protocol.StatelessResetToken, packetHandler)
	RemoveResetToken(protocol.StatelessResetToken)
}

type closeError struct {
	err       error
	immediate bool
}

type errCloseForRecreating struct {
	nextPacketNumber protocol.PacketNumber
	nextVersion      protocol.Version
}

func (e *errCloseForRecreating) Error() string {
	return "closing connection in order to recreate it"
}

var deadlineSendImmediately = monotime.Time(42 * time.Millisecond) // any value > time.Time{} and before time.Now() is fine

type blockMode uint8

const (
	// blockModeNone means that the connection is not blocked.
	blockModeNone blockMode = iota
	// blockModeCongestionLimited means that the connection is congestion limited.
	// In that case, we can still send acknowledgments and PTO probe packets.
	blockModeCongestionLimited
	// blockModeHardBlocked means that no packet can be sent, under no circumstances. This can happen when:
	// * the send queue is full
	// * the SentPacketHandler returns SendNone, e.g. when we are tracking the maximum number of packets
	// In that case, the timer will be set to the idle timeout.
	blockModeHardBlocked
)

// A Conn is a QUIC connection between two peers.
// Calls to the connection (and to streams) can return the following types of errors:
//   - [ApplicationError]: for errors triggered by the application running on top of QUIC
//   - [TransportError]: for errors triggered by the QUIC transport (in many cases a misbehaving peer)
//   - [IdleTimeoutError]: when the peer goes away unexpectedly (this is a [net.Error] timeout error)
//   - [HandshakeTimeoutError]: when the cryptographic handshake takes too long (this is a [net.Error] timeout error)
//   - [StatelessResetError]: when we receive a stateless reset
//   - [VersionNegotiationError]: returned by the client, when there's no version overlap between the peers
type Conn struct {
	// Destination connection ID used during the handshake.
	// Used to check source connection ID on incoming packets.
	handshakeDestConnID protocol.ConnectionID
	// Set for the client. Destination connection ID used on the first Initial sent.
	origDestConnID protocol.ConnectionID
	retrySrcConnID *protocol.ConnectionID // only set for the client (and if a Retry was performed)

	srcConnIDLen int
	// Only set for the server: the length of the destination connection ID of the client's Initial packets
	// that carry the ClientHello. After a Retry, this is the source connection ID of the Retry.
	clientDestConnIDLen int

	perspective protocol.Perspective
	// The version in use for the connection.
	// After compatible version negotiation (RFC 9368), this is the Negotiated Version.
	version protocol.Version
	// The client's Chosen Version, i.e. the version of the client's first flight. It is never modified.
	chosenVersion protocol.Version
	// Only set for the client: the versions that the client's first flight is compatible with,
	// other than the Chosen Version. The server can switch to one of them (compatible version negotiation).
	compatibleVersions []protocol.Version
	// Only used by the client: is the Negotiated Version known?
	knowsNegotiatedVersion bool
	config                 *Config

	conn      sendConn
	sendQueue sender

	multipathController         MultipathController
	multipathObserver           MultipathObserver
	extensionFrameHandler       ExtensionFrameHandler
	multipathDuplicationPolicy  *MultipathDuplicationPolicy
	multipathReinjectionManager *MultipathReinjectionManager
	// the paths that the next packets carrying retransmissions are sent on, see handlePendingReinjections
	reinjectionPathQueue   []protocol.PathID
	reinjectionQueueCounts map[protocol.PathID]int
	// the local addresses that paths were opened from, see maybeOpenAutoPaths
	autoPathsStarted bool
	autoAddedPaths   map[string]bool
	// the addresses advertised by the server that paths were opened to, see maybeOpenPathToAdvertisedAddr
	autoAdvertisedPaths map[netip.AddrPort]bool
	// the number of paths opened automatically, limited by Config.MaxPaths
	autoPathsOpened int
	// the controller set in the Config is used by this connection, and needs to be released when it's closed
	releaseMultipathControllerOnClose bool
	// passed to the multipath controller in the PathSelectionContext, set when IETF Multipath QUIC becomes active
	pathCongestionFunc func(PathID) (ByteCount, ByteCount, bool)
	// the local IP that the peer sends packets to on the primary path
	primaryLocalIP net.IP
	// The address that the peer used during the handshake.
	// For the client, it is the server address the connection was dialed to.
	peerHandshakeAddr net.Addr
	// the Transport used for the handshake (client only)
	handshakeTransport *Transport
	// If the client dialed an unspecified IP address (e.g. 0.0.0.0 or ::), the operating system chooses the
	// address that the packets are sent to, usually a loopback address. This is the source address of the first
	// packet received from the server that was processed, see isKnownServerAddr0.
	unspecifiedServerAddr net.Addr

	// Did we advertise the initial_max_path_id transport parameter of IETF Multipath QUIC?
	advertisedMultipath bool
	// The state of IETF Multipath QUIC. Only set if both endpoints advertised the extension.
	mp *multipathState
	// Did we advertise the add_address transport parameter of the address advertisement extension?
	advertisedAddAddress bool
	// The state of the address advertisement extension. Only set if both endpoints advertised the extension,
	// and IETF Multipath QUIC is used.
	addrAdv *addressAdvertisement
	// The address_discovery transport parameter we sent.
	advertisedAddressDiscovery wire.AddressDiscoveryMode
	// The state of QUIC Address Discovery. Only set if OBSERVED_ADDRESS frames are sent or received.
	addrDisc *addressDiscovery
	// errors that occurred when sending on the sendConn of a path of IETF Multipath QUIC
	pathWriteErrorsMx sync.Mutex
	pathWriteErrors   []pathWriteError
	// The path that LocalAddr, RemoteAddr and ConnectionStats refer to: path 0, until path 0 was abandoned
	// (IETF Multipath QUIC), or until the client switched to a new path (RFC 9000 connection migration).
	// It is set when the run loop starts. They refer to c.conn and c.rttStats as long as it is nil.
	primaryPath atomic.Pointer[primaryPath]
	// the paths returned by Paths (IETF Multipath QUIC)
	mpPaths atomic.Pointer[[]PathInfo]

	// lazily initialzed: most connections never migrate
	pathManager         *pathManager
	largestRcvdAppData  protocol.PacketNumber
	pathManagerOutgoing atomic.Pointer[pathManagerOutgoing]

	// The preferred address sent by the server (section 9.6 of RFC 9000), nil if none was sent.
	prefAddr *preferredAddrServer
	// The client's migration to the server's preferred address, nil if the client doesn't migrate.
	prefAddrMigration *preferredAddrMigration
	// The client migrated to the server's preferred address.
	migratedToPreferredAddr atomic.Bool

	streamsMap      *streamsMap
	connIDManager   *connIDManager      // connection IDs provided by the peer for path 0
	peerConnIDs     *pathConnIDManagers // connection IDs provided by the peer for all paths, path 0 is the connIDManager
	connIDGenerator *connIDGenerator
	// registers the peer's stateless reset tokens with the Transports that the connection receives packets on
	resetTokenRunners *resetTokenRunners

	rttStats  *utils.RTTStats
	connStats utils.ConnectionStats

	cryptoStreamManager   *cryptoStreamManager
	sentPacketHandler     ackhandler.SentPacketHandler
	receivedPacketHandler ackhandler.ReceivedPacketHandler
	retransmissionQueue   *retransmissionQueue
	framer                *framer
	connFlowController    *connectionFlowController
	tokenStoreKey         string                    // only set for the client
	tokenGenerator        *handshake.TokenGenerator // only set for the server

	unpacker      unpacker
	frameParser   wire.FrameParser
	packer        packer
	mtuDiscoverer *mtuFinder // initialized when the transport parameters are received

	maxPayloadSizeEstimate atomic.Uint32

	initialStream       *initialCryptoStream
	handshakeStream     *cryptoStream
	oneRTTStream        *cryptoStream // only set for the server
	cryptoStreamHandler cryptoStreamHandler

	notifyReceivedPacket chan struct{}
	sendingScheduled     chan struct{}
	receivedPacketMx     sync.Mutex
	receivedPackets      ringbuffer.RingBuffer[receivedPacket]

	// closeChan is used to notify the run loop that it should terminate
	closeChan chan struct{}
	closeErr  atomic.Pointer[closeError]

	ctx                   context.Context
	ctxCancel             context.CancelCauseFunc
	handshakeCompleteChan chan struct{}

	undecryptablePackets          []receivedPacketWithChecksum // undecryptable packets, waiting for a change in encryption level
	undecryptablePacketsToProcess []receivedPacketWithChecksum

	earlyConnReadyChan chan struct{}
	sentFirstPacket    bool
	droppedInitialKeys bool
	handshakeComplete  bool
	handshakeConfirmed bool

	receivedRetry       bool
	versionNegotiated   bool
	receivedFirstPacket bool

	blocked blockMode

	// the minimum of the max_idle_timeout values advertised by both endpoints
	idleTimeout  time.Duration
	creationTime monotime.Time
	// The idle timeout is set based on the max of the time we received the last packet...
	lastPacketReceivedTime monotime.Time
	// When the connection started processing the packets taken from the queue of received packets, see ackTime.
	// It is zero while processing packets that were queued because their keys weren't available yet.
	processingStartTime monotime.Time
	// ... and the time we sent a new ack-eliciting packet after receiving a packet.
	firstAckElicitingPacketAfterIdleSentTime monotime.Time
	// pacingDeadline is the time when the next packet should be sent
	pacingDeadline monotime.Time

	peerParams *wire.TransportParameters

	timer *time.Timer
	// keepAlivePingSent stores whether a keep alive PING is in flight.
	// It is reset as soon as we receive a packet from the peer.
	keepAlivePingSent bool
	keepAliveInterval time.Duration

	datagramQueue *datagramQueue

	connStateMutex sync.Mutex
	connState      ConnectionState

	logID     string
	qlogTrace qlogwriter.Trace
	qlogger   qlogwriter.Recorder
	logger    utils.Logger
}

var _ streamSender = &Conn{}

type connTestHooks struct {
	run                     func() error
	earlyConnReady          func() <-chan struct{}
	context                 func() context.Context
	handshakeComplete       func() <-chan struct{}
	closeWithTransportError func(TransportErrorCode)
	destroy                 func(error)
	handlePacket            func(receivedPacket)
}

type wrappedConn struct {
	testHooks *connTestHooks
	*Conn
}

var newConnection = func(
	ctx context.Context,
	ctxCancel context.CancelCauseFunc,
	conn sendConn,
	runner connRunner,
	origDestConnID protocol.ConnectionID,
	retrySrcConnID *protocol.ConnectionID,
	clientDestConnID protocol.ConnectionID,
	destConnID protocol.ConnectionID,
	srcConnID protocol.ConnectionID,
	connIDGenerator ConnectionIDGenerator,
	statelessResetter *statelessResetter,
	conf *Config,
	tlsConf *tls.Config,
	tokenGenerator *handshake.TokenGenerator,
	clientAddressValidated bool,
	rtt time.Duration,
	preferredAddr *serverPreferredAddr,
	qlogTrace qlogwriter.Trace,
	logger utils.Logger,
	v protocol.Version,
) *wrappedConn {
	s := &Conn{
		ctx:                 ctx,
		ctxCancel:           ctxCancel,
		conn:                conn,
		config:              conf,
		handshakeDestConnID: destConnID,
		srcConnIDLen:        srcConnID.Len(),
		clientDestConnIDLen: clientDestConnID.Len(),
		tokenGenerator:      tokenGenerator,
		oneRTTStream:        newCryptoStream(),
		perspective:         protocol.PerspectiveServer,
		qlogTrace:           qlogTrace,
		logger:              logger,
		version:             v,
		chosenVersion:       v,
	}
	if qlogTrace != nil {
		s.qlogger = qlogTrace.AddProducer()
	}
	if origDestConnID.Len() > 0 {
		s.logID = origDestConnID.String()
	} else {
		s.logID = destConnID.String()
	}
	s.resetTokenRunners = newResetTokenRunners(runner, s)
	s.connIDManager = newConnIDManager(
		destConnID,
		s.resetTokenRunners.AddResetToken,
		s.resetTokenRunners.RemoveResetToken,
		s.queueControlFrame,
	)
	s.peerConnIDs = newPathConnIDManagers(s.connIDManager)
	s.connIDGenerator = newConnIDGenerator(
		runner,
		srcConnID,
		&clientDestConnID,
		statelessResetter,
		connRunnerCallbacks{
			AddConnectionID:    func(connID protocol.ConnectionID) { runner.Add(connID, s) },
			RemoveConnectionID: runner.Remove,
			ReplaceWithClosed:  runner.ReplaceWithClosed,
		},
		s.queueControlFrame,
		connIDGenerator,
	)
	s.preSetup()
	s.rttStats.SetInitialRTT(rtt)
	s.sentPacketHandler = ackhandler.NewSentPacketHandler(
		0,
		protocol.ByteCount(s.config.InitialPacketSize),
		s.rttStats,
		&s.connStats,
		clientAddressValidated,
		s.conn.capabilities().ECN,
		s.receivedPacketHandler.IgnorePacketsBelow,
		s.perspective,
		s.qlogger,
		s.logger,
	)
	s.setupMultipath()
	s.maxPayloadSizeEstimate.Store(uint32(estimateMaxPayloadSize(protocol.ByteCount(s.config.InitialPacketSize))))
	statelessResetToken := statelessResetter.GetStatelessResetToken(srcConnID)
	params := &wire.TransportParameters{
		InitialMaxStreamDataBidiLocal:   protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxStreamDataBidiRemote:  protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxStreamDataUni:         protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxData:                  protocol.ByteCount(s.config.InitialConnectionReceiveWindow),
		MaxIdleTimeout:                  s.config.MaxIdleTimeout,
		MaxBidiStreamNum:                protocol.StreamNum(s.config.MaxIncomingStreams),
		MaxUniStreamNum:                 protocol.StreamNum(s.config.MaxIncomingUniStreams),
		MaxAckDelay:                     protocol.MaxAckDelayInclGranularity,
		AckDelayExponent:                protocol.AckDelayExponent,
		MaxUDPPayloadSize:               protocol.MaxPacketBufferSize,
		StatelessResetToken:             &statelessResetToken,
		OriginalDestinationConnectionID: origDestConnID,
		// For interoperability with quic-go versions before May 2023, this value must be set to a value
		// different from protocol.DefaultActiveConnectionIDLimit.
		// If set to the default value, it will be omitted from the transport parameters, which will make
		// old quic-go versions interpret it as 0, instead of the default value of 2.
		// See https://github.com/quic-go/quic-go/pull/3806.
		ActiveConnectionIDLimit:   protocol.MaxActiveConnectionIDs,
		InitialSourceConnectionID: srcConnID,
		RetrySourceConnectionID:   retrySrcConnID,
		EnableResetStreamAt:       conf.EnableStreamResetPartialDelivery,
		GreaseQUICBit:             conf.EnableQUICBitGreasing,
		// The Available Versions are the Fully Deployed Versions (section 3 of RFC 9368).
		VersionInformation: &wire.VersionInformation{
			ChosenVersion:     v,
			AvailableVersions: conf.Versions,
		},
	}
	if s.config.EnableDatagrams {
		params.MaxDatagramFrameSize = wire.MaxDatagramSize
	} else {
		params.MaxDatagramFrameSize = protocol.InvalidByteCount
	}
	// The client's source connection ID is the destination connection ID.
	s.maybeAdvertiseMultipath(params, srcConnID, destConnID)
	s.maybeAdvertiseAddressAdvertisement(params)
	s.maybeAdvertiseAddressDiscovery(params)
	s.maybeAdvertisePreferredAddress(params, preferredAddr)
	if s.qlogger != nil {
		s.qlogTransportParameters(params, protocol.PerspectiveServer, false)
	}
	// The server only switches versions if the application configured the versions (and their order).
	var preferredVersions []protocol.Version
	if conf.versionsConfigured {
		preferredVersions = conf.Versions
	}
	cs := handshake.NewCryptoSetupServer(
		clientDestConnID,
		conn.LocalAddr(),
		conn.RemoteAddr(),
		params,
		tlsConf,
		conf.Allow0RTT,
		useTicketFor0RTT(conf.zeroRTTReplayCache),
		s.rttStats,
		s.qlogger,
		logger,
		s.version,
		preferredVersions,
	)
	s.cryptoStreamHandler = cs
	packer := newPacketPacker(srcConnID, s.connIDManager.Get, s.initialStream, s.handshakeStream, s.sentPacketHandler, s.retransmissionQueue, cs, s.framer, &s.receivedPacketHandler, s.datagramQueue, s.perspective)
	// Datagrams containing PATH_RESPONSE frames are only expanded within the anti-amplification limit
	// (section 8.2.2 of RFC 9000).
	packer.amplificationBudget = s.sentPacketHandler.AmplificationBudgetForPath
	s.packer = packer
	s.unpacker = newPacketUnpacker(cs, s.srcConnIDLen, s.config.EnableQUICBitGreasing)
	s.cryptoStreamManager = newCryptoStreamManager(s.initialStream, s.handshakeStream, s.oneRTTStream)
	return &wrappedConn{Conn: s}
}

// useTicketFor0RTT returns the function that the server's crypto setup calls when a client uses a session ticket for
// 0-RTT. Without a cache, 0-RTT is rejected.
func useTicketFor0RTT(cache ZeroRTTReplayCache) func(handshake.SessionTicketID, time.Time) bool {
	if cache == nil {
		return nil
	}
	return cache.UseTicket
}

// declare this as a variable, such that we can it mock it in the tests
var newClientConnection = func(
	ctx context.Context,
	conn sendConn,
	runner connRunner,
	destConnID protocol.ConnectionID,
	srcConnID protocol.ConnectionID,
	connIDGenerator ConnectionIDGenerator,
	statelessResetter *statelessResetter,
	conf *Config,
	tlsConf *tls.Config,
	initialPacketNumber protocol.PacketNumber,
	enable0RTT bool,
	hasNegotiatedVersion bool,
	qlogTrace qlogwriter.Trace,
	logger utils.Logger,
	v protocol.Version,
) *wrappedConn {
	s := &Conn{
		conn:                conn,
		config:              conf,
		origDestConnID:      destConnID,
		handshakeDestConnID: destConnID,
		srcConnIDLen:        srcConnID.Len(),
		peerHandshakeAddr:   conn.RemoteAddr(),
		perspective:         protocol.PerspectiveClient,
		logID:               destConnID.String(),
		logger:              logger,
		qlogTrace:           qlogTrace,
		versionNegotiated:   hasNegotiatedVersion,
		version:             v,
		chosenVersion:       v,
	}
	if tr, ok := runner.(*packetHandlerMap); ok {
		s.handshakeTransport = (*Transport)(tr)
	}
	if qlogTrace != nil {
		s.qlogger = qlogTrace.AddProducer()
	}
	if s.qlogger != nil {
		var srcAddr, destAddr *net.UDPAddr
		if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			srcAddr = addr
		}
		if addr, ok := conn.RemoteAddr().(*net.UDPAddr); ok {
			destAddr = addr
		}
		s.qlogger.RecordEvent(startedConnectionEvent(srcAddr, destAddr))
	}
	s.resetTokenRunners = newResetTokenRunners(runner, s)
	s.connIDManager = newConnIDManager(
		destConnID,
		s.resetTokenRunners.AddResetToken,
		s.resetTokenRunners.RemoveResetToken,
		s.queueControlFrame,
	)
	s.peerConnIDs = newPathConnIDManagers(s.connIDManager)
	s.connIDGenerator = newConnIDGenerator(
		runner,
		srcConnID,
		nil,
		statelessResetter,
		connRunnerCallbacks{
			AddConnectionID:    func(connID protocol.ConnectionID) { runner.Add(connID, s) },
			RemoveConnectionID: runner.Remove,
			ReplaceWithClosed:  runner.ReplaceWithClosed,
		},
		s.queueControlFrame,
		connIDGenerator,
	)
	s.ctx, s.ctxCancel = context.WithCancelCause(ctx)
	s.preSetup()
	s.sentPacketHandler = ackhandler.NewSentPacketHandler(
		initialPacketNumber,
		protocol.ByteCount(s.config.InitialPacketSize),
		s.rttStats,
		&s.connStats,
		false, // has no effect
		s.conn.capabilities().ECN,
		s.receivedPacketHandler.IgnorePacketsBelow,
		s.perspective,
		s.qlogger,
		s.logger,
	)
	s.setupMultipath()
	s.maxPayloadSizeEstimate.Store(uint32(estimateMaxPayloadSize(protocol.ByteCount(s.config.InitialPacketSize))))
	oneRTTStream := newCryptoStream()
	params := &wire.TransportParameters{
		InitialMaxStreamDataBidiRemote: protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxStreamDataBidiLocal:  protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxStreamDataUni:        protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxData:                 protocol.ByteCount(s.config.InitialConnectionReceiveWindow),
		MaxIdleTimeout:                 s.config.MaxIdleTimeout,
		MaxBidiStreamNum:               protocol.StreamNum(s.config.MaxIncomingStreams),
		MaxUniStreamNum:                protocol.StreamNum(s.config.MaxIncomingUniStreams),
		MaxAckDelay:                    protocol.MaxAckDelayInclGranularity,
		MaxUDPPayloadSize:              protocol.MaxPacketBufferSize,
		AckDelayExponent:               protocol.AckDelayExponent,
		// For interoperability with quic-go versions before May 2023, this value must be set to a value
		// different from protocol.DefaultActiveConnectionIDLimit.
		// If set to the default value, it will be omitted from the transport parameters, which will make
		// old quic-go versions interpret it as 0, instead of the default value of 2.
		// See https://github.com/quic-go/quic-go/pull/3806.
		ActiveConnectionIDLimit:   protocol.MaxActiveConnectionIDs,
		InitialSourceConnectionID: srcConnID,
		EnableResetStreamAt:       conf.EnableStreamResetPartialDelivery,
		GreaseQUICBit:             conf.EnableQUICBitGreasing,
		// The Available Versions are the versions that the first flight is compatible with (section 3 of RFC 9368).
		VersionInformation: &wire.VersionInformation{
			ChosenVersion:     v,
			AvailableVersions: protocol.CompatibleVersions(s.config.Versions, v),
		},
	}
	for _, ver := range params.VersionInformation.AvailableVersions {
		if ver != v {
			s.compatibleVersions = append(s.compatibleVersions, ver)
		}
	}
	if s.config.EnableDatagrams {
		params.MaxDatagramFrameSize = wire.MaxDatagramSize
	} else {
		params.MaxDatagramFrameSize = protocol.InvalidByteCount
	}
	s.maybeAdvertiseMultipath(params, srcConnID, destConnID)
	s.maybeAdvertiseAddressAdvertisement(params)
	s.maybeAdvertiseAddressDiscovery(params)
	if s.qlogger != nil {
		s.qlogTransportParameters(params, protocol.PerspectiveClient, false)
	}
	cs := handshake.NewCryptoSetupClient(
		destConnID,
		params,
		tlsConf,
		enable0RTT,
		s.rttStats,
		s.qlogger,
		logger,
		s.version,
		s.config.Versions,
		hasNegotiatedVersion,
	)
	s.cryptoStreamHandler = cs
	s.cryptoStreamManager = newCryptoStreamManager(s.initialStream, s.handshakeStream, oneRTTStream)
	s.unpacker = newPacketUnpacker(cs, s.srcConnIDLen, s.config.EnableQUICBitGreasing)
	packer := newPacketPacker(srcConnID, s.connIDManager.Get, s.initialStream, s.handshakeStream, s.sentPacketHandler, s.retransmissionQueue, cs, s.framer, &s.receivedPacketHandler, s.datagramQueue, s.perspective)
	// 0-RTT packets always use the Chosen Version, even after compatible version negotiation (section 4.1 of RFC 9369).
	packer.zeroRTTVersion = s.chosenVersion
	s.packer = packer
	if len(tlsConf.ServerName) > 0 {
		s.tokenStoreKey = tlsConf.ServerName
	} else {
		s.tokenStoreKey = conn.RemoteAddr().String()
	}
	if s.config.TokenStore != nil {
		if token := s.config.TokenStore.Pop(versionedTokenStoreKey(s.tokenStoreKey, s.chosenVersion)); token != nil {
			s.packer.SetToken(token.data)
			s.rttStats.SetInitialRTT(token.rtt)
		}
	}
	return &wrappedConn{Conn: s}
}

func (c *Conn) preSetup() {
	c.largestRcvdAppData = protocol.InvalidPacketNumber
	c.initialStream = newInitialCryptoStream(c.perspective == protocol.PerspectiveClient)
	c.handshakeStream = newCryptoStream()
	c.sendQueue = newSendQueue(c.conn, c.handlePathWriteError)
	c.retransmissionQueue = newRetransmissionQueue()
	c.frameParser = *wire.NewFrameParser(
		c.config.EnableDatagrams,
		c.config.EnableStreamResetPartialDelivery,
		false, // ACK_FREQUENCY is not supported yet
	)
	if c.config.ExtensionFrameHandler != nil {
		c.extensionFrameHandler = c.config.ExtensionFrameHandler
		c.frameParser.AllowUnknownFrameTypes()
	}
	c.rttStats = utils.NewRTTStats()
	c.connFlowController = newConnectionFlowController(
		protocol.ByteCount(c.config.InitialConnectionReceiveWindow),
		protocol.ByteCount(c.config.MaxConnectionReceiveWindow),
		func(size protocol.ByteCount) bool {
			if c.config.AllowConnectionWindowIncrease == nil {
				return true
			}
			return c.config.AllowConnectionWindowIncrease(c, uint64(size))
		},
		c.rttStats,
		c.logger,
	)
	c.earlyConnReadyChan = make(chan struct{})
	c.streamsMap = newStreamsMap(
		c.ctx,
		c,
		c.queueControlFrame,
		c.newFlowController,
		uint64(c.config.MaxIncomingStreams),
		uint64(c.config.MaxIncomingUniStreams),
		c.perspective,
	)
	c.framer = newFramer(c.connFlowController)
	c.receivedPackets.Init(8)
	c.notifyReceivedPacket = make(chan struct{}, 1)
	c.closeChan = make(chan struct{}, 1)
	c.sendingScheduled = make(chan struct{}, 1)
	c.handshakeCompleteChan = make(chan struct{})

	now := monotime.Now()
	c.lastPacketReceivedTime = now
	c.creationTime = now

	c.receivedPacketHandler = *ackhandler.NewReceivedPacketHandler(c.logger)

	c.datagramQueue = newDatagramQueue(c.scheduleSending, c.logger)
	c.connState.Version = c.version
}

// run the connection main loop
func (c *Conn) run() (err error) {
	defer func() { c.ctxCancel(err) }()
	defer c.releaseMultipath()

	defer func() {
		// drain queued packets that will never be processed
		c.receivedPacketMx.Lock()
		defer c.receivedPacketMx.Unlock()

		for !c.receivedPackets.Empty() {
			p := c.receivedPackets.PopFront()
			p.buffer.Decrement()
			p.buffer.MaybeRelease()
		}
	}()

	// LocalAddr, RemoteAddr and ConnectionStats can be called concurrently with the run loop,
	// which replaces c.conn when the client switches to a new path (RFC 9000 connection migration).
	c.primaryPath.CompareAndSwap(nil, &primaryPath{conn: c.conn, rttStats: c.rttStats})
	c.timer = time.NewTimer(monotime.Until(c.idleTimeoutStartTime().Add(c.config.HandshakeIdleTimeout)))

	if err := c.cryptoStreamHandler.StartHandshake(c.ctx); err != nil {
		return err
	}
	if err := c.handleHandshakeEvents(monotime.Now()); err != nil {
		return err
	}
	go func() {
		if err := c.sendQueue.Run(); err != nil {
			c.destroyImpl(err)
		}
	}()

	if c.perspective == protocol.PerspectiveClient {
		c.scheduleSending() // so the ClientHello actually gets sent
	}

	var sendQueueAvailable <-chan struct{}

runLoop:
	for {
		if c.framer.QueuedTooManyControlFrames() {
			c.setCloseError(&closeError{err: &qerr.TransportError{ErrorCode: InternalError}})
			break runLoop
		}
		// Close immediately if requested
		select {
		case <-c.closeChan:
			break runLoop
		default:
		}

		// no need to set a timer if we can send packets immediately
		if c.pacingDeadline != deadlineSendImmediately {
			c.maybeResetTimer()
		}

		// 1st: handle undecryptable packets, if any.
		// This can only occur before completion of the handshake.
		if len(c.undecryptablePacketsToProcess) > 0 {
			var processedUndecryptablePacket bool
			queue := c.undecryptablePacketsToProcess
			c.undecryptablePacketsToProcess = nil
			for _, p := range queue {
				processed, err := c.handleOnePacket(p.receivedPacket, p.checksum)
				if err != nil {
					c.setCloseError(&closeError{err: err})
					break runLoop
				}
				if processed {
					processedUndecryptablePacket = true
				}
			}
			if processedUndecryptablePacket {
				// if we processed any undecryptable packets, jump to the resetting of the timers directly
				continue
			}
		}

		// 2nd: receive packets.
		processed, err := c.handlePackets() // don't check receivedPackets.Len() in the run loop to avoid locking the mutex
		if err != nil {
			c.setCloseError(&closeError{err: err})
			break runLoop
		}

		// We don't need to wait for new events if:
		// * we processed packets: we probably need to send an ACK, and potentially more data
		// * the pacer allows us to send more packets immediately
		shouldProceedImmediately := sendQueueAvailable == nil && (processed || c.pacingDeadline.Equal(deadlineSendImmediately))
		if !shouldProceedImmediately {
			// 3rd: wait for something to happen:
			// * closing of the connection
			// * timer firing
			// * sending scheduled
			// * send queue available
			// * received packets
			select {
			case <-c.closeChan:
				break runLoop
			case <-c.timer.C:
			case <-c.sendingScheduled:
			case <-sendQueueAvailable:
			case <-c.notifyReceivedPacket:
				wasProcessed, err := c.handlePackets()
				if err != nil {
					c.setCloseError(&closeError{err: err})
					break runLoop
				}
				// if we processed any undecryptable packets, jump to the resetting of the timers directly
				if !wasProcessed {
					continue
				}
			}
		}

		// Check for loss detection timeout.
		// This could cause packets to be declared lost, and retransmissions to be enqueued.
		now := monotime.Now()
		if timeout := c.sentPacketHandler.GetLossDetectionTimeout(); !timeout.IsZero() && !timeout.After(now) {
			if err := c.sentPacketHandler.OnLossDetectionTimeout(now); err != nil {
				c.setCloseError(&closeError{err: err})
				break runLoop
			}
		}

		if c.mp != nil && c.mp.active {
			if err := c.handleMultipathEvents(now); err != nil {
				c.destroyImpl(err)
				break runLoop
			}
		}

		if keepAliveTime := c.nextKeepAliveTime(); !keepAliveTime.IsZero() && !now.Before(keepAliveTime) {
			// send a PING frame since there is no activity in the connection
			c.logger.Debugf("Sending a keep-alive PING to keep the connection alive.")
			c.framer.QueueControlFrame(&wire.PingFrame{})
			c.keepAlivePingSent = true
		} else if !c.handshakeComplete && now.Sub(c.creationTime) >= c.config.handshakeTimeout() {
			c.destroyImpl(qerr.ErrHandshakeTimeout)
			break runLoop
		} else {
			idleTimeoutStartTime := c.idleTimeoutStartTime()
			if (!c.handshakeComplete && now.Sub(idleTimeoutStartTime) >= c.config.HandshakeIdleTimeout) ||
				(c.handshakeComplete && !now.Before(c.nextIdleTimeoutTime())) {
				c.destroyImpl(qerr.ErrIdleTimeout)
				break runLoop
			}
		}

		c.connIDGenerator.RemoveRetiredConnIDs(now)

		if err := c.handlePreferredAddrTimers(now); err != nil {
			c.destroyImpl(err)
			break runLoop
		}

		if c.perspective == protocol.PerspectiveClient {
			pm := c.pathManagerOutgoing.Load()
			if pm != nil {
				tr, id, ok := pm.ShouldSwitchPath(c.connIDManager.HasConnIDForPath)
				if ok {
					c.switchToNewPath(tr, id, now)
				}
			}
		}

		if c.sendQueue.WouldBlock() {
			// The send queue is still busy sending out packets. Wait until there's space to enqueue new packets.
			sendQueueAvailable = c.sendQueue.Available()
			// Cancel the pacing timer, as we can't send any more packets until the send queue is available again.
			c.pacingDeadline = 0
			c.blocked = blockModeHardBlocked
			continue
		}

		if c.closeErr.Load() != nil {
			break runLoop
		}

		c.blocked = blockModeNone // sending might set it back to true if we're congestion limited
		if err := c.triggerSending(now); err != nil {
			// No more packets are sent once the packet numbers are exhausted (section 12.3 of RFC 9000), or the
			// confidentiality limit of the AEAD was reached (section 6.6 of RFC 9001), not even a CONNECTION_CLOSE.
			immediate := errors.Is(err, errPacketNumbersExhausted) || errors.Is(err, handshake.ErrConfidentialityLimitReached)
			c.setCloseError(&closeError{err: err, immediate: immediate})
			break runLoop
		}
		if c.sendQueue.WouldBlock() {
			// The send queue is still busy sending out packets. Wait until there's space to enqueue new packets.
			sendQueueAvailable = c.sendQueue.Available()
			// Cancel the pacing timer, as we can't send any more packets until the send queue is available again.
			c.pacingDeadline = 0
			c.blocked = blockModeHardBlocked
		} else {
			sendQueueAvailable = nil
		}
	}

	closeErr := c.closeErr.Load()
	c.cryptoStreamHandler.Close()
	c.sendQueue.Close() // close the send queue before sending the CONNECTION_CLOSE
	c.handleCloseError(closeErr)
	if c.qlogger != nil {
		if _, ok := errors.AsType[*errCloseForRecreating](closeErr.err); !ok {
			c.qlogger.Close()
		}
	}
	c.logger.Infof("Connection %s closed.", c.logID)
	c.timer.Stop()
	return closeErr.err
}

// blocks until the early connection can be used
func (c *Conn) earlyConnReady() <-chan struct{} {
	return c.earlyConnReadyChan
}

// Context returns a context that is cancelled when the connection is closed.
// The cancellation cause is set to the error that caused the connection to close.
func (c *Conn) Context() context.Context {
	return c.ctx
}

// isPotentialStatelessReset says if the first byte of a packet is the first byte of a stateless reset:
// a short header packet with the QUIC Bit set. If the grease_quic_bit transport parameter was sent,
// the peer might also set the QUIC Bit to 0 (section 3 of RFC 9287).
func (c *Conn) isPotentialStatelessReset(firstByte byte) bool {
	if c.config.EnableQUICBitGreasing {
		return !wire.IsLongHeaderPacket(firstByte)
	}
	return firstByte&0b11000000 == 0b01000000
}

// acceptsGreasedQUICBit says if the connection accepts packets with the QUIC Bit set to 0,
// since it sent the grease_quic_bit transport parameter (RFC 9287).
func (c *Conn) acceptsGreasedQUICBit() bool {
	return c.config.EnableQUICBitGreasing
}

var _ greasedQUICBitAcceptor = &Conn{}

func (c *Conn) supportsDatagrams() bool {
	return c.peerParams.MaxDatagramFrameSize > 0
}

func (c *Conn) supportsMultipath() bool {
	return c.mp != nil
}

// ConnectionState returns basic details about the QUIC connection.
func (c *Conn) ConnectionState() ConnectionState {
	c.connStateMutex.Lock()
	defer c.connStateMutex.Unlock()

	cs := c.cryptoStreamHandler.ConnectionState()
	c.connState.TLS = cs.ConnectionState
	c.connState.Used0RTT = cs.Used0RTT
	if c.peerParams != nil {
		c.connState.SupportsDatagrams.Remote = c.supportsDatagrams()
		c.connState.SupportsStreamResetPartialDelivery.Remote = c.peerParams.EnableResetStreamAt
		c.connState.SupportsQUICBitGreasing.Remote = c.peerParams.GreaseQUICBit
	}
	c.connState.SupportsDatagrams.Local = c.config.EnableDatagrams
	c.connState.SupportsStreamResetPartialDelivery.Local = c.config.EnableStreamResetPartialDelivery
	c.connState.SupportsQUICBitGreasing.Local = c.config.EnableQUICBitGreasing
	c.connState.SupportsMultipath = c.supportsMultipath()
	c.connState.SupportsAddressAdvertisement = c.addressAdvertisementState() != nil
	if a := c.addressDiscoveryState(); a != nil {
		c.connState.SupportsAddressDiscovery.Send = a.send
		c.connState.SupportsAddressDiscovery.Receive = a.receive
	}
	c.connState.GSO = c.primarySendConn().capabilities().GSO
	return c.connState
}

// ConnectionStats contains statistics about the QUIC connection
type ConnectionStats struct {
	// MinRTT is the estimate of the minimum RTT observed on the active network
	// path.
	MinRTT time.Duration
	// LatestRTT is the last RTT sample observed on the active network path.
	LatestRTT time.Duration
	// SmoothedRTT is an exponentially weighted moving average of an endpoint's
	// RTT samples. See https://www.rfc-editor.org/rfc/rfc9002#section-5.3
	SmoothedRTT time.Duration
	// MeanDeviation estimates the variation in the RTT samples using a mean
	// variation. See https://www.rfc-editor.org/rfc/rfc9002#section-5.3
	MeanDeviation time.Duration

	// BytesSent is the number of bytes sent on the underlying connection,
	// including retransmissions. Does not include UDP or any other outer
	// framing.
	BytesSent uint64
	// PacketsSent is the number of packets sent on the underlying connection,
	// including those that are determined to have been lost.
	PacketsSent uint64
	// BytesReceived is the number of total bytes received on the underlying
	// connection, including duplicate data for streams. Does not include UDP or
	// any other outer framing.
	BytesReceived uint64
	// PacketsReceived is the number of total packets received on the underlying
	// connection, including packets that were not processable.
	PacketsReceived uint64
	// BytesLost is the number of bytes lost on the underlying connection (does
	// not monotonically increase, because packets that are declared lost can
	// subsequently be received). Does not include UDP or any other outer
	// framing.
	BytesLost uint64
	// PacketsLost is the number of packets lost on the underlying connection
	// (does not monotonically increase, because packets that are declared lost
	// can subsequently be received).
	PacketsLost uint64
}

func (c *Conn) ConnectionStats() ConnectionStats {
	// With IETF Multipath QUIC, the RTT statistics are those of the primary path.
	rttStats := c.primaryRTTStats()
	return ConnectionStats{
		MinRTT:        rttStats.MinRTT(),
		LatestRTT:     rttStats.LatestRTT(),
		SmoothedRTT:   rttStats.SmoothedRTT(),
		MeanDeviation: rttStats.MeanDeviation(),

		BytesSent:       c.connStats.BytesSent.Load(),
		PacketsSent:     c.connStats.PacketsSent.Load(),
		BytesReceived:   c.connStats.BytesReceived.Load(),
		PacketsReceived: c.connStats.PacketsReceived.Load(),
		BytesLost:       c.connStats.BytesLost.Load(),
		PacketsLost:     c.connStats.PacketsLost.Load(),
	}
}

// Time when the connection should time out
func (c *Conn) nextIdleTimeoutTime() monotime.Time {
	idleTimeout := max(c.idleTimeout, c.maxPTO(true)*3)
	return c.idleTimeoutStartTime().Add(idleTimeout)
}

// Time when the next keep-alive packet should be sent.
// It returns a zero time if no keep-alive should be sent.
func (c *Conn) nextKeepAliveTime() monotime.Time {
	if c.config.KeepAlivePeriod == 0 || c.keepAlivePingSent {
		return 0
	}
	keepAliveInterval := max(c.keepAliveInterval, c.maxPTO(true)*3/2)
	return c.lastPacketReceivedTime.Add(keepAliveInterval)
}

func (c *Conn) maybeResetTimer() {
	var deadline monotime.Time
	if !c.handshakeComplete {
		deadline = c.creationTime.Add(c.config.handshakeTimeout())
		if t := c.idleTimeoutStartTime().Add(c.config.HandshakeIdleTimeout); t.Before(deadline) {
			deadline = t
		}
	} else {
		// A keep-alive packet is ack-eliciting, so it can only be sent if the connection is
		// neither congestion limited nor hard-blocked.
		if c.blocked != blockModeNone {
			deadline = c.nextIdleTimeoutTime()
		} else {
			if keepAliveTime := c.nextKeepAliveTime(); !keepAliveTime.IsZero() {
				deadline = keepAliveTime
			} else {
				deadline = c.nextIdleTimeoutTime()
			}
		}
	}
	// Path validation packets are not limited by congestion control.
	if c.mp != nil {
		if t := c.mp.nextTimeout(); !t.IsZero() && t.Before(deadline) {
			deadline = t
		}
	}
	if t := c.prefAddrMigration.timeout(); !t.IsZero() && t.Before(deadline) {
		deadline = t
	}
	// If the connection is hard-blocked, we can't even send acknowledgments,
	// nor can we send PTO probe packets.
	if c.blocked == blockModeHardBlocked {
		c.timer.Reset(monotime.Until(deadline))
		return
	}

	if t := c.receivedPacketHandler.GetAlarmTimeout(); !t.IsZero() && t.Before(deadline) {
		deadline = t
	}
	if t := c.sentPacketHandler.GetLossDetectionTimeout(); !t.IsZero() && t.Before(deadline) {
		deadline = t
	}
	if c.blocked == blockModeCongestionLimited {
		c.timer.Reset(monotime.Until(deadline))
		return
	}

	if !c.pacingDeadline.IsZero() && c.pacingDeadline.Before(deadline) {
		deadline = c.pacingDeadline
	}
	c.timer.Reset(monotime.Until(deadline))
}

func (c *Conn) idleTimeoutStartTime() monotime.Time {
	startTime := c.lastPacketReceivedTime
	if t := c.firstAckElicitingPacketAfterIdleSentTime; !t.IsZero() && t.After(startTime) {
		startTime = t
	}
	return startTime
}

func (c *Conn) switchToNewPath(tr *Transport, id pathID, now monotime.Time) {
	// The client sends from a new local address, using the connection ID it used for probing the path,
	// which wasn't used on any other path. The connection ID used so far is retired (section 9.5 of RFC 9000).
	// If the path was used before, the connection ID used for probing it was retired when the client switched to
	// another path, and a new one is used. The switch is delayed until one is available, see HasConnIDForPath.
	if !c.connIDManager.UseConnIDForPath(id, invalidPathID) {
		if _, ok := c.connIDManager.GetConnIDForPath(id); ok {
			c.connIDManager.UseConnIDForPath(id, invalidPathID)
		}
	}
	initialPacketSize := protocol.ByteCount(c.config.InitialPacketSize)
	c.sentPacketHandler.MigratedPath(now, initialPacketSize)
	maxPacketSize := protocol.ByteCount(protocol.MaxPacketBufferSize)
	if c.peerParams.MaxUDPPayloadSize > 0 && c.peerParams.MaxUDPPayloadSize < maxPacketSize {
		maxPacketSize = c.peerParams.MaxUDPPayloadSize
	}
	c.mtuDiscoverer.Reset(now, initialPacketSize, maxPacketSize)
	c.conn = newSendConn(tr.conn, c.conn.RemoteAddr(), packetInfo{}, utils.DefaultLogger) // TODO: find a better way
	// The new path's connection might not be able to set the ECN bits.
	c.sentPacketHandler.SetECNEnabled(c.conn.capabilities().ECN)
	c.primaryPath.Store(&primaryPath{conn: c.conn, rttStats: c.rttStats})
	c.observedAddrPathSwitched(0, rfc9000ObservationTuple(tr.conn.LocalAddr(), c.conn.RemoteAddr()))
	c.sendQueue.Close()
	c.sendQueue = newSendQueue(c.conn, c.handlePathWriteError)
	go func() {
		if err := c.sendQueue.Run(); err != nil {
			c.destroyImpl(err)
		}
	}()
	// Section 9.6.3 of RFC 9000: the preferred address is validated from the new local address.
	if c.prefAddrMigration.validating() {
		c.startPreferredAddrValidation(now)
	}
}

func (c *Conn) handleHandshakeComplete(now monotime.Time) error {
	defer close(c.handshakeCompleteChan)
	// Once the handshake completes, we have derived 1-RTT keys.
	// There's no point in queueing undecryptable packets for later decryption anymore.
	c.undecryptablePackets = nil

	// The client only switches to a connection ID provided in a NEW_CONNECTION_ID frame once the handshake is
	// confirmed, i.e. once it stopped sending Initial and Handshake packets. Some servers drop long header packets
	// that don't use the connection ID chosen during the handshake.
	if c.perspective == protocol.PerspectiveServer {
		c.connIDManager.SetHandshakeComplete()
	}
	c.connIDGenerator.SetHandshakeComplete(now.Add(3 * c.maxPTO(false)))
	if c.mp != nil {
		if err := c.activateMultipath(); err != nil {
			return err
		}
	}

	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.ALPNInformation{
			ChosenALPN: c.cryptoStreamHandler.ConnectionState().NegotiatedProtocol,
		})
	}

	// The server applies transport parameters right away, but the client side has to wait for handshake completion.
	// During a 0-RTT connection, the client is only allowed to use the new transport parameters for 1-RTT packets.
	if c.perspective == protocol.PerspectiveClient {
		c.applyTransportParameters()
		c.maybeStartAutoPaths()
		return nil
	}

	// All these only apply to the server side.
	if err := c.handleHandshakeConfirmed(now); err != nil {
		return err
	}

	ticket, err := c.cryptoStreamHandler.GetSessionTicket()
	if err != nil {
		return err
	}
	if ticket != nil { // may be nil if session tickets are disabled via tls.Config.SessionTicketsDisabled
		c.oneRTTStream.Write(ticket)
		for c.oneRTTStream.HasData() {
			if cf := c.oneRTTStream.PopCryptoFrame(protocol.MaxPostHandshakeCryptoFrameSize); cf != nil {
				c.queueControlFrame(cf)
			}
		}
	}
	token, err := c.tokenGenerator.NewToken(c.conn.RemoteAddr(), c.rttStats.SmoothedRTT(), c.version)
	if err != nil {
		return err
	}
	c.queueControlFrame(&wire.NewTokenFrame{Token: token})
	if c.mp != nil {
		c.mp.validatedClientAddrs = []net.Addr{c.conn.RemoteAddr()}
	}
	c.queueControlFrame(&wire.HandshakeDoneFrame{})
	c.maybeAdvertiseLocalAddrs()
	return nil
}

func (c *Conn) handleHandshakeConfirmed(now monotime.Time) error {
	// Drop initial keys.
	// On the client side, this should have happened when sending the first Handshake packet,
	// but this is not guaranteed if the server misbehaves.
	// See CVE-2025-59530 for more details.
	c.dropEncryptionLevel(protocol.EncryptionInitial, now)
	c.dropEncryptionLevel(protocol.EncryptionHandshake, now)

	c.handshakeConfirmed = true
	c.cryptoStreamHandler.SetHandshakeConfirmed()
	c.connIDManager.SetHandshakeComplete()

	if !c.config.DisablePathMTUDiscovery && c.conn.capabilities().DF {
		c.mtuDiscoverer.Start(now)
	}
	c.maybeMigrateToPreferredAddr(now)
	c.maybeStartAutoPaths()
	return nil
}

const maxPacketsToProcess = 32

func (c *Conn) handlePackets() (wasProcessed bool, _ error) {
	// Process packets from the receivedPackets queue.
	// Limit the number of packets to process to maxPacketsToProcess,
	// so we eventually get a chance to send out an ACK when receiving a lot of packets.
	c.receivedPacketMx.Lock()

	if c.receivedPackets.Empty() {
		c.receivedPacketMx.Unlock()
		return false, nil
	}

	var hasMorePackets bool
	c.processingStartTime = monotime.Now()
	defer func() { c.processingStartTime = 0 }()
	for range maxPacketsToProcess {
		p := c.receivedPackets.PopFront()
		c.receivedPacketMx.Unlock()

		var datagramPayloadChecksum qlog.DatagramPayloadChecksum
		if c.qlogger != nil && wire.IsLongHeaderPacket(p.data[0]) {
			datagramPayloadChecksum = qlog.CalculateDatagramPayloadChecksum(p.data)
		}
		processed, err := c.handleOnePacket(p, datagramPayloadChecksum)
		if err != nil {
			return false, err
		}
		if processed {
			wasProcessed = true
		}
		c.receivedPacketMx.Lock()
		hasMorePackets = !c.receivedPackets.Empty()
		if !hasMorePackets {
			break
		}
		// Prioritize sending of new CRYPTO data.
		// This is especially relevant when processing 0-RTT packets.
		if !c.handshakeComplete && (c.initialStream.HasData() || c.handshakeStream.HasData()) {
			break
		}
	}
	c.receivedPacketMx.Unlock()

	if hasMorePackets {
		select {
		case c.notifyReceivedPacket <- struct{}{}:
		default:
		}
	}
	return wasProcessed, nil
}

// ackTime returns the time that the ACK Delay of the acknowledgment of a packet received at rcvTime is measured from.
// Only delays that the endpoint controls are included (section 13.2.5 of RFC 9000). The time that the packet spent
// in the queue of received packets, before the connection started processing it, is part of the path's RTT.
// For packets that were queued because their keys weren't available yet, the buffering delay is included,
// since it can be large and is likely to be non-repeating.
func (c *Conn) ackTime(rcvTime monotime.Time) monotime.Time {
	if c.processingStartTime.After(rcvTime) {
		return c.processingStartTime
	}
	return rcvTime
}

func (c *Conn) handleOnePacket(rp receivedPacket, datagramPayloadChecksum qlog.DatagramPayloadChecksum) (wasProcessed bool, _ error) {
	// A client discards packets from unknown server addresses (section 9 of RFC 9000).
	// With IETF Multipath QUIC, every path has its own server address, see multipathReceivePathID.
	if c.perspective == protocol.PerspectiveClient && len(rp.data) > 0 &&
		(c.mp == nil || !c.mp.active || wire.IsLongHeaderPacket(rp.data[0])) &&
		!c.isKnownServerAddr0(rp.remoteAddr) {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Raw:                     qlog.RawInfo{Length: int(rp.Size())},
				DatagramPayloadChecksum: datagramPayloadChecksum,
				Trigger:                 qlog.PacketDropUnexpectedPacket,
			})
		}
		c.logger.Debugf("Dropping packet (%d bytes) from unknown server address %s.", rp.Size(), rp.remoteAddr)
		rp.buffer.Decrement()
		rp.buffer.MaybeRelease()
		return false, nil
	}
	// With IETF Multipath QUIC, the bytes of a datagram starting with a 1-RTT packet count for the path
	// that the packet was received on, see handleShortHeaderPacket.
	if c.mp == nil || len(rp.data) == 0 || wire.IsLongHeaderPacket(rp.data[0]) {
		c.sentPacketHandler.ReceivedBytes(rp.Size(), rp.rcvTime)
	}
	if c.primaryLocalIP == nil && rp.info.addr.IsValid() && !c.handshakeComplete {
		c.primaryLocalIP = rp.info.addr.Unmap().AsSlice()
	}

	if wire.IsVersionNegotiationPacket(rp.data) {
		return false, c.handleVersionNegotiationPacket(rp)
	}

	var counter uint8
	var lastConnID protocol.ConnectionID
	data := rp.data
	p := rp
	for len(data) > 0 {
		if counter > 0 {
			p = *p.Clone()
			p.data = data

			destConnID, err := wire.ParseConnectionID(p.data, c.srcConnIDLen)
			if err != nil {
				if c.qlogger != nil {
					c.qlogger.RecordEvent(qlog.PacketDropped{
						Raw:                     qlog.RawInfo{Length: len(data)},
						DatagramPayloadChecksum: datagramPayloadChecksum,
						Trigger:                 qlog.PacketDropHeaderParseError,
					})
				}
				c.logger.Debugf("error parsing packet, couldn't parse connection ID: %s", err)
				break
			}
			if destConnID != lastConnID {
				if c.qlogger != nil {
					c.qlogger.RecordEvent(qlog.PacketDropped{
						Header:                  qlog.PacketHeader{DestConnectionID: destConnID},
						Raw:                     qlog.RawInfo{Length: len(data)},
						DatagramPayloadChecksum: datagramPayloadChecksum,
						Trigger:                 qlog.PacketDropUnknownConnectionID,
					})
				}
				c.logger.Debugf("coalesced packet has different destination connection ID: %s, expected %s", destConnID, lastConnID)
				break
			}
		}

		if wire.IsLongHeaderPacket(p.data[0]) {
			parsePacket := wire.ParsePacket
			if c.config.EnableQUICBitGreasing {
				parsePacket = wire.ParsePacketWithGreasedQUICBit
			}
			hdr, packetData, rest, err := parsePacket(p.data)
			if err != nil {
				if c.qlogger != nil {
					if err == wire.ErrUnsupportedVersion {
						c.qlogger.RecordEvent(qlog.PacketDropped{
							Header:                  qlog.PacketHeader{Version: hdr.Version},
							Raw:                     qlog.RawInfo{Length: len(data)},
							DatagramPayloadChecksum: datagramPayloadChecksum,
							Trigger:                 qlog.PacketDropUnsupportedVersion,
						})
					} else {
						c.qlogger.RecordEvent(qlog.PacketDropped{
							Raw:                     qlog.RawInfo{Length: len(data)},
							DatagramPayloadChecksum: datagramPayloadChecksum,
							Trigger:                 qlog.PacketDropHeaderParseError,
						})
					}
				}
				c.logger.Debugf("error parsing packet: %s", err)
				break
			}
			lastConnID = hdr.DestConnectionID

			if !c.acceptsVersion(hdr) {
				if c.qlogger != nil {
					c.qlogger.RecordEvent(qlog.PacketDropped{
						Raw:                     qlog.RawInfo{Length: len(data)},
						DatagramPayloadChecksum: datagramPayloadChecksum,
						Trigger:                 qlog.PacketDropUnexpectedVersion,
					})
				}
				c.logger.Debugf("Dropping packet with version %x. Expected %x.", hdr.Version, c.version)
				break
			}

			if counter > 0 {
				p.buffer.Split()
			}
			counter++

			// only log if this actually a coalesced packet
			if c.logger.Debug() && (counter > 1 || len(rest) > 0) {
				c.logger.Debugf("Parsed a coalesced packet. Part %d: %d bytes. Remaining: %d bytes.", counter, len(packetData), len(rest))
			}

			p.data = packetData

			processed, err := c.handleLongHeaderPacket(p, hdr, datagramPayloadChecksum)
			if err != nil {
				return false, err
			}
			if processed {
				wasProcessed = true
			}
			data = rest
		} else {
			if counter > 0 {
				p.buffer.Split()
			}
			processed, err := c.handleShortHeaderPacket(p, counter > 0, datagramPayloadChecksum)
			if err != nil {
				return false, err
			}
			if processed {
				wasProcessed = true
			}
			break
		}
	}

	// Stateless resets are sent as short header packets (see handleShortHeaderPacket), but any datagram ending in
	// a valid stateless reset token is a stateless reset, since other QUIC versions might use a long header
	// (section 10.3 of RFC 9000). The check is skipped if a packet of the datagram was processed (section 10.3.1).
	if !wasProcessed && len(rp.data) >= protocol.MinReceivedStatelessResetSize && wire.IsLongHeaderPacket(rp.data[0]) {
		if c.peerConnIDs.IsActiveStatelessResetToken(protocol.StatelessResetToken(rp.data[len(rp.data)-16:])) {
			p.buffer.MaybeRelease()
			return false, &StatelessResetError{}
		}
	}

	if wasProcessed && c.perspective == protocol.PerspectiveClient && c.unspecifiedServerAddr == nil {
		if addr, ok := c.peerHandshakeAddr.(*net.UDPAddr); ok && addr.IP.IsUnspecified() {
			c.unspecifiedServerAddr = rp.remoteAddr
		}
	}
	p.buffer.MaybeRelease()
	c.blocked = blockModeNone
	return wasProcessed, nil
}

func (c *Conn) handleShortHeaderPacket(
	p receivedPacket,
	isCoalesced bool,
	datagramPayloadChecksum qlog.DatagramPayloadChecksum, // only for logging
) (wasProcessed bool, _ error) {
	var wasQueued bool

	defer func() {
		// Put back the packet buffer if the packet wasn't queued for later decryption.
		if !wasQueued {
			p.buffer.Decrement()
		}
	}()

	// With IETF Multipath QUIC, the bytes received count for the path of the packet,
	// which is only known once the destination connection ID was parsed.
	countBytes := c.mp != nil && !isCoalesced
	destConnID, err := wire.ParseConnectionID(p.data, c.srcConnIDLen)
	if err != nil {
		if countBytes {
			c.sentPacketHandler.ReceivedBytes(p.Size(), p.rcvTime)
		}
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:   qlog.PacketType1RTT,
					PacketNumber: protocol.InvalidPacketNumber,
				},
				Raw:                     qlog.RawInfo{Length: len(p.data)},
				DatagramPayloadChecksum: datagramPayloadChecksum,
				Trigger:                 qlog.PacketDropHeaderParseError,
			})
		}
		return false, nil
	}
	// With IETF Multipath QUIC, the destination connection ID determines the path.
	// Without it, this is always path 0.
	var mpPathID protocol.PathID
	var newPath bool
	if c.mp != nil {
		var dropReason qlog.PacketDropReason
		mpPathID, newPath, dropReason = c.multipathReceivePathID(destConnID, p.remoteAddr)
		if countBytes {
			switch {
			case newPath:
				// The path is created after the packet was decrypted.
			case dropReason != "" || mpPathID == 0:
				c.sentPacketHandler.ReceivedBytes(p.Size(), p.rcvTime)
			case !pathUsesAddrs(c.pathSendConn(c.mp.paths[mpPathID]), p.remoteAddr, p.info):
				// Only datagrams received from the path's peer address increase the anti-amplification limit
				// for sending to that address (section 8 of RFC 9000).
				// Datagrams received from other 4-tuples only count for the connection statistics.
				c.sentPacketHandler.ReceivedBytes(p.Size(), p.rcvTime)
			default:
				c.sentPacketHandler.ReceivedBytesForPath(mpPathID, p.Size(), p.rcvTime)
			}
		}
		if dropReason != "" {
			if c.qlogger != nil {
				c.qlogger.RecordEvent(qlog.PacketDropped{
					Header: qlog.PacketHeader{
						PacketType:       qlog.PacketType1RTT,
						DestConnectionID: destConnID,
						PacketNumber:     protocol.InvalidPacketNumber,
					},
					Raw:                     qlog.RawInfo{Length: len(p.data)},
					DatagramPayloadChecksum: datagramPayloadChecksum,
					Trigger:                 dropReason,
				})
			}
			c.logger.Debugf("Dropping 1-RTT packet (%d bytes) with destination connection ID %s from %s: %s", p.Size(), destConnID, p.remoteAddr, dropReason)
			return false, nil
		}
	}
	pn, pnLen, keyPhase, data, err := c.unpacker.UnpackShortHeader(p.rcvTime, p.data, mpPathID)
	if err != nil {
		// Stateless reset packets (see RFC 9000, section 10.3):
		// * fill the entire UDP datagram (i.e. they cannot be part of a coalesced packet)
		// * are short header packets (first bit is 0)
		// * have the QUIC bit set (second bit is 1), unless the peer can grease it (RFC 9287)
		// * are at least 21 bytes long
		if !isCoalesced && len(p.data) >= protocol.MinReceivedStatelessResetSize && c.isPotentialStatelessReset(p.data[0]) {
			token := protocol.StatelessResetToken(p.data[len(p.data)-16:])
			if c.peerConnIDs.IsActiveStatelessResetToken(token) {
				return false, &StatelessResetError{}
			}
		}
		// No state is created for a new path if the packet can't be decrypted.
		if newPath {
			c.sentPacketHandler.ReceivedBytes(p.Size(), p.rcvTime)
		}
		wasQueued, err = c.handleUnpackError(err, p, qlog.PacketType1RTT, datagramPayloadChecksum)
		return false, err
	}
	if newPath {
		c.newServerPath(mpPathID, p)
		c.sentPacketHandler.ReceivedBytesForPath(mpPathID, p.Size(), p.rcvTime)
	}
	// Section 9.6.2 of RFC 9000: once the connection migrated to the server's preferred address,
	// packets received on the original address are dropped.
	if c.prefAddr.dropsPacket(mpPathID, p.info) {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketType1RTT,
					DestConnectionID: destConnID,
					PacketNumber:     pn,
				},
				Raw:                     qlog.RawInfo{Length: int(p.Size())},
				DatagramPayloadChecksum: datagramPayloadChecksum,
				Trigger:                 qlog.PacketDropUnexpectedPacket,
			})
		}
		c.logger.Debugf("Dropping packet %d received on the original address after migrating to the preferred address.", pn)
		return false, nil
	}
	// RFC 9000 connection migration only applies to path 0.
	if mpPathID == 0 {
		c.largestRcvdAppData = max(c.largestRcvdAppData, pn)
	}
	if c.mp != nil {
		c.mp.lastRcvdPathID = mpPathID
		if path := c.mp.paths[mpPathID]; pn > path.largestRcvdPN {
			path.largestRcvdPN = pn
		}
	}

	if c.logger.Debug() {
		c.logger.Debugf("<- Reading packet %d (%d bytes) for connection %s, 1-RTT", pn, p.Size(), destConnID)
		wire.LogShortHeader(c.logger, destConnID, pn, pnLen, keyPhase)
	}

	if c.receivedPacketHandler.IsPotentiallyDuplicate(pn, protocol.Encryption1RTT, mpPathID) {
		c.logger.Debugf("Dropping (potentially) duplicate packet.")
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:   qlog.PacketType1RTT,
					PacketNumber: pn,
				},
				Raw:                     qlog.RawInfo{Length: int(p.Size())},
				DatagramPayloadChecksum: datagramPayloadChecksum,
				Trigger:                 qlog.PacketDropDuplicate,
			})
		}
		return false, nil
	}

	var log func([]qlog.Frame)
	if c.qlogger != nil {
		log = func(frames []qlog.Frame) {
			c.qlogger.RecordEvent(qlog.PacketReceived{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketType1RTT,
					DestConnectionID: destConnID,
					PacketNumber:     pn,
					KeyPhaseBit:      keyPhase,
					PathID:           mpPathID,
					HasPathID:        c.mp != nil && c.mp.active,
				},
				Raw: qlog.RawInfo{
					Length:        int(p.Size()),
					PayloadLength: int(p.Size() - wire.ShortHeaderLen(destConnID, pnLen)),
				},
				DatagramPayloadChecksum: datagramPayloadChecksum,
				Frames:                  frames,
				ECN:                     toQlogECN(p.ecn),
			})
		}
	}
	// The server validates the path from its preferred address, while the client validates it (client only).
	// Processing the packet might complete the client's validation.
	fromPreferredAddr := c.prefAddrMigration.isProbePath(mpPathID, p.remoteAddr)
	isNonProbing, pathChallenges, err := c.handleUnpackedShortHeaderPacket(destConnID, pn, data, p.ecn, p.rcvTime, log, mpPathID)
	if err != nil {
		return false, err
	}
	if fromPreferredAddr {
		return true, c.respondOnPreferredAddrPath(pathChallenges, p.rcvTime)
	}
	// With IETF Multipath QUIC, every path migrates on its own (section 3.1.2 of draft-ietf-quic-multipath-21).
	if c.mp != nil && c.mp.active {
		return true, c.handleMultipathPacketOnPath(c.mp.paths[mpPathID], p, pn, isNonProbing, pathChallenges)
	}
	// In RFC 9000, only the client can migrate between paths.
	if c.perspective == protocol.PerspectiveClient {
		// A PATH_CHALLENGE received on a path that the client probes is answered on that path.
		if ok, err := c.respondOnProbedPath(p, pathChallenges); ok || err != nil {
			return true, err
		}
		c.queuePathResponses(mpPathID, pathChallenges)
		return true, nil
	}
	// A server that sent a preferred address distinguishes the paths from the preferred address.
	local := c.prefAddr.localAddr(p.info)
	if addrsEqual(p.remoteAddr, c.RemoteAddr()) && local == c.prefAddr.currentLocalAddr() {
		// The client validates the current path (see section 8.2 of RFC 9000).
		c.queuePathResponses(mpPathID, pathChallenges)
		return true, nil
	}
	if c.pathManager == nil {
		c.pathManager = newPathManager(
			c.connIDManager.GetConnIDForPath,
			c.connIDManager.RetireConnIDForPath,
			func() time.Duration { return c.rttStats.PTO(true) },
			c.logger,
		)
	}
	// RFC 9000 connection migration sends the PATH_RESPONSE frames in probe packets right away.
	// The anti-amplification limit applies until the client's address is validated (section 8 of RFC 9000):
	// the packets sent in response to this datagram share 3 times its size.
	// Once the address is validated, a datagram of at least 1200 bytes can be sent (section 8.2.2 of RFC 9000).
	// The limit still applies to larger datagrams: the address might have been validated a while ago, e.g. that of
	// the previous path, and might be spoofed by an attacker now.
	budget := amplificationFactor * p.Size()
	if c.pathManager.AddrValidated(p.remoteAddr, local) {
		budget = max(budget, protocol.MinInitialPacketSize)
	}
	var shouldSwitchPath bool
	var probeConnID protocol.ConnectionID
	var frames []ackhandler.Frame
	for i := 0; i == 0 || i < len(pathChallenges); i++ {
		var pathChallenge *wire.PathChallengeFrame
		if i < len(pathChallenges) {
			pathChallenge = pathChallenges[i]
		}
		connID, fs, switchPath := c.pathManager.HandlePacketOnLocalAddr(p.remoteAddr, local, p.info, p.rcvTime, pathChallenge, isNonProbing)
		shouldSwitchPath = shouldSwitchPath || switchPath
		if len(fs) > 0 {
			probeConnID = connID
			frames = append(frames, fs...)
		}
	}
	if len(frames) > 0 {
		frames = c.observedAddrProbeFrame(frames, 0, rfc9000ObservationTuple(nil, p.remoteAddr))
		if err := c.sendPathProbes(probeConnID, frames, p.remoteAddr, p.info, budget, p.rcvTime, datagramPayloadChecksum); err != nil {
			return true, err
		}
	}
	// We only switch paths in response to the highest-numbered non-probing packet,
	// see section 9.3 of RFC 9000.
	if !shouldSwitchPath || pn != c.largestRcvdAppData {
		return true, nil
	}
	prevAddr, prevLocal, prevInfo := c.conn.RemoteAddr(), c.prefAddr.currentLocalAddr(), sendConnInfo(c.conn)
	id, ok := c.pathManager.SwitchToPathOnLocalAddr(p.remoteAddr, local)
	prevID := invalidPathID
	if c.prefAddr.isMigration(mpPathID, p.info) {
		// Packets received on the original address are dropped (section 9.6.2 of RFC 9000),
		// so the previous path is not validated.
		c.prefAddr.migrated(local)
		c.logger.Debugf("Migrated to the preferred address %s.", local)
	} else {
		// Section 9.3.3 of RFC 9000: the previously active path is validated.
		// This defends against an attacker that forwards packets from another address:
		// a non-probing packet received on the previous path switches the connection back.
		prevID = c.pathManager.AddPreviousPath(prevAddr, prevLocal, prevInfo, p.rcvTime)
	}
	// The connection ID used to validate the path was only used towards the new address (section 9.5 of RFC 9000).
	// The connection uses it from now on. The connection ID used so far is used to validate the previous path,
	// or retired if the previous path is not validated.
	if ok {
		c.connIDManager.UseConnIDForPath(id, prevID)
	}
	c.observedAddrPathSwitched(0, rfc9000ObservationTuple(nil, p.remoteAddr))
	c.sentPacketHandler.MigratedPath(p.rcvTime, protocol.ByteCount(c.config.InitialPacketSize))
	maxPacketSize := protocol.ByteCount(protocol.MaxPacketBufferSize)
	if c.peerParams.MaxUDPPayloadSize > 0 && c.peerParams.MaxUDPPayloadSize < maxPacketSize {
		maxPacketSize = c.peerParams.MaxUDPPayloadSize
	}
	c.mtuDiscoverer.Reset(
		p.rcvTime,
		protocol.ByteCount(c.config.InitialPacketSize),
		maxPacketSize,
	)
	c.conn.ChangeRemoteAddr(p.remoteAddr, p.info)
	return true, nil
}

// respondOnProbedPath answers PATH_CHALLENGE frames received on a path that isn't the active path (client only,
// RFC 9000 connection migration): a path added with AddPath, or the path used for the handshake, after the client
// switched away from it. The PATH_RESPONSE frames are sent on that path, i.e. from its Transport, using a connection ID
// not used on any other path (sections 8.2.2 and 9.5 of RFC 9000). If no such connection ID is available,
// the PATH_CHALLENGE frames are not answered.
// It returns false if the packet wasn't received on such a path.
func (c *Conn) respondOnProbedPath(p receivedPacket, challenges []*wire.PathChallengeFrame) (bool, error) {
	if len(challenges) == 0 || p.transport == nil {
		return false, nil
	}
	pm := c.pathManagerOutgoing.Load()
	if pm == nil {
		return false, nil
	}
	connID, isInactive, ok := pm.InactivePathConnID(p.transport)
	if !isInactive {
		return false, nil
	}
	if !ok {
		c.logger.Debugf("Not answering PATH_CHALLENGE frames on path from %s: no connection ID available.", p.transport.conn.LocalAddr())
		return true, nil
	}
	frames := make([]ackhandler.Frame, 0, len(challenges))
	for _, ch := range challenges {
		frames = append(frames, ackhandler.Frame{Frame: &wire.PathResponseFrame{Data: ch.Data}, Handler: emptyHandler{}})
	}
	probe, buf, err := c.packer.PackPathProbePacket(connID, frames, protocol.MinInitialPacketSize, c.version, 0)
	if err != nil {
		if err == errNothingToPack {
			c.logger.Debugf("Not answering PATH_CHALLENGE frames on path from %s: frames too large.", p.transport.conn.LocalAddr())
			return true, nil
		}
		return true, err
	}
	if c.logger.Debug() {
		c.logger.Debugf("sending path probe packet from %s", p.transport.conn.LocalAddr())
	}
	c.logShortHeaderPacket(probe, protocol.ECNNon, buf.Len())
	c.registerPackedShortHeaderPacket(probe, protocol.ECNNon, p.rcvTime)
	// Failing to send the packet (e.g. because the network is unreachable) doesn't close the connection.
	if _, err := p.transport.WriteTo(buf.Data, p.remoteAddr); err != nil {
		c.logger.Debugf("failed to send path probe packet: %s", err)
	}
	buf.Release()
	return true, nil
}

// isKnownServerAddr0 says if the client accepts packets from a server address on the path used for the handshake
// (section 9 of RFC 9000): the address that the client sent the handshake to, and the server's preferred address,
// once the client started validating it (section 9.6 of RFC 9000).
// If the client dialed an unspecified IP address, the address of the server is learned from the first packet.
// Only UDP addresses are compared. A net.PacketConn that reports other types of addresses might not report the
// address that the client sends to, so these packets are accepted.
func (c *Conn) isKnownServerAddr0(addr net.Addr) bool {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr == nil {
		return true
	}
	handshakeAddr, ok := c.peerHandshakeAddr.(*net.UDPAddr)
	if !ok || addrsEqual(udpAddr, handshakeAddr) {
		return true
	}
	// If the client dialed an unspecified IP address, the server address is not known in advance.
	// Packets from the dialed port are accepted until the first packet was processed, and from then on only
	// packets from the address that packet was received from.
	if handshakeAddr.IP.IsUnspecified() {
		if c.unspecifiedServerAddr == nil {
			return udpAddr.Port == handshakeAddr.Port
		}
		if addrsEqual(udpAddr, c.unspecifiedServerAddr) {
			return true
		}
	}
	if m := c.prefAddrMigration; m != nil && m.state != preferredAddrPending && addrsEqual(udpAddr, m.addr) {
		return true
	}
	return false
}

// sendPathProbes sends PATH_CHALLENGE, PATH_RESPONSE and OBSERVED_ADDRESS frames to a client address in probe packets
// (server only, RFC 9000 connection migration). All frames are sent in a single packet, unless they don't fit.
// The packets sent share the budget of the anti-amplification limit.
// Frames that can't be sent are dropped: the path is validated once the next packet is received on it.
func (c *Conn) sendPathProbes(
	connID protocol.ConnectionID,
	frames []ackhandler.Frame,
	remoteAddr net.Addr,
	info packetInfo,
	budget protocol.ByteCount,
	now monotime.Time,
	datagramPayloadChecksum qlog.DatagramPayloadChecksum, // only for logging
) error {
	for len(frames) > 0 {
		n := len(frames)
		for {
			sent, ok, err := c.sendPathProbe(connID, frames[:n], remoteAddr, info, budget, now, datagramPayloadChecksum)
			if err != nil {
				return err
			}
			if ok {
				budget -= sent
				break
			}
			if n == 1 {
				pathProbeFramesNotSent(frames)
				return nil
			}
			n = (n + 1) / 2
		}
		frames = frames[n:]
	}
	return nil
}

// pathProbeFramesNotSent is called for frames that couldn't be sent in a probe packet.
func pathProbeFramesNotSent(frames []ackhandler.Frame) {
	for _, f := range frames {
		switch f.Frame.(type) {
		case *wire.PathChallengeFrame, *wire.ObservedAddressFrame:
			f.Handler.OnLost(f.Frame)
		}
	}
}

// sendPathProbe sends a packet with PATH_CHALLENGE and PATH_RESPONSE frames to a client address
// (server only, RFC 9000 connection migration). The datagram is expanded to 1200 bytes, unless the budget of the
// anti-amplification limit doesn't allow this (sections 8.2.1 and 8.2.2 of RFC 9000).
// It returns the size of the packet sent, and false if the frames don't fit into a packet.
func (c *Conn) sendPathProbe(
	connID protocol.ConnectionID,
	frames []ackhandler.Frame,
	remoteAddr net.Addr,
	info packetInfo,
	budget protocol.ByteCount,
	now monotime.Time,
	datagramPayloadChecksum qlog.DatagramPayloadChecksum, // only for logging
) (_ protocol.ByteCount, ok bool, _ error) {
	probe, buf, err := c.packer.PackPathProbePacket(connID, frames, min(budget, protocol.MinInitialPacketSize), c.version, 0)
	if err != nil {
		if err != errNothingToPack {
			return 0, false, err
		}
		return 0, false, nil
	}
	if probe.Length < protocol.MinInitialPacketSize {
		for _, f := range frames {
			if f, ok := f.Frame.(*wire.PathChallengeFrame); ok {
				c.pathManager.ChallengeNotExpanded(f.Data)
			}
		}
	}
	c.logger.Debugf("sending path probe packet to %s", remoteAddr)
	// ECN is not used on unvalidated paths.
	ecn := c.sentPacketHandler.ECNMode(false)
	c.logShortHeaderPacketWithDatagramPayloadChecksum(probe, ecn, buf.Len(), false, datagramPayloadChecksum)
	c.registerPackedShortHeaderPacket(probe, ecn, now)
	c.sendQueue.SendProbe(buf, remoteAddr, info)
	return probe.Length, true, nil
}

// sendDuePathChallenges sends the PATH_CHALLENGE frames that are due on paths whose client address was validated
// (server only, RFC 9000 connection migration): the second PATH_CHALLENGE that validates the path MTU, and the
// PATH_CHALLENGE that validates the previously active path after the client migrated.
func (c *Conn) sendDuePathChallenges(now monotime.Time) error {
	if c.pathManager == nil {
		return nil
	}
	for {
		connID, addr, info, f, ok := c.pathManager.PopDueChallenge(now)
		if !ok {
			return nil
		}
		if err := c.sendPathProbes(connID, []ackhandler.Frame{f}, addr, info, protocol.MaxByteCount, now, 0); err != nil {
			return err
		}
	}
}

func (c *Conn) handleLongHeaderPacket(p receivedPacket, hdr *wire.Header, datagramPayloadChecksum qlog.DatagramPayloadChecksum) (wasProcessed bool, _ error) {
	var wasQueued bool

	defer func() {
		// Put back the packet buffer if the packet wasn't queued for later decryption.
		if !wasQueued {
			p.buffer.Decrement()
		}
	}()

	if hdr.Type == protocol.PacketTypeRetry {
		return c.handleRetryPacket(hdr, p.data, p.rcvTime), nil
	}

	// The server can change the source connection ID with the first Handshake packet.
	// After this, all packets with a different source connection have to be ignored.
	if c.receivedFirstPacket && hdr.Type == protocol.PacketTypeInitial && hdr.SrcConnectionID != c.handshakeDestConnID {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:   qlog.PacketTypeInitial,
					PacketNumber: protocol.InvalidPacketNumber,
				},
				Raw:                     qlog.RawInfo{Length: int(p.Size())},
				DatagramPayloadChecksum: datagramPayloadChecksum,
				Trigger:                 qlog.PacketDropUnknownConnectionID,
			})
		}
		c.logger.Debugf("Dropping Initial packet (%d bytes) with unexpected source connection ID: %s (expected %s)", p.Size(), hdr.SrcConnectionID, c.handshakeDestConnID)
		return false, nil
	}
	// Initial packets sent by the server never carry a token (section 17.2.2 of RFC 9000).
	if c.perspective == protocol.PerspectiveClient && hdr.Type == protocol.PacketTypeInitial && len(hdr.Token) > 0 {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:   qlog.PacketTypeInitial,
					PacketNumber: protocol.InvalidPacketNumber,
				},
				Raw:                     qlog.RawInfo{Length: int(p.Size())},
				DatagramPayloadChecksum: datagramPayloadChecksum,
				Trigger:                 qlog.PacketDropUnexpectedPacket,
			})
		}
		c.logger.Debugf("Dropping Initial packet (%d bytes) with a token.", p.Size())
		return false, nil
	}
	// drop 0-RTT packets, if we are a client
	if c.perspective == protocol.PerspectiveClient && hdr.Type == protocol.PacketType0RTT {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:   qlog.PacketType0RTT,
					PacketNumber: protocol.InvalidPacketNumber,
				},
				Raw:                     qlog.RawInfo{Length: int(p.Size())},
				DatagramPayloadChecksum: datagramPayloadChecksum,
				Trigger:                 qlog.PacketDropUnexpectedPacket,
			})
		}
		return false, nil
	}

	packet, err := c.unpacker.UnpackLongHeader(hdr, p.data)
	if err != nil {
		wasQueued, err = c.handleUnpackError(err, p, toQlogPacketType(hdr.Type), datagramPayloadChecksum)
		return false, err
	}
	// The client learns the Negotiated Version from the first Initial packet using a different version.
	if c.perspective == protocol.PerspectiveClient && hdr.Version != c.version {
		c.switchVersion(hdr.Version)
	}

	if c.logger.Debug() {
		c.logger.Debugf("<- Reading packet %d (%d bytes) for connection %s, %s", packet.hdr.PacketNumber, p.Size(), hdr.DestConnectionID, packet.encryptionLevel)
		packet.hdr.Log(c.logger)
	}

	if pn := packet.hdr.PacketNumber; c.receivedPacketHandler.IsPotentiallyDuplicate(pn, packet.encryptionLevel, 0) {
		c.logger.Debugf("Dropping (potentially) duplicate packet.")
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       toQlogPacketType(packet.hdr.Type),
					DestConnectionID: hdr.DestConnectionID,
					SrcConnectionID:  hdr.SrcConnectionID,
					PacketNumber:     pn,
					Version:          packet.hdr.Version,
				},
				Raw:                     qlog.RawInfo{Length: int(p.Size()), PayloadLength: int(packet.hdr.Length)},
				DatagramPayloadChecksum: datagramPayloadChecksum,
				Trigger:                 qlog.PacketDropDuplicate,
			})
		}
		return false, nil
	}

	if err := c.handleUnpackedLongHeaderPacket(packet, p.ecn, p.rcvTime, datagramPayloadChecksum, p.Size()); err != nil {
		return false, err
	}
	return true, nil
}

func (c *Conn) handleUnpackError(err error, p receivedPacket, pt qlog.PacketType, datagramPayloadChecksum qlog.DatagramPayloadChecksum) (wasQueued bool, _ error) {
	switch err {
	case handshake.ErrKeysDropped:
		if c.qlogger != nil {
			connID, _ := wire.ParseConnectionID(p.data, c.srcConnIDLen)
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       pt,
					DestConnectionID: connID,
					PacketNumber:     protocol.InvalidPacketNumber,
				},
				Raw:                     qlog.RawInfo{Length: int(p.Size())},
				DatagramPayloadChecksum: datagramPayloadChecksum,
				Trigger:                 qlog.PacketDropKeyUnavailable,
			})
		}
		c.logger.Debugf("Dropping %s packet (%d bytes) because we already dropped the keys.", pt, p.Size())
		return false, nil
	case handshake.ErrUnexpectedVersion:
		if c.qlogger != nil {
			connID, _ := wire.ParseConnectionID(p.data, c.srcConnIDLen)
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       pt,
					DestConnectionID: connID,
					PacketNumber:     protocol.InvalidPacketNumber,
				},
				Raw:                     qlog.RawInfo{Length: int(p.Size())},
				DatagramPayloadChecksum: datagramPayloadChecksum,
				Trigger:                 qlog.PacketDropUnexpectedVersion,
			})
		}
		c.logger.Debugf("Dropping %s packet (%d bytes) with an unexpected version.", pt, p.Size())
		return false, nil
	case handshake.ErrKeysNotYetAvailable:
		// Sealer for this encryption level not yet available.
		// Try again later.
		c.tryQueueingUndecryptablePacket(p, pt, datagramPayloadChecksum)
		return true, nil
	case wire.ErrInvalidReservedBits:
		return false, &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: err.Error(),
		}
	case handshake.ErrDecryptionFailed:
		// This might be a packet injected by an attacker. Drop it.
		if c.qlogger != nil {
			connID, _ := wire.ParseConnectionID(p.data, c.srcConnIDLen)
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       pt,
					DestConnectionID: connID,
					PacketNumber:     protocol.InvalidPacketNumber,
				},
				Raw:                     qlog.RawInfo{Length: int(p.Size())},
				DatagramPayloadChecksum: datagramPayloadChecksum,
				Trigger:                 qlog.PacketDropPayloadDecryptError,
			})
		}
		c.logger.Debugf("Dropping %s packet (%d bytes) that could not be unpacked. Error: %s", pt, p.Size(), err)
		return false, nil
	default:
		if _, ok := errors.AsType[*headerParseError](err); ok {
			// This might be a packet injected by an attacker. Drop it.
			if c.qlogger != nil {
				connID, _ := wire.ParseConnectionID(p.data, c.srcConnIDLen)
				c.qlogger.RecordEvent(qlog.PacketDropped{
					Header: qlog.PacketHeader{
						PacketType:       pt,
						DestConnectionID: connID,
						PacketNumber:     protocol.InvalidPacketNumber,
					},
					Raw:                     qlog.RawInfo{Length: int(p.Size())},
					DatagramPayloadChecksum: datagramPayloadChecksum,
					Trigger:                 qlog.PacketDropHeaderParseError,
				})
			}
			c.logger.Debugf("Dropping %s packet (%d bytes) for which we couldn't unpack the header. Error: %s", pt, p.Size(), err)
			return false, nil
		}
		// This is an error returned by the AEAD (other than ErrDecryptionFailed).
		// For example, a PROTOCOL_VIOLATION due to key updates.
		return false, err
	}
}

func (c *Conn) handleRetryPacket(hdr *wire.Header, data []byte, rcvTime monotime.Time) bool /* was this a valid Retry */ {
	if c.perspective == protocol.PerspectiveServer {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketTypeRetry,
					SrcConnectionID:  hdr.SrcConnectionID,
					DestConnectionID: hdr.DestConnectionID,
					Version:          hdr.Version,
				},
				Raw:     qlog.RawInfo{Length: len(data)},
				Trigger: qlog.PacketDropUnexpectedPacket,
			})
		}
		c.logger.Debugf("Ignoring Retry.")
		return false
	}
	if c.receivedFirstPacket {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketTypeRetry,
					SrcConnectionID:  hdr.SrcConnectionID,
					DestConnectionID: hdr.DestConnectionID,
					Version:          hdr.Version,
				},
				Raw:     qlog.RawInfo{Length: len(data)},
				Trigger: qlog.PacketDropUnexpectedPacket,
			})
		}
		c.logger.Debugf("Ignoring Retry, since we already received a packet.")
		return false
	}
	destConnID := c.connIDManager.Get()
	if hdr.SrcConnectionID == destConnID {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketTypeRetry,
					SrcConnectionID:  hdr.SrcConnectionID,
					DestConnectionID: hdr.DestConnectionID,
					Version:          hdr.Version,
				},
				Raw:     qlog.RawInfo{Length: len(data)},
				Trigger: qlog.PacketDropUnexpectedPacket,
			})
		}
		c.logger.Debugf("Ignoring Retry, since the server didn't change the Source Connection ID.")
		return false
	}
	// If a token is already set, this means that we already received a Retry from the server.
	// Ignore this Retry packet.
	if c.receivedRetry {
		c.logger.Debugf("Ignoring Retry, since a Retry was already received.")
		return false
	}

	tag := handshake.GetRetryIntegrityTag(data[:len(data)-16], destConnID, hdr.Version)
	if !bytes.Equal(data[len(data)-16:], tag[:]) {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketTypeRetry,
					SrcConnectionID:  hdr.SrcConnectionID,
					DestConnectionID: hdr.DestConnectionID,
					Version:          hdr.Version,
				},
				Raw:     qlog.RawInfo{Length: len(data)},
				Trigger: qlog.PacketDropPayloadDecryptError,
			})
		}
		c.logger.Debugf("Ignoring spoofed Retry. Integrity Tag doesn't match.")
		return false
	}

	// The ClientHello sent in response to the Retry carries the initial_max_path_id transport parameter, and can't
	// be changed anymore. Endpoints advertising the parameter must not use zero-length connection IDs
	// (section 2.1 of draft-ietf-quic-multipath-21). The Destination Connection ID of the Retry is our Source
	// Connection ID. The server didn't create any state when sending the Retry, so the connection is closed
	// without sending a CONNECTION_CLOSE.
	if c.advertisedMultipath && !shouldAdvertiseMultipath(c.multipathController, hdr.DestConnectionID, hdr.SrcConnectionID) {
		c.logger.Debugf("Received a Retry with a zero-length Source Connection ID, but advertised multipath support.")
		c.destroyImpl(&qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "Retry with a zero-length connection ID, but multipath was advertised",
		})
		return false
	}

	newDestConnID := hdr.SrcConnectionID
	c.receivedRetry = true
	c.sentPacketHandler.ResetForRetry(rcvTime)
	c.handshakeDestConnID = newDestConnID
	c.retrySrcConnID = &newDestConnID
	c.cryptoStreamHandler.ChangeConnectionID(newDestConnID)
	c.packer.SetToken(hdr.Token)
	c.connIDManager.ChangeInitialConnID(newDestConnID)

	if c.logger.Debug() {
		c.logger.Debugf("<- Received Retry:")
		(&wire.ExtendedHeader{Header: *hdr}).Log(c.logger)
		c.logger.Debugf("Switching destination connection ID to: %s", hdr.SrcConnectionID)
	}
	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.PacketReceived{
			Header: qlog.PacketHeader{
				PacketType:       qlog.PacketTypeRetry,
				DestConnectionID: destConnID,
				SrcConnectionID:  newDestConnID,
				Version:          hdr.Version,
				Token:            &qlog.Token{Raw: hdr.Token},
			},
			Raw: qlog.RawInfo{Length: len(data)},
		})
	}

	c.scheduleSending()
	return true
}

func (c *Conn) handleVersionNegotiationPacket(p receivedPacket) error {
	if c.perspective == protocol.PerspectiveServer || // servers never receive version negotiation packets
		c.receivedFirstPacket || c.versionNegotiated { // ignore delayed / duplicated version negotiation packets
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header:  qlog.PacketHeader{PacketType: qlog.PacketTypeVersionNegotiation},
				Raw:     qlog.RawInfo{Length: int(p.Size())},
				Trigger: qlog.PacketDropUnexpectedPacket,
			})
		}
		return nil
	}

	src, dest, supportedVersions, err := wire.ParseVersionNegotiationPacket(p.data)
	if err != nil {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header:  qlog.PacketHeader{PacketType: qlog.PacketTypeVersionNegotiation},
				Raw:     qlog.RawInfo{Length: int(p.Size())},
				Trigger: qlog.PacketDropHeaderParseError,
			})
		}
		c.logger.Debugf("Error parsing Version Negotiation packet: %s", err)
		return nil
	}

	if slices.Contains(supportedVersions, c.version) {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header:  qlog.PacketHeader{PacketType: qlog.PacketTypeVersionNegotiation},
				Raw:     qlog.RawInfo{Length: int(p.Size())},
				Trigger: qlog.PacketDropUnexpectedVersion,
			})
		}
		// The Version Negotiation packet contains the version that we offered.
		// This might be a packet sent by an attacker, or it was corrupted.
		return nil
	}

	c.logger.Infof("Received a Version Negotiation packet. Supported Versions: %s", supportedVersions)
	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.VersionNegotiationReceived{
			Header: qlog.PacketHeaderVersionNegotiation{
				DestConnectionID: dest,
				SrcConnectionID:  src,
			},
			SupportedVersions: supportedVersions,
		})
	}
	newVersion, ok := protocol.ChooseSupportedVersion(c.config.Versions, supportedVersions)
	if !ok {
		c.destroyImpl(&VersionNegotiationError{
			Ours:   c.config.Versions,
			Theirs: supportedVersions,
		})
		c.logger.Infof("No compatible QUIC version found.")
		return nil
	}
	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.VersionInformation{
			ChosenVersion:  newVersion,
			ClientVersions: c.config.Versions,
			ServerVersions: supportedVersions,
		})
	}

	c.logger.Infof("Switching to QUIC version %s.", newVersion)
	nextPN, _ := c.sentPacketHandler.PeekPacketNumber(0, protocol.EncryptionInitial)
	return &errCloseForRecreating{
		nextPacketNumber: nextPN,
		nextVersion:      newVersion,
	}
}

func (c *Conn) handleUnpackedLongHeaderPacket(
	packet *unpackedPacket,
	ecn protocol.ECN,
	rcvTime monotime.Time,
	datagramPayloadChecksum qlog.DatagramPayloadChecksum, // only for logging
	packetSize protocol.ByteCount, // only for logging
) error {
	if !c.receivedFirstPacket {
		c.receivedFirstPacket = true
		if !c.versionNegotiated && c.qlogger != nil {
			var clientVersions, serverVersions []Version
			switch c.perspective {
			case protocol.PerspectiveClient:
				clientVersions = c.config.Versions
			case protocol.PerspectiveServer:
				serverVersions = c.config.Versions
			}
			c.qlogger.RecordEvent(qlog.VersionInformation{
				ChosenVersion:  c.version,
				ClientVersions: clientVersions,
				ServerVersions: serverVersions,
			})
		}
		// The server can change the source connection ID with the first Handshake packet.
		if c.perspective == protocol.PerspectiveClient && packet.hdr.SrcConnectionID != c.handshakeDestConnID {
			cid := packet.hdr.SrcConnectionID
			c.logger.Debugf("Received first packet. Switching destination connection ID to: %s", cid)
			c.handshakeDestConnID = cid
			c.connIDManager.ChangeInitialConnID(cid)
		}
		// We create the connection as soon as we receive the first packet from the client.
		// We do that before authenticating the packet.
		// That means that if the source connection ID was corrupted,
		// we might have created a connection with an incorrect source connection ID.
		// Once we authenticate the first packet, we need to update it.
		if c.perspective == protocol.PerspectiveServer {
			if packet.hdr.SrcConnectionID != c.handshakeDestConnID {
				c.handshakeDestConnID = packet.hdr.SrcConnectionID
				c.connIDManager.ChangeInitialConnID(packet.hdr.SrcConnectionID)
			}
			if c.qlogger != nil {
				var srcAddr, destAddr *net.UDPAddr
				if addr, ok := c.conn.LocalAddr().(*net.UDPAddr); ok {
					srcAddr = addr
				}
				if addr, ok := c.conn.RemoteAddr().(*net.UDPAddr); ok {
					destAddr = addr
				}
				c.qlogger.RecordEvent(startedConnectionEvent(srcAddr, destAddr))
			}
		}
	}

	if c.perspective == protocol.PerspectiveServer && packet.encryptionLevel == protocol.EncryptionHandshake &&
		!c.droppedInitialKeys {
		// On the server side, Initial keys are dropped as soon as the first Handshake packet is received.
		// See Section 4.9.1 of RFC 9001.
		c.dropEncryptionLevel(protocol.EncryptionInitial, rcvTime)
	}

	c.lastPacketReceivedTime = rcvTime
	c.firstAckElicitingPacketAfterIdleSentTime = 0
	c.keepAlivePingSent = false

	if packet.hdr.Type == protocol.PacketType0RTT {
		c.largestRcvdAppData = max(c.largestRcvdAppData, packet.hdr.PacketNumber)
	}

	var log func([]qlog.Frame)
	if c.qlogger != nil {
		log = func(frames []qlog.Frame) {
			var token *qlog.Token
			if len(packet.hdr.Token) > 0 {
				token = &qlog.Token{Raw: packet.hdr.Token}
			}
			c.qlogger.RecordEvent(qlog.PacketReceived{
				Header: qlog.PacketHeader{
					PacketType:       toQlogPacketType(packet.hdr.Type),
					DestConnectionID: packet.hdr.DestConnectionID,
					SrcConnectionID:  packet.hdr.SrcConnectionID,
					PacketNumber:     packet.hdr.PacketNumber,
					Version:          packet.hdr.Version,
					Token:            token,
				},
				Raw: qlog.RawInfo{
					Length:        int(packetSize),
					PayloadLength: int(packet.hdr.Length),
				},
				DatagramPayloadChecksum: datagramPayloadChecksum,
				Frames:                  frames,
				ECN:                     toQlogECN(ecn),
			})
		}
	}
	isAckEliciting, _, pathChallenges, err := c.handleFrames(packet.data, packet.hdr.DestConnectionID, packet.encryptionLevel, log, rcvTime)
	if err != nil {
		return err
	}
	// PATH_CHALLENGE frames are allowed in 0-RTT packets, which are sent on the path of the handshake.
	c.queuePathResponses(0, pathChallenges)
	c.sentPacketHandler.ReceivedPacket(packet.encryptionLevel, rcvTime)
	return c.receivedPacketHandler.ReceivedPacket(packet.hdr.PacketNumber, ecn, packet.encryptionLevel, c.ackTime(rcvTime), isAckEliciting, 0)
}

func (c *Conn) handleUnpackedShortHeaderPacket(
	destConnID protocol.ConnectionID,
	pn protocol.PacketNumber,
	data []byte,
	ecn protocol.ECN,
	rcvTime monotime.Time,
	log func([]qlog.Frame),
	pathID protocol.PathID,
) (isNonProbing bool, pathChallenges []*wire.PathChallengeFrame, _ error) {
	c.lastPacketReceivedTime = rcvTime
	c.firstAckElicitingPacketAfterIdleSentTime = 0
	c.keepAlivePingSent = false

	isAckEliciting, isNonProbing, pathChallenges, err := c.handleFrames(data, destConnID, protocol.Encryption1RTT, log, rcvTime)
	if err != nil {
		return false, nil, err
	}
	c.sentPacketHandler.ReceivedPacket(protocol.Encryption1RTT, rcvTime)
	if err := c.receivedPacketHandler.ReceivedPacket(pn, ecn, protocol.Encryption1RTT, c.ackTime(rcvTime), isAckEliciting, pathID); err != nil {
		return false, nil, err
	}
	return isNonProbing, pathChallenges, nil
}

// handleFrames parses the frames, one after the other, and handles them.
// It returns the PATH_CHALLENGE frames contained in the packet, in the order they were received.
// The caller is responsible for responding to them.
func (c *Conn) handleFrames(
	data []byte,
	destConnID protocol.ConnectionID,
	encLevel protocol.EncryptionLevel,
	log func([]qlog.Frame),
	rcvTime monotime.Time,
) (isAckEliciting, isNonProbing bool, pathChallenges []*wire.PathChallengeFrame, _ error) {
	// Only used for tracing.
	// If we're not tracing, this slice will always remain empty.
	var frames []qlog.Frame
	if log != nil {
		frames = make([]qlog.Frame, 0, 4)
	}
	handshakeWasComplete := c.handshakeComplete
	var handleErr error
	var skipHandling bool

	for len(data) > 0 {
		frameType, l, err := c.frameParser.ParseType(data, encLevel)
		if err != nil {
			// The frame parser skips over PADDING frames, and returns an io.EOF if the PADDING
			// frames were the last frames in this packet.
			if err == io.EOF {
				break
			}
			return false, false, nil, err
		}
		data = data[l:]

		if !c.frameParser.IsKnownFrameType(frameType) {
			// Frames handled by the extension frame handler are ack-eliciting and non-probing,
			// even if the frame type is reserved for an extension that wasn't negotiated.
			isAckEliciting = true
			isNonProbing = true
			if c.extensionFrameHandler == nil {
				return false, false, nil, &qerr.TransportError{
					ErrorCode:    qerr.FrameEncodingError,
					FrameType:    uint64(frameType),
					ErrorMessage: "unknown frame type",
				}
			}
			n, err := c.extensionFrameHandler.HandleFrame(ExtensionFrameContext{
				FrameType:       uint64(frameType),
				EncryptionLevel: encLevel,
				Version:         c.version,
				Data:            data,
			})
			if err != nil {
				return false, false, nil, err
			}
			if n <= 0 || n > len(data) {
				return false, false, nil, &qerr.TransportError{
					ErrorCode:    qerr.FrameEncodingError,
					FrameType:    uint64(frameType),
					ErrorMessage: "invalid custom frame length",
				}
			}
			data = data[n:]
			continue
		}

		// The frame parser knows the frames of the multipath extension once we advertise the extension.
		// The peer must not send them unless it advertised the extension as well (section 2 of draft-ietf-quic-multipath).
		if frameType.IsMultipathFrameType() && c.mp == nil {
			return false, false, nil, &qerr.TransportError{
				ErrorCode:    qerr.ProtocolViolation,
				FrameType:    uint64(frameType),
				ErrorMessage: "multipath extension not negotiated",
			}
		}

		if ackhandler.IsFrameTypeAckEliciting(frameType) {
			isAckEliciting = true
		}
		if !wire.IsProbingFrameType(frameType) {
			isNonProbing = true
		}

		// We're inlining common cases, to avoid using interfaces
		// Fast path: STREAM, DATAGRAM and ACK
		if frameType.IsStreamFrameType() {
			streamFrame, l, err := c.frameParser.ParseStreamFrame(frameType, data, c.version)
			if err != nil {
				return false, false, nil, err
			}
			data = data[l:]

			if log != nil {
				frames = append(frames, toQlogFrame(streamFrame))
			}
			// an error occurred handling a previous frame, don't handle the current frame
			if skipHandling {
				continue
			}
			wire.LogFrame(c.logger, streamFrame, false)
			handleErr = c.streamsMap.HandleStreamFrame(streamFrame, rcvTime)
		} else if frameType.IsAckFrameType() || frameType.IsPathAckFrameType() {
			ackFrame, l, err := c.frameParser.ParseAckFrame(frameType, data, encLevel, c.version)
			if err != nil {
				return false, false, nil, err
			}
			data = data[l:]
			if log != nil {
				frames = append(frames, toQlogFrame(ackFrame))
			}
			// an error occurred handling a previous frame, don't handle the current frame
			if skipHandling {
				continue
			}
			wire.LogFrame(c.logger, ackFrame, false)
			handleErr = c.handleAckFrame(ackFrame, frameType, encLevel, rcvTime)
		} else if frameType.IsDatagramFrameType() {
			datagramFrame, l, err := c.frameParser.ParseDatagramFrame(frameType, data, c.version)
			if err != nil {
				return false, false, nil, err
			}
			data = data[l:]

			if log != nil {
				frames = append(frames, toQlogFrame(datagramFrame))
			}
			// an error occurred handling a previous frame, don't handle the current frame
			if skipHandling {
				continue
			}
			wire.LogFrame(c.logger, datagramFrame, false)
			handleErr = c.handleDatagramFrame(datagramFrame)
		} else {
			frame, l, err := c.frameParser.ParseLessCommonFrame(frameType, data, c.version)
			if err != nil {
				return false, false, nil, err
			}
			data = data[l:]

			if log != nil {
				frames = append(frames, toQlogFrame(frame))
			}
			// an error occurred handling a previous frame, don't handle the current frame
			if skipHandling {
				continue
			}
			pc, err := c.handleFrame(frame, encLevel, destConnID, rcvTime)
			if pc != nil {
				pathChallenges = append(pathChallenges, pc)
			}
			handleErr = err
		}

		if handleErr != nil {
			// if we're logging, we need to keep parsing (but not handling) all frames
			skipHandling = true
			if log == nil {
				return false, false, nil, handleErr
			}
		}
	}

	if log != nil {
		log(frames)
		if handleErr != nil {
			return false, false, nil, handleErr
		}
	}

	// Handle completion of the handshake after processing all the frames.
	// This ensures that we correctly handle the following case on the server side:
	// We receive a Handshake packet that contains the CRYPTO frame that allows us to complete the handshake,
	// and an ACK serialized after that CRYPTO frame. In this case, we still want to process the ACK frame.
	if !handshakeWasComplete && c.handshakeComplete {
		if err := c.handleHandshakeComplete(rcvTime); err != nil {
			return false, false, nil, err
		}
	}
	return
}

func (c *Conn) handleFrame(
	f wire.Frame,
	encLevel protocol.EncryptionLevel,
	destConnID protocol.ConnectionID,
	rcvTime monotime.Time,
) (pathChallenge *wire.PathChallengeFrame, _ error) {
	var err error
	wire.LogFrame(c.logger, f, false)
	switch frame := f.(type) {
	case *wire.CryptoFrame:
		err = c.handleCryptoFrame(frame, encLevel, rcvTime)
	case *wire.ConnectionCloseFrame:
		err = c.handleConnectionCloseFrame(frame)
	case *wire.ResetStreamFrame:
		err = c.streamsMap.HandleResetStreamFrame(frame, rcvTime)
	case *wire.MaxDataFrame:
		c.connFlowController.UpdateSendWindow(frame.MaximumData)
	case *wire.MaxStreamDataFrame:
		err = c.streamsMap.HandleMaxStreamDataFrame(frame)
	case *wire.MaxStreamsFrame:
		c.streamsMap.HandleMaxStreamsFrame(frame)
	case *wire.DataBlockedFrame:
	case *wire.StreamDataBlockedFrame:
		err = c.streamsMap.HandleStreamDataBlockedFrame(frame)
	case *wire.StreamsBlockedFrame:
	case *wire.StopSendingFrame:
		err = c.streamsMap.HandleStopSendingFrame(frame)
	case *wire.PingFrame:
	case *wire.PathChallengeFrame:
		pathChallenge = frame
	case *wire.PathResponseFrame:
		err = c.handlePathResponseFrame(frame, rcvTime)
	case *wire.NewTokenFrame:
		err = c.handleNewTokenFrame(frame)
	case *wire.NewConnectionIDFrame:
		err = c.peerConnIDs.AddNewConnectionID(frame)
	case *wire.RetireConnectionIDFrame:
		err = c.connIDGenerator.Retire(frame.SequenceNumber, destConnID, rcvTime.Add(3*c.maxPTO(false)))
	case *wire.HandshakeDoneFrame:
		err = c.handleHandshakeDoneFrame(rcvTime)
	case *wire.PathAbandonFrame, *wire.PathStatusFrame, *wire.PathNewConnectionIDFrame, *wire.PathRetireConnectionIDFrame,
		*wire.MaxPathIDFrame, *wire.PathsBlockedFrame, *wire.PathCIDsBlockedFrame:
		if c.mp == nil {
			return nil, &qerr.TransportError{
				ErrorCode:    qerr.ProtocolViolation,
				ErrorMessage: "multipath extension not negotiated",
			}
		}
		err = c.handleMultipathFrame(frame, destConnID, rcvTime)
	case *wire.AddAddressFrame:
		err = c.handleAddAddressFrame(frame)
	case *wire.ObservedAddressFrame:
		// The path of a 0-RTT packet is path 0.
		var pathID protocol.PathID
		if encLevel == protocol.Encryption1RTT && c.mp != nil {
			pathID = c.mp.lastRcvdPathID
		}
		err = c.handleObservedAddressFrame(frame, pathID)
	default:
		err = fmt.Errorf("unexpected frame type: %s", reflect.ValueOf(&frame).Elem().Type().Name())
	}
	return pathChallenge, err
}

// handlePacket is called by the server with a new packet
func (c *Conn) handlePacket(p receivedPacket) {
	c.receivedPacketMx.Lock()
	// Discard packets once the amount of queued packets is larger than
	// the channel size, protocol.MaxConnUnprocessedPackets
	if c.receivedPackets.Len() >= protocol.MaxConnUnprocessedPackets {
		if c.qlogger != nil {
			var datagramPayloadChecksum qlog.DatagramPayloadChecksum
			if wire.IsLongHeaderPacket(p.data[0]) {
				datagramPayloadChecksum = qlog.CalculateDatagramPayloadChecksum(p.data)
			}
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Raw:                     qlog.RawInfo{Length: int(p.Size())},
				DatagramPayloadChecksum: datagramPayloadChecksum,
				Trigger:                 qlog.PacketDropDOSPrevention,
			})
		}
		c.receivedPacketMx.Unlock()
		return
	}
	c.receivedPackets.PushBack(p)
	c.receivedPacketMx.Unlock()

	select {
	case c.notifyReceivedPacket <- struct{}{}:
	default:
	}
}

func (c *Conn) handleConnectionCloseFrame(frame *wire.ConnectionCloseFrame) error {
	if frame.IsApplicationError {
		return &qerr.ApplicationError{
			Remote:       true,
			ErrorCode:    qerr.ApplicationErrorCode(frame.ErrorCode),
			ErrorMessage: frame.ReasonPhrase,
		}
	}
	return &qerr.TransportError{
		Remote:       true,
		ErrorCode:    qerr.TransportErrorCode(frame.ErrorCode),
		FrameType:    frame.FrameType,
		ErrorMessage: frame.ReasonPhrase,
	}
}

func (c *Conn) handleCryptoFrame(frame *wire.CryptoFrame, encLevel protocol.EncryptionLevel, rcvTime monotime.Time) error {
	// A CRYPTO frame sent by the server in an Initial packet indicates the Negotiated Version
	// (section 4.1 of RFC 9369): the server only sends CRYPTO frames using the Negotiated Version.
	if c.perspective == protocol.PerspectiveClient && encLevel == protocol.EncryptionInitial {
		c.knowsNegotiatedVersion = true
	}
	if err := c.cryptoStreamManager.HandleCryptoFrame(frame, encLevel); err != nil {
		return err
	}
	for {
		data := c.cryptoStreamManager.GetCryptoData(encLevel)
		if data == nil {
			break
		}
		if err := c.cryptoStreamHandler.HandleMessage(data, encLevel); err != nil {
			return err
		}
	}
	return c.handleHandshakeEvents(rcvTime)
}

func (c *Conn) handleHandshakeEvents(now monotime.Time) error {
	for {
		ev := c.cryptoStreamHandler.NextEvent()
		var err error
		switch ev.Kind {
		case handshake.EventNoEvent:
			return nil
		case handshake.EventHandshakeComplete:
			// Don't call handleHandshakeComplete yet.
			// It's advantageous to process ACK frames that might be serialized after the CRYPTO frame first.
			c.handshakeComplete = true
		case handshake.EventReceivedTransportParameters:
			err = c.handleTransportParameters(ev.TransportParameters)
		case handshake.EventVersionNegotiated:
			c.setVersion(ev.Version)
		case handshake.EventRestoredTransportParameters:
			c.restoreTransportParameters(ev.TransportParameters)
			close(c.earlyConnReadyChan)
		case handshake.EventReceived0RTTReadKeys,
			handshake.EventReceivedHandshakeReadKeys,
			handshake.EventReceived1RTTReadKeys:
			//nolint:exhaustive // only Handshake and 1-RTT require finishing the previous CRYPTO stream
			switch ev.Kind {
			case handshake.EventReceivedHandshakeReadKeys:
				err = c.cryptoStreamManager.Finish(protocol.EncryptionInitial)
			case handshake.EventReceived1RTTReadKeys:
				err = c.cryptoStreamManager.Finish(protocol.EncryptionHandshake)
			}
			// queue all previously undecryptable packets
			c.undecryptablePacketsToProcess = append(c.undecryptablePacketsToProcess, c.undecryptablePackets...)
			c.undecryptablePackets = nil
		case handshake.EventDiscard0RTTKeys:
			c.dropEncryptionLevel(protocol.Encryption0RTT, now)
		case handshake.EventWriteInitialData:
			_, err = c.initialStream.Write(ev.Data)
		case handshake.EventWriteHandshakeData:
			_, err = c.handshakeStream.Write(ev.Data)
		}
		if err != nil {
			return err
		}
	}
}

// queuePathResponses queues a PATH_RESPONSE frame for every PATH_CHALLENGE frame received in a packet
// (section 8.2.2 of RFC 9000).
// With IETF Multipath QUIC, they are sent on the path that the packet was received on.
func (c *Conn) queuePathResponses(pathID protocol.PathID, pathChallenges []*wire.PathChallengeFrame) {
	for _, f := range pathChallenges {
		if c.mp == nil || !c.mp.active {
			c.queueControlFrame(&wire.PathResponseFrame{Data: f.Data})
			continue
		}
		c.mp.queuePathFrame(pathID, ackhandler.Frame{Frame: &wire.PathResponseFrame{Data: f.Data}})
		c.scheduleSending()
	}
}

func (c *Conn) handlePathResponseFrame(f *wire.PathResponseFrame, rcvTime monotime.Time) error {
	if c.perspective == protocol.PerspectiveClient && c.handlePreferredAddrPathResponse(f, rcvTime) {
		return nil
	}
	if c.mp != nil {
		if ok, err := c.handlePathValidationResponse(f, rcvTime); ok || err != nil {
			return err
		}
		if c.mp.active {
			// The server validates the other 4-tuples of a path (section 3.1.2 of draft-ietf-quic-multipath-21).
			for _, id := range c.mp.pathIDs {
				if pm := c.mp.paths[id].migration; pm != nil {
					pm.HandlePathResponseFrame(f)
				}
			}
		}
		// This might be the response to a PATH_CHALLENGE sent to validate a path or a 4-tuple of a path,
		// received after the validation succeeded (or failed).
		if (c.mp.active || c.mp.sentPathChallenge) &&
			((c.perspective == protocol.PerspectiveClient && c.pathManagerOutgoing.Load() == nil) ||
				(c.perspective == protocol.PerspectiveServer && c.pathManager == nil)) {
			return nil
		}
	}
	switch c.perspective {
	case protocol.PerspectiveClient:
		return c.handlePathResponseFrameClient(f)
	case protocol.PerspectiveServer:
		return c.handlePathResponseFrameServer(f)
	default:
		panic("unreachable")
	}
}

func (c *Conn) handlePathResponseFrameClient(f *wire.PathResponseFrame) error {
	pm := c.pathManagerOutgoing.Load()
	if pm == nil {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "unexpected PATH_RESPONSE frame",
		}
	}
	pm.HandlePathResponseFrame(f)
	return nil
}

func (c *Conn) handlePathResponseFrameServer(f *wire.PathResponseFrame) error {
	if c.pathManager == nil {
		// since we didn't send PATH_CHALLENGEs yet, we don't expect PATH_RESPONSEs
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "unexpected PATH_RESPONSE frame",
		}
	}
	c.pathManager.HandlePathResponseFrame(f)
	return nil
}

func (c *Conn) handleNewTokenFrame(frame *wire.NewTokenFrame) error {
	if c.perspective == protocol.PerspectiveServer {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "received NEW_TOKEN frame from the client",
		}
	}
	if c.config.TokenStore != nil {
		// The token was issued for the Negotiated Version.
		c.config.TokenStore.Put(versionedTokenStoreKey(c.tokenStoreKey, c.version), &ClientToken{data: frame.Token, rtt: c.primaryRTTStats().SmoothedRTT()})
	}
	return nil
}

func (c *Conn) handleHandshakeDoneFrame(rcvTime monotime.Time) error {
	if c.perspective == protocol.PerspectiveServer {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "received a HANDSHAKE_DONE frame",
		}
	}
	if !c.handshakeConfirmed {
		return c.handleHandshakeConfirmed(rcvTime)
	}
	return nil
}

func (c *Conn) handleAckFrame(frame *wire.AckFrame, frameType wire.FrameType, encLevel protocol.EncryptionLevel, rcvTime monotime.Time) error {
	if frame.HasPathID {
		if err := c.mp.checkPathID(frame.PathID, frameType); err != nil {
			return err
		}
		// Until the extension is active, only path 0 is used.
		if !c.mp.active && frame.PathID != 0 && !c.mp.isAbandoned(frame.PathID) {
			return &qerr.TransportError{
				ErrorCode:    qerr.ProtocolViolation,
				FrameType:    uint64(frameType),
				ErrorMessage: fmt.Sprintf("received PATH_ACK for path %d, which didn't send any packets", frame.PathID),
			}
		}
	}
	// PATH_ACK frames for abandoned paths are ignored (section 3.4.3 of draft-ietf-quic-multipath-21).
	// So are ACK frames, which acknowledge packets sent on path 0, once path 0 was abandoned.
	if c.mp != nil && encLevel == protocol.Encryption1RTT && c.mp.isAbandoned(frame.PathID) {
		return nil
	}
	acked1RTTPacket, err := c.sentPacketHandler.ReceivedAck(frame, encLevel, c.lastPacketReceivedTime)
	if err != nil {
		return err
	}
	if !acked1RTTPacket {
		return nil
	}
	// On the client side: If the packet acknowledged a 1-RTT packet, this confirms the handshake.
	// This is only possible if the ACK was sent in a 1-RTT packet.
	// This is an optimization over simply waiting for a HANDSHAKE_DONE frame, see section 4.1.2 of RFC 9001.
	if c.perspective == protocol.PerspectiveClient && !c.handshakeConfirmed {
		if err := c.handleHandshakeConfirmed(rcvTime); err != nil {
			return err
		}
	}
	// If one of the acknowledged packets was a Path MTU probe packet, this might have increased the Path MTU estimate.
	if c.mp != nil && c.mp.active {
		if path, ok := c.mp.paths[frame.PathID]; ok {
			c.maybeUpdatePathMTU(path)
			c.multipathAckReceived(path)
		}
	} else if c.mtuDiscoverer != nil {
		mtu := c.mtuDiscoverer.CurrentSize()
		maxPayloadSize := estimateMaxPayloadSize(mtu)
		if maxPayloadSize > protocol.ByteCount(c.maxPayloadSizeEstimate.Load()) {
			c.maxPayloadSizeEstimate.Store(uint32(maxPayloadSize))
			c.sentPacketHandler.SetMaxDatagramSize(mtu)
		}
	}
	if c.mp != nil {
		// An ACK frame acknowledges packets sent on path 0.
		return c.cryptoStreamHandler.SetLargest1RTTAckedForPath(frame.PathID, frame.LargestAcked(), rcvTime)
	}
	return c.cryptoStreamHandler.SetLargest1RTTAcked(frame.LargestAcked())
}

func (c *Conn) handleDatagramFrame(f *wire.DatagramFrame) error {
	if f.Length(c.version) > wire.MaxDatagramSize {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "DATAGRAM frame too large",
		}
	}
	c.datagramQueue.HandleDatagramFrame(f)
	return nil
}

func (c *Conn) setCloseError(e *closeError) {
	c.closeErr.CompareAndSwap(nil, e)
	select {
	case c.closeChan <- struct{}{}:
	default:
	}
}

// closeLocal closes the connection and send a CONNECTION_CLOSE containing the error
func (c *Conn) closeLocal(e error) {
	c.setCloseError(&closeError{err: e, immediate: false})
}

// destroy closes the connection without sending the error on the wire
func (c *Conn) destroy(e error) {
	c.destroyImpl(e)
	<-c.ctx.Done()
}

func (c *Conn) destroyImpl(e error) {
	c.setCloseError(&closeError{err: e, immediate: true})
}

// CloseWithError closes the connection with an error.
// The error string will be sent to the peer.
func (c *Conn) CloseWithError(code ApplicationErrorCode, desc string) error {
	c.closeLocal(&qerr.ApplicationError{
		ErrorCode:    code,
		ErrorMessage: desc,
	})
	<-c.ctx.Done()
	return nil
}

func (c *Conn) closeWithTransportError(code TransportErrorCode) {
	c.closeLocal(&qerr.TransportError{ErrorCode: code})
	<-c.ctx.Done()
}

func (c *Conn) handleCloseError(closeErr *closeError) {
	if closeErr.immediate {
		if nerr, ok := closeErr.err.(net.Error); ok && nerr.Timeout() {
			c.logger.Errorf("Destroying connection: %s", closeErr.err)
		} else {
			c.logger.Errorf("Destroying connection with error: %s", closeErr.err)
		}
	} else {
		if closeErr.err == nil {
			c.logger.Infof("Closing connection.")
		} else {
			c.logger.Errorf("Closing connection with error: %s", closeErr.err)
		}
	}

	e := closeErr.err
	if e == nil {
		e = &qerr.ApplicationError{}
	} else {
		defer func() { closeErr.err = e }()
	}

	var (
		statelessResetErr     *StatelessResetError
		versionNegotiationErr *VersionNegotiationError
		recreateErr           *errCloseForRecreating
		applicationErr        *ApplicationError
		transportErr          *TransportError
	)
	var isRemoteClose, isStatelessReset bool
	var trigger qlog.ConnectionCloseTrigger
	var reason string
	var transportErrorCode *qlog.TransportErrorCode
	var applicationErrorCode *qlog.ApplicationErrorCode
	switch {
	case errors.Is(e, qerr.ErrIdleTimeout),
		errors.Is(e, qerr.ErrHandshakeTimeout):
		trigger = qlog.ConnectionCloseTriggerIdleTimeout
	case errors.As(e, &statelessResetErr):
		isStatelessReset = true
		trigger = qlog.ConnectionCloseTriggerStatelessReset
	case errors.As(e, &versionNegotiationErr):
		trigger = qlog.ConnectionCloseTriggerVersionMismatch
	case errors.As(e, &recreateErr):
	case errors.As(e, &applicationErr):
		isRemoteClose = applicationErr.Remote
		reason = applicationErr.ErrorMessage
		applicationErrorCode = &applicationErr.ErrorCode
	case errors.As(e, &transportErr):
		isRemoteClose = transportErr.Remote
		reason = transportErr.ErrorMessage
		transportErrorCode = &transportErr.ErrorCode
	case closeErr.immediate:
		e = closeErr.err
	default:
		te := &qerr.TransportError{
			ErrorCode:    qerr.InternalError,
			ErrorMessage: e.Error(),
		}
		e = te
		reason = te.ErrorMessage
		code := te.ErrorCode
		transportErrorCode = &code
	}

	c.streamsMap.CloseWithError(e)
	if c.datagramQueue != nil {
		c.datagramQueue.CloseWithError(e)
	}

	// In rare instances, the connection ID manager might switch to a new connection ID
	// when sending the CONNECTION_CLOSE frame.
	// The connection ID manager removes the active stateless reset token from the packet
	// handler map when it is closed, so we need to make sure that this happens last.
	defer c.peerConnIDs.Close()

	if c.qlogger != nil && !errors.As(e, &recreateErr) {
		initiator := qlog.InitiatorLocal
		if isRemoteClose {
			initiator = qlog.InitiatorRemote
		}
		c.qlogger.RecordEvent(qlog.ConnectionClosed{
			Initiator:        initiator,
			ConnectionError:  transportErrorCode,
			ApplicationError: applicationErrorCode,
			Trigger:          trigger,
			Reason:           reason,
		})
	}

	// With IETF Multipath QUIC, the closing and draining states last for 3 times the largest PTO among all paths
	// (section 2.6 of draft-ietf-quic-multipath-21).

	// If this is a remote close we're done here.
	// After receiving a stateless reset, the endpoint enters the draining period
	// and doesn't send any further packets (section 10.3.1 of RFC 9000).
	if isRemoteClose || (isStatelessReset && !closeErr.immediate) {
		c.connIDGenerator.ReplaceWithClosed(nil, 3*c.maxPTO(false))
		return
	}
	if closeErr.immediate {
		c.connIDGenerator.RemoveAll()
		return
	}
	// Don't send out any CONNECTION_CLOSE if this is an error that occurred
	// before we even sent out the first packet.
	if c.perspective == protocol.PerspectiveClient && !c.sentFirstPacket {
		c.connIDGenerator.RemoveAll()
		return
	}
	connClosePacket, err := c.sendConnectionClose(e)
	if err != nil {
		c.logger.Debugf("Error sending CONNECTION_CLOSE: %s", err)
	}
	if c.mp != nil && c.mp.active {
		c.connIDGenerator.ReplaceWithClosedPaths(c.multipathConnectionClosePackets(e, connClosePacket), 3*c.maxPTO(false))
		return
	}
	c.connIDGenerator.ReplaceWithClosed(connClosePacket, 3*c.maxPTO(false))
}

func (c *Conn) dropEncryptionLevel(encLevel protocol.EncryptionLevel, now monotime.Time) {
	c.sentPacketHandler.DropPackets(encLevel, now)
	c.receivedPacketHandler.DropPackets(encLevel)
	//nolint:exhaustive // only Initial and 0-RTT need special treatment
	switch encLevel {
	case protocol.EncryptionInitial:
		c.droppedInitialKeys = true
		c.cryptoStreamHandler.DiscardInitialKeys()
	case protocol.Encryption0RTT:
		c.streamsMap.ResetFor0RTT()
		c.framer.Handle0RTTRejection()
		c.connFlowController.Reset()
	}
}

// is called for the client, when restoring transport parameters saved for 0-RTT
func (c *Conn) restoreTransportParameters(params *wire.TransportParameters) {
	if c.logger.Debug() {
		c.logger.Debugf("Restoring Transport Parameters: %s", params)
	}
	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.ParametersSet{
			Restore:                         true,
			Initiator:                       qlog.InitiatorRemote,
			SentBy:                          c.perspective,
			OriginalDestinationConnectionID: params.OriginalDestinationConnectionID,
			InitialSourceConnectionID:       params.InitialSourceConnectionID,
			RetrySourceConnectionID:         params.RetrySourceConnectionID,
			StatelessResetToken:             params.StatelessResetToken,
			DisableActiveMigration:          params.DisableActiveMigration,
			MaxIdleTimeout:                  params.MaxIdleTimeout,
			MaxUDPPayloadSize:               params.MaxUDPPayloadSize,
			AckDelayExponent:                params.AckDelayExponent,
			MaxAckDelay:                     params.MaxAckDelay,
			ActiveConnectionIDLimit:         params.ActiveConnectionIDLimit,
			InitialMaxData:                  params.InitialMaxData,
			InitialMaxStreamDataBidiLocal:   params.InitialMaxStreamDataBidiLocal,
			InitialMaxStreamDataBidiRemote:  params.InitialMaxStreamDataBidiRemote,
			InitialMaxStreamDataUni:         params.InitialMaxStreamDataUni,
			InitialMaxStreamsBidi:           int64(params.MaxBidiStreamNum),
			InitialMaxStreamsUni:            int64(params.MaxUniStreamNum),
			MaxDatagramFrameSize:            params.MaxDatagramFrameSize,
			EnableResetStreamAt:             params.EnableResetStreamAt,
			AddressDiscovery:                qlogAddressDiscovery(params.AddressDiscovery),
		})
	}

	c.peerParams = params
	c.connIDGenerator.SetMaxActiveConnIDs(params.ActiveConnectionIDLimit)
	c.connFlowController.UpdateSendWindow(params.InitialMaxData)
	c.streamsMap.HandleTransportParameters(params)
}

func (c *Conn) handleTransportParameters(params *wire.TransportParameters) error {
	if c.qlogger != nil {
		c.qlogTransportParameters(params, c.perspective.Opposite(), false)
	}
	if err := c.checkTransportParameters(params); err != nil {
		return &qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: err.Error(),
		}
	}
	if err := c.checkMultipathTransportParameters(params); err != nil {
		return err
	}

	if c.perspective == protocol.PerspectiveClient && c.peerParams != nil && c.ConnectionState().Used0RTT && !params.ValidForUpdate(c.peerParams) {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "server sent reduced limits after accepting 0-RTT data",
		}
	}

	c.peerParams = params
	// The QUIC Bit is only greased once the peer's transport parameters were processed,
	// and never based on the transport parameters of a previous connection (section 3.1 of RFC 9287).
	if c.config.EnableQUICBitGreasing && params.GreaseQUICBit {
		c.packer.EnableQUICBitGreasing()
	}
	if err := c.maybeNegotiateMultipath(params); err != nil {
		return err
	}
	c.maybeNegotiateAddressAdvertisement(params)
	c.maybeNegotiateAddressDiscovery(params)
	// On the client side we have to wait for handshake completion.
	// During a 0-RTT connection, we are only allowed to use the new transport parameters for 1-RTT packets.
	if c.perspective == protocol.PerspectiveServer {
		c.applyTransportParameters()
		// On the server side, the early connection is ready as soon as we processed
		// the client's transport parameters.
		close(c.earlyConnReadyChan)
	}
	return nil
}

func (c *Conn) checkTransportParameters(params *wire.TransportParameters) error {
	if c.logger.Debug() {
		c.logger.Debugf("Processed Transport Parameters: %s", params)
	}

	// check the initial_source_connection_id
	if params.InitialSourceConnectionID != c.handshakeDestConnID {
		return fmt.Errorf("expected initial_source_connection_id to equal %s, is %s", c.handshakeDestConnID, params.InitialSourceConnectionID)
	}

	if c.perspective == protocol.PerspectiveServer {
		return nil
	}
	// check the original_destination_connection_id
	if params.OriginalDestinationConnectionID != c.origDestConnID {
		return fmt.Errorf("expected original_destination_connection_id to equal %s, is %s", c.origDestConnID, params.OriginalDestinationConnectionID)
	}
	if c.retrySrcConnID != nil { // a Retry was performed
		if params.RetrySourceConnectionID == nil {
			return errors.New("missing retry_source_connection_id")
		}
		if *params.RetrySourceConnectionID != *c.retrySrcConnID {
			return fmt.Errorf("expected retry_source_connection_id to equal %s, is %s", c.retrySrcConnID, *params.RetrySourceConnectionID)
		}
	} else if params.RetrySourceConnectionID != nil {
		return errors.New("received retry_source_connection_id, although no Retry was performed")
	}
	// A server that uses a zero-length connection ID must not send a preferred address (section 18.2 of RFC 9000).
	if params.PreferredAddress != nil && params.InitialSourceConnectionID.Len() == 0 {
		return errors.New("received preferred_address, although the server uses a zero-length connection ID")
	}
	return nil
}

func (c *Conn) applyTransportParameters() {
	params := c.peerParams
	// Our local idle timeout will always be > 0.
	c.idleTimeout = c.config.MaxIdleTimeout
	// If the peer advertised an idle timeout, take the minimum of the values.
	if params.MaxIdleTimeout > 0 {
		c.idleTimeout = min(c.idleTimeout, params.MaxIdleTimeout)
	}
	c.keepAliveInterval = min(c.config.KeepAlivePeriod, c.idleTimeout/2)
	c.streamsMap.HandleTransportParameters(params)
	c.frameParser.SetAckDelayExponent(params.AckDelayExponent)
	c.connFlowController.UpdateSendWindow(params.InitialMaxData)
	c.rttStats.SetMaxAckDelay(params.MaxAckDelay)
	c.connIDGenerator.SetMaxActiveConnIDs(params.ActiveConnectionIDLimit)
	if params.StatelessResetToken != nil {
		c.connIDManager.SetStatelessResetToken(*params.StatelessResetToken)
	}
	if params.PreferredAddress != nil {
		c.handlePreferredAddress(params.PreferredAddress)
	}
	maxPacketSize := protocol.ByteCount(protocol.MaxPacketBufferSize)
	if params.MaxUDPPayloadSize > 0 && params.MaxUDPPayloadSize < maxPacketSize {
		maxPacketSize = params.MaxUDPPayloadSize
	}
	c.mtuDiscoverer = newMTUDiscoverer(
		c.rttStats,
		protocol.ByteCount(c.config.InitialPacketSize),
		maxPacketSize,
		c.qlogger,
	)
}

func (c *Conn) triggerSending(now monotime.Time) error {
	if c.mp != nil && c.mp.active && c.handshakeConfirmed {
		return c.triggerSendingMultipath(now)
	}
	c.pacingDeadline = 0

	// Path probe packets are not congestion controlled.
	if c.perspective == protocol.PerspectiveServer && c.handshakeConfirmed {
		if err := c.sendDuePathChallenges(now); err != nil {
			return err
		}
	}

	sendMode := c.sentPacketHandler.SendMode(now)
	switch sendMode {
	case ackhandler.SendAny:
		return c.sendPackets(now)
	case ackhandler.SendNone:
		c.blocked = blockModeHardBlocked
		return nil
	case ackhandler.SendPacingLimited:
		deadline := c.sentPacketHandler.TimeUntilSend()
		if deadline.IsZero() {
			deadline = deadlineSendImmediately
		}
		c.pacingDeadline = deadline
		// Allow sending of an ACK if we're pacing limit.
		// This makes sure that a peer that is mostly receiving data (and thus has an inaccurate cwnd estimate)
		// sends enough ACKs to allow its peer to utilize the bandwidth.
		return c.maybeSendAckOnlyPacket(now)
	case ackhandler.SendAck:
		// We can at most send a single ACK only packet.
		// There will only be a new ACK after receiving new packets.
		// SendAck is only returned when we're congestion limited, so we don't need to set the pacing timer.
		c.blocked = blockModeCongestionLimited
		return c.maybeSendAckOnlyPacket(now)
	case ackhandler.SendPTOInitial, ackhandler.SendPTOHandshake, ackhandler.SendPTOAppData:
		if err := c.sendProbePacket(sendMode, now); err != nil {
			return err
		}
		if c.sendQueue.WouldBlock() {
			c.scheduleSending()
			return nil
		}
		return c.triggerSending(now)
	default:
		return fmt.Errorf("BUG: invalid send mode %d", sendMode)
	}
}

func (c *Conn) sendPackets(now monotime.Time) error {
	if c.perspective == protocol.PerspectiveClient && c.handshakeConfirmed {
		if pm := c.pathManagerOutgoing.Load(); pm != nil {
			connID, frame, tr, ok := pm.NextPathToProbe()
			if ok {
				frames := c.observedAddrProbeFrame(
					[]ackhandler.Frame{frame},
					0,
					rfc9000ObservationTuple(tr.conn.LocalAddr(), c.conn.RemoteAddr()),
				)
				probe, buf, err := c.packer.PackPathProbePacket(connID, frames, protocol.MinInitialPacketSize, c.version, 0)
				if err != nil {
					return err
				}
				c.logger.Debugf("sending path probe packet from %s", c.LocalAddr())
				c.logShortHeaderPacket(probe, protocol.ECNNon, buf.Len())
				c.registerPackedShortHeaderPacket(probe, protocol.ECNNon, now)
				// Failing to send a probe packet (e.g. because the new network is unreachable)
				// must not close the connection. The probe will be declared lost.
				if _, err := tr.WriteTo(buf.Data, c.conn.RemoteAddr()); err != nil {
					c.logger.Debugf("failed to send path probe packet: %s", err)
				}
				buf.Release()
				// There's (likely) more data to send. Loop around again.
				c.scheduleSending()
				return nil
			}
		}
	}

	// Path MTU Discovery
	// Can't use GSO, since we need to send a single packet that's larger than our current maximum size.
	// Performance-wise, this doesn't matter, since we only send a very small (<10) number of
	// MTU probe packets per connection.
	if c.handshakeConfirmed && c.mtuDiscoverer != nil && c.mtuDiscoverer.ShouldSendProbe(now) {
		ping, size := c.mtuDiscoverer.GetPing(now)
		p, buf, err := c.packer.PackMTUProbePacket(ping, size, c.version, 0)
		if err != nil {
			return err
		}
		ecn := c.sentPacketHandler.ECNMode(true)
		c.logShortHeaderPacket(p, ecn, buf.Len())
		c.registerPackedShortHeaderPacket(p, ecn, now)
		c.sendQueue.Send(buf, 0, ecn)
		// There's (likely) more data to send. Loop around again.
		c.scheduleSending()
		return nil
	}

	if offset := c.connFlowController.GetWindowUpdate(now); offset > 0 {
		c.framer.QueueControlFrame(&wire.MaxDataFrame{MaximumData: offset})
	}
	if cf := c.cryptoStreamManager.GetPostHandshakeData(protocol.MaxPostHandshakeCryptoFrameSize); cf != nil {
		c.queueControlFrame(cf)
	}

	if !c.handshakeConfirmed {
		packet, err := c.packer.PackCoalescedPacket(false, c.maxPacketSize(), now, c.version, 0)
		if err != nil || packet == nil {
			return err
		}
		c.sentFirstPacket = true
		if err := c.sendPackedCoalescedPacket(packet, c.sentPacketHandler.ECNMode(packet.IsOnlyShortHeaderPacket()), now); err != nil {
			return err
		}
		//nolint:exhaustive // only need to handle pacing-related events here
		switch c.sentPacketHandler.SendMode(now) {
		case ackhandler.SendPacingLimited:
			c.resetPacingDeadline()
		case ackhandler.SendAny:
			c.pacingDeadline = deadlineSendImmediately
		}
		return nil
	}

	if c.conn.capabilities().GSO {
		return c.sendPacketsWithGSO(now)
	}
	return c.sendPacketsWithoutGSO(now)
}

func (c *Conn) sendPacketsWithoutGSO(now monotime.Time) error {
	for {
		buf := getPacketBuffer()
		ecn := c.sentPacketHandler.ECNMode(true)
		if _, _, err := c.appendOneShortHeaderPacket(buf, c.maxPacketSize(), ecn, now, 0); err != nil {
			if err == errNothingToPack {
				buf.Release()
				return nil
			}
			return err
		}

		c.sendQueue.Send(buf, 0, ecn)

		if c.sendQueue.WouldBlock() {
			return nil
		}
		sendMode := c.sentPacketHandler.SendMode(now)
		if sendMode == ackhandler.SendPacingLimited {
			c.resetPacingDeadline()
			return nil
		}
		if sendMode != ackhandler.SendAny {
			return nil
		}
		// Prioritize receiving of packets over sending out more packets.
		c.receivedPacketMx.Lock()
		hasPackets := !c.receivedPackets.Empty()
		c.receivedPacketMx.Unlock()
		if hasPackets {
			c.pacingDeadline = deadlineSendImmediately
			return nil
		}
	}
}

func (c *Conn) sendPacketsWithGSO(now monotime.Time) error {
	buf := getLargePacketBuffer()
	maxSize := c.maxPacketSize()

	ecn := c.sentPacketHandler.ECNMode(true)
	for {
		var dontSendMore bool
		size, _, err := c.appendOneShortHeaderPacket(buf, maxSize, ecn, now, 0)
		if err != nil {
			if err != errNothingToPack {
				return err
			}
			if buf.Len() == 0 {
				buf.Release()
				return nil
			}
			dontSendMore = true
		}

		if !dontSendMore {
			sendMode := c.sentPacketHandler.SendMode(now)
			if sendMode == ackhandler.SendPacingLimited {
				c.resetPacingDeadline()
			}
			if sendMode != ackhandler.SendAny {
				dontSendMore = true
			}
		}

		// Don't send more packets in this batch if they require a different ECN marking than the previous ones.
		nextECN := c.sentPacketHandler.ECNMode(true)

		// Append another packet if
		// 1. The congestion controller and pacer allow sending more
		// 2. The last packet appended was a full-size packet
		// 3. The next packet will have the same ECN marking
		// 4. We still have enough space for another full-size packet in the buffer
		if !dontSendMore && size == maxSize && nextECN == ecn && buf.Len()+maxSize <= buf.Cap() {
			continue
		}

		c.sendQueue.Send(buf, uint16(maxSize), ecn)

		if dontSendMore {
			return nil
		}
		if c.sendQueue.WouldBlock() {
			return nil
		}

		// Prioritize receiving of packets over sending out more packets.
		c.receivedPacketMx.Lock()
		hasPackets := !c.receivedPackets.Empty()
		c.receivedPacketMx.Unlock()
		if hasPackets {
			c.pacingDeadline = deadlineSendImmediately
			return nil
		}

		ecn = nextECN
		buf = getLargePacketBuffer()
	}
}

func (c *Conn) resetPacingDeadline() {
	deadline := c.sentPacketHandler.TimeUntilSend()
	if deadline.IsZero() {
		deadline = deadlineSendImmediately
	}
	c.pacingDeadline = deadline
}

func (c *Conn) maybeSendAckOnlyPacket(now monotime.Time) error {
	if !c.handshakeConfirmed {
		ecn := c.sentPacketHandler.ECNMode(false)
		packet, err := c.packer.PackCoalescedPacket(true, c.maxPacketSize(), now, c.version, 0)
		if err != nil {
			return err
		}
		if packet == nil {
			return nil
		}
		return c.sendPackedCoalescedPacket(packet, ecn, now)
	}

	ecn := c.sentPacketHandler.ECNMode(true)
	p, buf, err := c.packer.PackAckOnlyPacket(c.maxPacketSize(), now, c.version, 0)
	if err != nil {
		if err == errNothingToPack {
			return nil
		}
		return err
	}
	c.logShortHeaderPacket(p, ecn, buf.Len())
	c.registerPackedShortHeaderPacket(p, ecn, now)
	c.sendQueue.Send(buf, 0, ecn)
	return nil
}

// handlePendingReinjections selects the paths for the lost frames that the reinjection policy reinjects.
// The frames are already queued for retransmission. The next packet carrying data is sent on the selected path.
func (c *Conn) handlePendingReinjections(now monotime.Time) {
	if c.multipathReinjectionManager == nil || c.mp == nil || !c.mp.active {
		return
	}
	pending := c.multipathReinjectionManager.GetPendingReinjections(now.ToTime())
	if len(pending) == 0 {
		return
	}
	for _, info := range pending {
		targetPath := c.selectReinjectionTarget(info)
		if targetPath != protocol.InvalidPathID {
			if ok, next := c.multipathReinjectionManager.canReinjectOnPath(targetPath, now.ToTime()); !ok {
				c.multipathReinjectionManager.deferReinjection(info, next)
				continue
			}
			if limit := c.multipathReinjectionManager.policy.GetMaxReinjectionQueuePerPath(); limit > 0 {
				if c.reinjectionQueueCounts == nil {
					c.reinjectionQueueCounts = make(map[protocol.PathID]int)
				}
				if c.reinjectionQueueCounts[targetPath] >= limit {
					delay := c.multipathReinjectionManager.policy.GetReinjectionDelay()
					c.multipathReinjectionManager.deferReinjection(info, now.ToTime().Add(delay))
					continue
				}
			}
		}
		info.TargetPathID = targetPath
		queued := hasRetransmittableFrames(info.Frames)
		if queued && targetPath != protocol.InvalidPathID {
			c.reinjectionPathQueue = append(c.reinjectionPathQueue, targetPath)
			if c.reinjectionQueueCounts == nil {
				c.reinjectionQueueCounts = make(map[protocol.PathID]int)
			}
			c.reinjectionQueueCounts[targetPath]++
		}
		c.multipathReinjectionManager.MarkReinjected(info.OriginalPathID, info.PacketNumber, targetPath)
		// Packet numbers are never reused, so this packet won't be reported lost again.
		c.multipathReinjectionManager.forgetPacket(info.OriginalPathID, info.PacketNumber)
	}
	c.scheduleSending()
}

// hasRetransmittableFrames says if any of the frames of a lost packet will be retransmitted.
// The frames were already handed to their handler's OnLost by the loss detection (which queues them for retransmission).
// Calling OnLost a second time would retransmit them twice (and corrupt the send stream's state),
// so reinjection only selects the path that the retransmission is sent on.
func hasRetransmittableFrames(frames []ackhandler.Frame) bool {
	for _, frame := range frames {
		if frame.Frame != nil && frame.Handler != nil {
			return true
		}
	}
	return false
}

// reinjectionCandidatePaths returns the paths that lost frames can be reinjected on:
// the paths that data is sent on (see multipathDataPaths).
func (c *Conn) reinjectionCandidatePaths() []PathInfo {
	var usable []*mpPath
	for _, id := range c.mp.pathIDs {
		if path := c.mp.paths[id]; path.usable() {
			usable = append(usable, path)
		}
	}
	dataPaths := c.appendMultipathDataPaths(nil, usable)
	paths := make([]PathInfo, 0, len(dataPaths))
	for _, path := range dataPaths {
		paths = append(paths, c.mpPathInfo(path))
	}
	return paths
}

// reinjectionPathUsable says if lost frames can be reinjected on the path that they were lost on.
func (c *Conn) reinjectionPathUsable(pathID protocol.PathID) bool {
	path, ok := c.mp.paths[pathID]
	return ok && path.usable()
}

func (c *Conn) selectReinjectionTarget(info *PacketReinjectionInfo) protocol.PathID {
	if c.multipathController == nil || c.multipathReinjectionManager == nil {
		return protocol.InvalidPathID
	}
	policy := c.multipathReinjectionManager.policy
	if policy == nil {
		return protocol.InvalidPathID
	}
	paths := c.reinjectionCandidatePaths()
	if len(paths) == 0 {
		return protocol.InvalidPathID
	}

	candidates := make([]PathInfo, 0, len(paths))
	for _, path := range paths {
		if path.ID == protocol.InvalidPathID || path.RemoteAddr == nil {
			continue
		}
		if path.ID == info.OriginalPathID {
			continue
		}
		if !policy.IsPreferredPathForReinjection(path.ID) {
			continue
		}
		candidates = append(candidates, path)
	}

	candidateIDs := make(map[protocol.PathID]struct{}, len(candidates))
	for _, candidate := range candidates {
		candidateIDs[candidate.ID] = struct{}{}
	}

	if selector, ok := c.multipathController.(MultipathReinjectionTargetSelector); ok {
		ctx := ReinjectionTargetContext{
			Now:            time.Now(),
			OriginalPathID: info.OriginalPathID,
			Candidates:     slices.Clone(candidates),
			Packet:         info,
		}
		if pathID, ok := selector.SelectReinjectionTarget(ctx); ok && pathID != protocol.InvalidPathID {
			if _, ok := candidateIDs[pathID]; ok {
				return pathID
			}
			if pathID == info.OriginalPathID && policy.IsPreferredPathForReinjection(pathID) && c.reinjectionPathUsable(pathID) {
				return pathID
			}
		}
	}

	if len(candidates) == 0 {
		if info.OriginalPathID != protocol.InvalidPathID && policy.IsPreferredPathForReinjection(info.OriginalPathID) &&
			c.reinjectionPathUsable(info.OriginalPathID) {
			return info.OriginalPathID
		}
		return protocol.InvalidPathID
	}

	slices.SortFunc(candidates, func(a, b PathInfo) int {
		switch {
		case a.ID < b.ID:
			return -1
		case a.ID > b.ID:
			return 1
		default:
			return 0
		}
	})

	best := candidates[0]
	var bestRTT time.Duration
	if stats := c.sentPacketHandler.GetPathRTTStats(best.ID); stats != nil {
		bestRTT = stats.SmoothedRTT()
	}
	for _, candidate := range candidates[1:] {
		stats := c.sentPacketHandler.GetPathRTTStats(candidate.ID)
		if stats == nil {
			continue
		}
		rtt := stats.SmoothedRTT()
		if bestRTT == 0 || (rtt > 0 && rtt < bestRTT) {
			best = candidate
			bestRTT = rtt
		}
	}

	return best.ID
}

func (c *Conn) sendProbePacket(sendMode ackhandler.SendMode, now monotime.Time) error {
	var encLevel protocol.EncryptionLevel
	//nolint:exhaustive // We only need to handle the PTO send modes here.
	switch sendMode {
	case ackhandler.SendPTOInitial:
		encLevel = protocol.EncryptionInitial
	case ackhandler.SendPTOHandshake:
		encLevel = protocol.EncryptionHandshake
	case ackhandler.SendPTOAppData:
		encLevel = protocol.Encryption1RTT
	default:
		return fmt.Errorf("connection BUG: unexpected send mode: %d", sendMode)
	}
	// Queue probe packets until we actually send out a packet,
	// or until there are no more packets to queue.
	var packet *coalescedPacket
	for packet == nil {
		if wasQueued := c.sentPacketHandler.QueueProbePacket(encLevel); !wasQueued {
			break
		}
		var err error
		packet, err = c.packer.PackPTOProbePacket(encLevel, c.maxPacketSize(), false, now, c.version, 0)
		if err != nil {
			return err
		}
	}
	if packet == nil {
		var err error
		packet, err = c.packer.PackPTOProbePacket(encLevel, c.maxPacketSize(), true, now, c.version, 0)
		if err != nil {
			return err
		}
	}
	if packet == nil || (len(packet.longHdrPackets) == 0 && packet.shortHdrPacket == nil) {
		return fmt.Errorf("connection BUG: couldn't pack %s probe packet: %v", encLevel, packet)
	}
	return c.sendPackedCoalescedPacket(packet, c.sentPacketHandler.ECNMode(packet.IsOnlyShortHeaderPacket()), now)
}

// appendOneShortHeaderPacket appends a new packet to the given packetBuffer.
// If there was nothing to pack, the returned size is 0.
func (c *Conn) appendOneShortHeaderPacket(buf *packetBuffer, maxSize protocol.ByteCount, ecn protocol.ECN, now monotime.Time, pathID protocol.PathID) (protocol.ByteCount, shortHeaderPacket, error) {
	startLen := buf.Len()
	p, err := c.packer.AppendPacket(buf, maxSize, now, c.version, pathID)
	if err != nil {
		return 0, shortHeaderPacket{}, err
	}
	size := buf.Len() - startLen
	c.logShortHeaderPacket(p, ecn, size)
	c.registerPackedShortHeaderPacket(p, ecn, now)
	return size, p, nil
}

func (c *Conn) registerPackedShortHeaderPacket(p shortHeaderPacket, ecn protocol.ECN, now monotime.Time) {
	if p.IsPathProbePacket {
		c.sentPacketHandler.SentPacket(
			now,
			p.PacketNumber,
			protocol.InvalidPacketNumber,
			p.StreamFrames,
			p.Frames,
			protocol.Encryption1RTT,
			ecn,
			p.Length,
			p.IsPathMTUProbePacket,
			true,
			protocol.PathID(p.PathID),
		)
		return
	}
	if c.firstAckElicitingPacketAfterIdleSentTime.IsZero() && (len(p.StreamFrames) > 0 || ackhandler.HasAckElicitingFrames(p.Frames)) {
		c.firstAckElicitingPacketAfterIdleSentTime = now
	}

	largestAcked, pathAcks := c.sentPacketAcks(&p)
	c.sentPacketHandler.SentPacket(
		now,
		p.PacketNumber,
		largestAcked,
		p.StreamFrames,
		p.Frames,
		protocol.Encryption1RTT,
		ecn,
		p.Length,
		p.IsPathMTUProbePacket,
		false,
		protocol.PathID(p.PathID),
		pathAcks...,
	)
	c.connIDSentPacket(&p)
	if c.mp != nil && c.mp.active && !p.IsPathMTUProbePacket && (len(p.StreamFrames) > 0 || p.IsAckEliciting()) {
		c.multipathSentPacket(protocol.PathID(p.PathID), now)
	}
}

// sentPacketAcks returns the largest packet number acknowledged by the ACK frame of a 1-RTT packet,
// and the PATH_ACK frames contained in the packet (IETF Multipath QUIC).
func (c *Conn) sentPacketAcks(p *shortHeaderPacket) (protocol.PacketNumber, []ackhandler.PathAck) {
	if p.Ack == nil && len(p.ExtraAcks) == 0 {
		return protocol.InvalidPacketNumber, nil
	}
	if p.Ack != nil && !p.Ack.HasPathID {
		return p.Ack.LargestAcked(), nil
	}
	acks := c.mp.pathAcks[:0]
	if p.Ack != nil {
		acks = append(acks, ackhandler.PathAck{PathID: p.Ack.PathID, LargestAcked: p.Ack.LargestAcked()})
	}
	for _, ack := range p.ExtraAcks {
		acks = append(acks, ackhandler.PathAck{PathID: ack.PathID, LargestAcked: ack.LargestAcked()})
	}
	return protocol.InvalidPacketNumber, acks
}

// connIDSentPacket is called for every 1-RTT packet sent,
// such that the connection ID used on the path is changed from time to time.
func (c *Conn) connIDSentPacket(p *shortHeaderPacket) {
	if c.mp != nil && c.mp.active {
		c.peerConnIDs.SentPacket(protocol.PathID(p.PathID))
		return
	}
	c.connIDManager.SentPacket()
}

func (c *Conn) sendPackedCoalescedPacket(packet *coalescedPacket, ecn protocol.ECN, now monotime.Time) error {
	c.logCoalescedPacket(packet, ecn)
	for _, p := range packet.longHdrPackets {
		if c.firstAckElicitingPacketAfterIdleSentTime.IsZero() && p.IsAckEliciting() {
			c.firstAckElicitingPacketAfterIdleSentTime = now
		}
		largestAcked := protocol.InvalidPacketNumber
		if p.ack != nil {
			largestAcked = p.ack.LargestAcked()
		}
		c.sentPacketHandler.SentPacket(
			now,
			p.header.PacketNumber,
			largestAcked,
			p.streamFrames,
			p.frames,
			p.EncryptionLevel(),
			ecn,
			p.length,
			false,
			false,
			0,
		)
		if c.perspective == protocol.PerspectiveClient && p.EncryptionLevel() == protocol.EncryptionHandshake &&
			!c.droppedInitialKeys {
			// On the client side, Initial keys are dropped as soon as the first Handshake packet is sent.
			// See Section 4.9.1 of RFC 9001.
			c.dropEncryptionLevel(protocol.EncryptionInitial, now)
		}
	}
	if p := packet.shortHdrPacket; p != nil {
		if c.firstAckElicitingPacketAfterIdleSentTime.IsZero() && p.IsAckEliciting() {
			c.firstAckElicitingPacketAfterIdleSentTime = now
		}
		largestAcked, pathAcks := c.sentPacketAcks(p)
		c.sentPacketHandler.SentPacket(
			now,
			p.PacketNumber,
			largestAcked,
			p.StreamFrames,
			p.Frames,
			protocol.Encryption1RTT,
			ecn,
			p.Length,
			p.IsPathMTUProbePacket,
			false,
			protocol.PathID(p.PathID),
			pathAcks...,
		)
		c.connIDSentPacket(p)
	} else {
		c.connIDManager.SentPacket()
	}
	c.sendQueue.Send(packet.buffer, 0, ecn)
	return nil
}

func (c *Conn) sendConnectionClose(e error) ([]byte, error) {
	// With IETF Multipath QUIC, the CONNECTION_CLOSE is sent on the path that the last packet was received on.
	var pathID protocol.PathID
	maxPacketSize := c.maxPacketSize()
	if c.mp != nil && c.mp.active {
		id, ok := c.mp.closePathID()
		if !ok {
			return nil, errors.New("no path to send the CONNECTION_CLOSE on")
		}
		pathID = id
		maxPacketSize = c.pathMaxPacketSize(c.mp.paths[id])
	}
	packet, err := c.packConnectionClose(e, maxPacketSize, pathID)
	if err != nil {
		return nil, err
	}
	if c.mp != nil && c.mp.active {
		return packet.buffer.Data, c.sendMultipathConnectionClose(c.mp.paths[pathID], packet)
	}
	ecn := c.sentPacketHandler.ECNMode(packet.IsOnlyShortHeaderPacket())
	c.logCoalescedPacket(packet, ecn)
	return packet.buffer.Data, c.conn.Write(packet.buffer.Data, 0, ecn)
}

// packConnectionClose packs a packet containing a CONNECTION_CLOSE frame for the error.
func (c *Conn) packConnectionClose(e error, maxPacketSize protocol.ByteCount, pathID protocol.PathID) (*coalescedPacket, error) {
	if transportErr, ok := errors.AsType[*qerr.TransportError](e); ok {
		return c.packer.PackConnectionClose(transportErr, maxPacketSize, c.version, pathID)
	}
	if applicationErr, ok := errors.AsType[*qerr.ApplicationError](e); ok {
		return c.packer.PackApplicationClose(applicationErr, maxPacketSize, c.version, pathID)
	}
	return c.packer.PackConnectionClose(&qerr.TransportError{
		ErrorCode:    qerr.InternalError,
		ErrorMessage: fmt.Sprintf("connection BUG: unspecified error type (msg: %s)", e.Error()),
	}, maxPacketSize, c.version, pathID)
}

func (c *Conn) maxPacketSize() protocol.ByteCount {
	if c.mtuDiscoverer == nil {
		// Use the configured packet size on the client side.
		// If the server sends a max_udp_payload_size that's smaller than this size, we can ignore this:
		// Apparently the server still processed the (fully padded) Initial packet anyway.
		if c.perspective == protocol.PerspectiveClient {
			return protocol.ByteCount(c.config.InitialPacketSize)
		}
		// On the server side, there's no downside to using 1200 bytes until we received the client's transport
		// parameters:
		// * If the first packet didn't contain the entire ClientHello, all we can do is ACK that packet. We don't
		//   need a lot of bytes for that.
		// * If it did, we will have processed the transport parameters and initialized the MTU discoverer.
		return protocol.MinInitialPacketSize
	}
	return c.mtuDiscoverer.CurrentSize()
}

// AcceptStream returns the next stream opened by the peer, blocking until one is available.
func (c *Conn) AcceptStream(ctx context.Context) (*Stream, error) {
	return c.streamsMap.AcceptStream(ctx)
}

// AcceptUniStream returns the next unidirectional stream opened by the peer, blocking until one is available.
func (c *Conn) AcceptUniStream(ctx context.Context) (*ReceiveStream, error) {
	return c.streamsMap.AcceptUniStream(ctx)
}

// OpenStream opens a new bidirectional QUIC stream.
// There is no signaling to the peer about new streams:
// The peer can only accept the stream after data has been sent on the stream,
// or the stream has been reset or closed.
// When reaching the peer's stream limit, it is not possible to open a new stream until the
// peer raises the stream limit. In that case, a [StreamLimitReachedError] is returned.
func (c *Conn) OpenStream() (*Stream, error) {
	return c.streamsMap.OpenStream()
}

// OpenStreamSync opens a new bidirectional QUIC stream.
// It blocks until a new stream can be opened.
// There is no signaling to the peer about new streams:
// The peer can only accept the stream after data has been sent on the stream,
// or the stream has been reset or closed.
func (c *Conn) OpenStreamSync(ctx context.Context) (*Stream, error) {
	return c.streamsMap.OpenStreamSync(ctx)
}

// OpenUniStream opens a new outgoing unidirectional QUIC stream.
// There is no signaling to the peer about new streams:
// The peer can only accept the stream after data has been sent on the stream,
// or the stream has been reset or closed.
// When reaching the peer's stream limit, it is not possible to open a new stream until the
// peer raises the stream limit. In that case, a [StreamLimitReachedError] is returned.
func (c *Conn) OpenUniStream() (*SendStream, error) {
	return c.streamsMap.OpenUniStream()
}

// OpenUniStreamSync opens a new outgoing unidirectional QUIC stream.
// It blocks until a new stream can be opened.
// There is no signaling to the peer about new streams:
// The peer can only accept the stream after data has been sent on the stream,
// or the stream has been reset or closed.
func (c *Conn) OpenUniStreamSync(ctx context.Context) (*SendStream, error) {
	return c.streamsMap.OpenUniStreamSync(ctx)
}

func (c *Conn) newFlowController(id protocol.StreamID) *streamFlowController {
	initialSendWindow := c.peerParams.InitialMaxStreamDataUni
	if protocol.StreamTypeOf(id) == protocol.StreamTypeBidi {
		if protocol.StreamInitiator(id) == c.perspective {
			initialSendWindow = c.peerParams.InitialMaxStreamDataBidiRemote
		} else {
			initialSendWindow = c.peerParams.InitialMaxStreamDataBidiLocal
		}
	}
	return newStreamFlowController(
		id,
		c.connFlowController,
		protocol.ByteCount(c.config.InitialStreamReceiveWindow),
		protocol.ByteCount(c.config.MaxStreamReceiveWindow),
		initialSendWindow,
		c.rttStats,
		c.logger,
	)
}

// scheduleSending signals that we have data for sending
func (c *Conn) scheduleSending() {
	select {
	case c.sendingScheduled <- struct{}{}:
	default:
	}
}

// tryQueueingUndecryptablePacket queues a packet for which we're missing the decryption keys.
// The qlogevents.PacketType is only used for logging purposes.
func (c *Conn) tryQueueingUndecryptablePacket(p receivedPacket, pt qlog.PacketType, datagramPayloadChecksum qlog.DatagramPayloadChecksum) {
	if c.handshakeComplete {
		panic("shouldn't queue undecryptable packets after handshake completion")
	}
	if len(c.undecryptablePackets)+1 > protocol.MaxUndecryptablePackets {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:   pt,
					PacketNumber: protocol.InvalidPacketNumber,
				},
				Raw:                     qlog.RawInfo{Length: int(p.Size())},
				DatagramPayloadChecksum: datagramPayloadChecksum,
				Trigger:                 qlog.PacketDropDOSPrevention,
			})
		}
		c.logger.Infof("Dropping undecryptable packet (%d bytes). Undecryptable packet queue full.", p.Size())
		return
	}
	c.logger.Infof("Queueing packet (%d bytes) for later decryption", p.Size())
	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.PacketBuffered{
			Header: qlog.PacketHeader{
				PacketType:   pt,
				PacketNumber: protocol.InvalidPacketNumber,
			},
			Raw:                     qlog.RawInfo{Length: int(p.Size())},
			DatagramPayloadChecksum: datagramPayloadChecksum,
		})
	}
	c.undecryptablePackets = append(c.undecryptablePackets, receivedPacketWithChecksum{receivedPacket: p, checksum: datagramPayloadChecksum})
}

func (c *Conn) queueControlFrame(f wire.Frame) {
	c.framer.QueueControlFrame(f)
	c.scheduleSending()
}

func (c *Conn) onHasConnectionData() { c.scheduleSending() }

func (c *Conn) onHasStreamData(id protocol.StreamID, str *SendStream) {
	c.framer.AddActiveStream(id, str)
	c.scheduleSending()
}

func (c *Conn) onHasStreamRetransmission(id protocol.StreamID, str *SendStream) {
	c.framer.AddStreamWithRetransmission(id, str)
	c.scheduleSending()
}

func (c *Conn) onHasStreamControlFrame(id protocol.StreamID, str streamControlFrameGetter) {
	c.framer.AddStreamWithControlFrames(id, str)
	c.scheduleSending()
}

func (c *Conn) onStreamCompleted(id protocol.StreamID) {
	if err := c.streamsMap.DeleteStream(id); err != nil {
		c.closeLocal(err)
	}
	c.framer.RemoveActiveStream(id)
}

func (c *Conn) updateStreamPriority(id protocol.StreamID) {
	c.framer.UpdateStreamPriority(id)
	c.scheduleSending()
}

func (c *Conn) recordStreamPriorityUpdated(id protocol.StreamID, urgency int8, incremental bool) {
	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.StreamPriorityUpdated{
			StreamID:    id,
			Urgency:     urgency,
			Incremental: incremental,
		})
	}
}

// SendDatagram sends a message using a QUIC datagram, as specified in RFC 9221,
// if the peer enabled datagram support.
// There is no delivery guarantee for DATAGRAM frames, they are not retransmitted if lost.
// The payload of the datagram needs to fit into a single QUIC packet.
// In addition, a datagram may be dropped before being sent out if the available packet size suddenly decreases.
// If the payload is too large to be sent at the current time, a [DatagramTooLargeError] is returned.
func (c *Conn) SendDatagram(p []byte) error {
	if !c.supportsDatagrams() {
		return errors.New("datagram support disabled")
	}

	f := &wire.DatagramFrame{DataLenPresent: true}
	// The payload size estimate is conservative.
	// Under many circumstances we could send a few more bytes.
	maxDataLen := min(
		// The frame encoding is the same for all versions.
		// The Chosen Version is never modified, so it's safe to use it here.
		f.MaxDataLen(c.peerParams.MaxDatagramFrameSize, c.chosenVersion),
		protocol.ByteCount(c.maxPayloadSizeEstimate.Load()),
	)
	if protocol.ByteCount(len(p)) > maxDataLen {
		return &DatagramTooLargeError{MaxDatagramPayloadSize: int64(maxDataLen)}
	}
	f.Data = make([]byte, len(p))
	copy(f.Data, p)
	return c.datagramQueue.Add(f)
}

// ReceiveDatagram gets a message received in a QUIC datagram, as specified in RFC 9221.
func (c *Conn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	if !c.config.EnableDatagrams {
		return nil, errors.New("datagram support disabled")
	}
	return c.datagramQueue.Receive(ctx)
}

// LocalAddr returns the local address of the QUIC connection.
func (c *Conn) LocalAddr() net.Addr { return c.primarySendConn().LocalAddr() }

// RemoteAddr returns the remote address of the QUIC connection.
func (c *Conn) RemoteAddr() net.Addr { return c.primarySendConn().RemoteAddr() }

// getPathManager lazily initializes the Conn's pathManagerOutgoing.
// May create multiple pathManagerOutgoing objects if called concurrently.
func (c *Conn) getPathManager() *pathManagerOutgoing {
	old := c.pathManagerOutgoing.Load()
	if old != nil {
		// Path manager is already initialized
		return old
	}

	// Initialize the path manager
	new := newPathManagerOutgoing(
		c.connIDManager.GetConnIDForPath,
		c.connIDManager.RetireConnIDForPath,
		c.scheduleSending,
		c.handshakeTransport,
	)
	if c.pathManagerOutgoing.CompareAndSwap(old, new) {
		return new
	}

	// Swap failed. A concurrent writer wrote first, use their value.
	return c.pathManagerOutgoing.Load()
}

// AddPath creates a new path that sends packets from the Transport's connection.
// Without IETF Multipath QUIC, the path can be used to migrate the connection (section 9 of RFC 9000).
// With IETF Multipath QUIC, it opens a new path of the connection when it is probed.
// If the client advertised IETF Multipath QUIC, whether the server supports it is only known once the handshake
// completed. A path added before is created when it is probed: [Path.Probe] waits for the handshake to complete.
// The Transport needs to stay open until the connection is closed: [Transport.Close] terminates the connection.
// If the server sent the disable_active_migration transport parameter, paths can only be added once the connection
// migrated to the server's preferred address (see [PreferredAddress]). With IETF Multipath QUIC, paths are opened to
// the server address that path 0 uses when the path is created.
func (c *Conn) AddPath(t *Transport) (*Path, error) {
	if c.perspective == protocol.PerspectiveServer {
		return nil, errors.New("server cannot initiate connection migration")
	}
	if c.waitForMultipathNegotiation() {
		if err := t.init(false); err != nil {
			return nil, err
		}
		return newDeferredPath(c, func() (*Path, error) { return c.addPath(t) }), nil
	}
	return c.addPath(t)
}

func (c *Conn) addPath(t *Transport) (*Path, error) {
	if c.mp == nil {
		return c.addSinglePath(t)
	}
	// With IETF Multipath QUIC, the path is opened to the server address of path 0.
	// c.conn is only replaced when migrating a connection that doesn't use multipath.
	remoteAddr := c.conn.RemoteAddr()
	// Section 2.2 of draft-ietf-quic-multipath-21: disable_active_migration only forbids opening paths to the
	// server's handshake address. Paths to the server's preferred address can be opened once path 0 migrated there.
	if c.peerParams.DisableActiveMigration && peerAddrsEqual(remoteAddr, c.peerHandshakeAddr) {
		return nil, errors.New("server disabled active migration to its handshake address")
	}
	if err := t.init(false); err != nil {
		return nil, err
	}
	return c.newMultipathPath(func() sendConn {
		runner := (*packetHandlerMap)(t)
		c.connIDGenerator.AddConnRunner(
			runner,
			connRunnerCallbacks{
				AddConnectionID:    func(connID protocol.ConnectionID) { runner.Add(connID, c) },
				RemoveConnectionID: runner.Remove,
				ReplaceWithClosed:  runner.ReplaceWithClosed,
			},
		)
		c.resetTokenRunners.AddRunner(runner, c)
		return newSendConn(t.conn, remoteAddr, packetInfo{}, c.logger)
	}), nil
}

// addSinglePath adds a path for RFC 9000 connection migration.
// It must not access c.conn, since the run loop replaces it when switching to a new path.
func (c *Conn) addSinglePath(t *Transport) (*Path, error) {
	// disable_active_migration doesn't apply once the client migrated to the server's preferred address
	// (section 18.2 of RFC 9000).
	if c.peerParams.DisableActiveMigration && !c.migratedToPreferredAddr.Load() {
		return nil, errors.New("server disabled connection migration")
	}
	if err := t.init(false); err != nil {
		return nil, err
	}
	return c.getPathManager().NewPath(
		t,
		200*time.Millisecond, // initial RTT estimate
		func() {
			runner := (*packetHandlerMap)(t)
			c.connIDGenerator.AddConnRunner(
				runner,
				connRunnerCallbacks{
					AddConnectionID:    func(connID protocol.ConnectionID) { runner.Add(connID, c) },
					RemoveConnectionID: runner.Remove,
					ReplaceWithClosed:  runner.ReplaceWithClosed,
				},
			)
			c.resetTokenRunners.AddRunner(runner, c)
		},
	), nil
}

// HandshakeComplete blocks until the handshake completes (or fails).
// For the client, data sent before completion of the handshake is encrypted with 0-RTT keys.
// For the server, data sent before completion of the handshake is encrypted with 1-RTT keys,
// however the client's identity is only verified once the handshake completes.
func (c *Conn) HandshakeComplete() <-chan struct{} {
	return c.handshakeCompleteChan
}

// QlogTrace returns the qlog trace of the QUIC connection.
// It is nil if qlog is not enabled.
func (c *Conn) QlogTrace() qlogwriter.Trace {
	return c.qlogTrace
}

// NextConnection transitions a connection to be usable after a 0-RTT rejection.
// It waits for the handshake to complete and then enables the connection for normal use.
// This should be called when the server rejects 0-RTT and the application receives
// [Err0RTTRejected] errors.
//
// Note that 0-RTT rejection invalidates all data sent in 0-RTT packets. It is the
// application's responsibility to handle this (for example by resending the data).
func (c *Conn) NextConnection(ctx context.Context) (*Conn, error) {
	// The handshake might fail after the server rejected 0-RTT.
	// This could happen if the Finished message is malformed or never received.
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-c.Context().Done():
		return nil, context.Cause(c.Context())
	case <-c.HandshakeComplete():
		c.streamsMap.UseResetMaps()
		return c, nil
	}
}

// estimateMaxPayloadSize estimates the maximum payload size for short header packets.
// It is not very sophisticated: it just subtracts the size of header (assuming the maximum
// connection ID length), and the size of the encryption tag.
func estimateMaxPayloadSize(mtu protocol.ByteCount) protocol.ByteCount {
	return mtu - 1 /* type byte */ - 20 /* maximum connection ID length */ - 16 /* tag size */
}

type multipathEnabler interface {
	EnableMultipath()
}

type multipathPathRegistrar interface {
	RegisterPath(PathInfo)
}

type multipathPathValidator interface {
	ValidatePath(PathID)
}

type multipathPathStateUpdater interface {
	UpdatePathState(PathID, PathStateUpdate)
}

type packetObserverFanout struct {
	observers []ackhandler.PacketObserver
}

func (f *packetObserverFanout) OnPacketSent(ev ackhandler.PacketEvent) {
	for _, observer := range f.observers {
		observer.OnPacketSent(ev)
	}
}

func (f *packetObserverFanout) OnPacketAcked(ev ackhandler.PacketEvent) {
	for _, observer := range f.observers {
		observer.OnPacketAcked(ev)
	}
}

func (f *packetObserverFanout) OnPacketLost(ev ackhandler.PacketEvent) {
	for _, observer := range f.observers {
		observer.OnPacketLost(ev)
	}
}

type multipathReinjectionObserver struct {
	manager *MultipathReinjectionManager
}

func (o *multipathReinjectionObserver) OnPacketSent(ackhandler.PacketEvent) {}

func (o *multipathReinjectionObserver) OnPacketAcked(ev ackhandler.PacketEvent) {
	o.manager.OnPacketAcked(ev.PathID, ev.PacketNumber)
}

func (o *multipathReinjectionObserver) OnPacketLost(ev ackhandler.PacketEvent) {
	frames := make([]ackhandler.Frame, 0, len(ev.Frames)+len(ev.StreamFrames))
	for _, frame := range ev.Frames {
		if frame.Frame == nil {
			continue
		}
		frames = append(frames, frame)
	}
	for _, frame := range ev.StreamFrames {
		if frame.Frame == nil {
			continue
		}
		frames = append(frames, ackhandler.Frame{Frame: frame.Frame, Handler: frame.Handler})
	}
	// Copies of frames sent on another path (IETF Multipath QUIC) are not retransmitted.
	if !hasRetransmittableFrames(frames) {
		return
	}
	o.manager.OnPacketLost(ev.PathID, ev.PacketNumber, ev.EncryptionLevel, frames)
}

func (c *Conn) setupMultipath() {
	c.multipathController = c.selectMultipathController()
	if c.multipathController == nil {
		return
	}
	if c.config.MultipathDuplicationPolicy != nil {
		c.multipathDuplicationPolicy = c.config.MultipathDuplicationPolicy
	}
	if c.config.MultipathReinjectionPolicy != nil {
		c.multipathReinjectionManager = NewMultipathReinjectionManager(c.config.MultipathReinjectionPolicy)
	}
}

// setupMultipathObservers informs the multipath controller and the reinjection manager about the packets sent,
// acknowledged and lost. If the controller implements MultipathObserver, it receives the PathEvents.
// Otherwise, its methods OnPacketSent, OnPacketAcked, OnPacketLost and UpdatePathState are called,
// if it implements them. The connection detects paths that potentially failed (see notifyPathFailureState).
func (c *Conn) setupMultipathObservers() {
	if obs, ok := c.multipathController.(MultipathObserver); ok {
		c.multipathObserver = obs
	}
	if c.multipathObserver == nil {
		_, hasSent := c.multipathController.(interface {
			OnPacketSent(PathID, ByteCount)
		})
		_, hasAcked := c.multipathController.(interface {
			OnPacketAcked(PathID)
		})
		_, hasLost := c.multipathController.(interface {
			OnPacketLost(PathID)
		})
		_, hasUpdate := c.multipathController.(multipathPathStateUpdater)
		if hasSent || hasAcked || hasLost || hasUpdate {
			c.multipathObserver = &multipathControllerObserver{controller: c.multipathController}
		}
	}

	var observers []ackhandler.PacketObserver
	if c.multipathObserver != nil {
		observers = append(observers, &multipathPacketObserver{conn: c})
	}
	if c.multipathReinjectionManager != nil {
		observers = append(observers, &multipathReinjectionObserver{manager: c.multipathReinjectionManager})
	}
	if len(observers) == 0 {
		return
	}
	if len(observers) == 1 {
		c.sentPacketHandler.SetPacketObserver(observers[0])
	} else {
		c.sentPacketHandler.SetPacketObserver(&packetObserverFanout{observers: observers})
	}
}

func packetInfoFromPathInfo(path PathInfo) packetInfo {
	var ip net.IP
	switch addr := path.LocalAddr.(type) {
	case *net.UDPAddr:
		ip = addr.IP
	case *net.IPAddr:
		ip = addr.IP
	}
	if ip == nil {
		return packetInfo{}
	}
	parsed, ok := netip.AddrFromSlice(ip)
	parsed = parsed.Unmap()
	// For an unspecified local address (e.g. a socket bound to [::] or 0.0.0.0),
	// the kernel selects the source address. Passing it as packet info makes sendmsg fail.
	if !ok || parsed.IsUnspecified() {
		return packetInfo{}
	}
	info := packetInfo{addr: parsed}
	if path.IfIndex > 0 {
		info.ifIndex = uint32(path.IfIndex)
	}
	return info
}

type multipathPacketObserver struct {
	conn *Conn
}

func (o *multipathPacketObserver) OnPacketSent(ev ackhandler.PacketEvent) {
	o.conn.multipathObserver.OnPacketSent(o.conn.toPathEvent(ev))
}

func (o *multipathPacketObserver) OnPacketAcked(ev ackhandler.PacketEvent) {
	o.conn.multipathObserver.OnPacketAcked(o.conn.toPathEvent(ev))
}

func (o *multipathPacketObserver) OnPacketLost(ev ackhandler.PacketEvent) {
	o.conn.multipathObserver.OnPacketLost(o.conn.toPathEvent(ev))
}

type multipathControllerObserver struct {
	controller MultipathController
}

func (o *multipathControllerObserver) OnPacketSent(ev PathEvent) {
	if ev.PathID == InvalidPathID || ev.IsPathProbe || ev.IsPathMTUProbe || !ev.AckEliciting {
		return
	}
	if sender, ok := o.controller.(interface {
		OnPacketSent(PathID, ByteCount)
	}); ok {
		sender.OnPacketSent(ev.PathID, ev.PacketSize)
	}
	if updater, ok := o.controller.(interface {
		UpdatePathState(PathID, PathStateUpdate)
	}); ok {
		if update, ok := congestionStateUpdate(ev); ok {
			updater.UpdatePathState(ev.PathID, update)
		}
	}
}

// congestionStateUpdate returns an update of the path's congestion window and bytes in flight.
func congestionStateUpdate(ev PathEvent) (PathStateUpdate, bool) {
	if ev.CongestionWindow == 0 {
		return PathStateUpdate{}, false
	}
	congestionLimited := ev.BytesInFlight >= ev.CongestionWindow
	return PathStateUpdate{
		CongestionWindow:  &ev.CongestionWindow,
		BytesInFlight:     &ev.BytesInFlight,
		CongestionLimited: &congestionLimited,
	}, true
}

func (o *multipathControllerObserver) OnPacketAcked(ev PathEvent) {
	if ev.PathID == InvalidPathID || ev.IsPathProbe || ev.IsPathMTUProbe || !ev.AckEliciting {
		return
	}
	if acked, ok := o.controller.(interface {
		OnPacketAcked(PathID)
	}); ok {
		acked.OnPacketAcked(ev.PathID)
	}
	if updater, ok := o.controller.(interface {
		UpdatePathState(PathID, PathStateUpdate)
	}); ok {
		// Acknowledgements don't validate a path, see section 8.2 of RFC 9000.
		// Paths are only validated by PATH_RESPONSE frames.
		update, hasUpdate := congestionStateUpdate(ev)
		if ev.SmoothedRTT > 0 {
			update.SmoothedRTT = &ev.SmoothedRTT
			update.RTTVar = &ev.RTTVar
			hasUpdate = true
		}
		if hasUpdate {
			updater.UpdatePathState(ev.PathID, update)
		}
	}
}

func (o *multipathControllerObserver) OnPacketLost(ev PathEvent) {
	if ev.PathID == InvalidPathID || ev.IsPathProbe || ev.IsPathMTUProbe || !ev.AckEliciting {
		return
	}
	if lost, ok := o.controller.(interface {
		OnPacketLost(PathID)
	}); ok {
		lost.OnPacketLost(ev.PathID)
	}
}

func (c *Conn) toPathEvent(ev ackhandler.PacketEvent) PathEvent {
	event := PathEvent{
		PathID:          ev.PathID,
		PacketNumber:    ev.PacketNumber,
		PacketSize:      ev.Length,
		EncryptionLevel: ev.EncryptionLevel,
		AckEliciting:    ev.IsAckEliciting,
		IsPathProbe:     ev.IsPathProbePacket,
		IsPathMTUProbe:  ev.IsPathMTUProbePacket,
		SentAt:          ev.SendTime.ToTime(),
		EventAt:         ev.EventTime.ToTime(),
	}
	// With IETF Multipath QUIC, packets carrying copies of frames sent on another path are registered with
	// sendingCopies set (see sendFrameCopies).
	if c.mp != nil && c.mp.sendingCopies {
		event.IsDuplicate = true
	}
	if stats := c.sentPacketHandler.GetPathRTTStats(ev.PathID); stats != nil {
		event.SmoothedRTT = stats.SmoothedRTT()
		event.RTTVar = stats.MeanDeviation()
	}
	if cwnd, bytesInFlight, ok := c.pathCongestion(ev.PathID); ok {
		event.CongestionWindow = cwnd
		event.BytesInFlight = bytesInFlight
	}
	return event
}

type rawFrame struct {
	frameType    uint64
	data         []byte
	ackEliciting bool
}

var _ wire.Frame = &rawFrame{}

func (f *rawFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, f.frameType)
	b = append(b, f.data...)
	return b, nil
}

func (f *rawFrame) Length(_ protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(f.frameType) + len(f.data))
}

func (f *rawFrame) AckEliciting() bool {
	return f.ackEliciting
}

type rawFrameHandler struct {
	conn       *Conn
	frame      *rawFrame
	onAcked    func()
	onLost     func()
	retransmit bool
}

var _ ackhandler.FrameHandler = &rawFrameHandler{}

func (h *rawFrameHandler) OnAcked(wire.Frame) {
	if h.onAcked != nil {
		h.onAcked()
	}
}

func (h *rawFrameHandler) OnLost(wire.Frame) {
	if h.onLost != nil {
		h.onLost()
	}
	if h.retransmit {
		h.conn.framer.QueueControlFrameWithHandler(h.frame, h)
		h.conn.scheduleSending()
	}
}

// QueueRawFrame queues a custom frame for sending.
// It returns an error if the frame type is used by QUIC or one of its extensions
// (including the multipath extensions), or doesn't fit into a varint.
func (c *Conn) QueueRawFrame(frame RawFrame) error {
	if frame.FrameType > quicvarint.Max {
		return fmt.Errorf("frame type %#x doesn't fit into a varint", frame.FrameType)
	}
	if wire.IsReservedFrameType(frame.FrameType) {
		return fmt.Errorf("frame type %#x is reserved", frame.FrameType)
	}
	data := append([]byte(nil), frame.Data...)
	rf := &rawFrame{
		frameType:    frame.FrameType,
		data:         data,
		ackEliciting: !frame.NonAckEliciting,
	}
	if frame.OnAcked != nil || frame.OnLost != nil || frame.RetransmitOnLoss {
		h := &rawFrameHandler{
			conn:       c,
			frame:      rf,
			onAcked:    frame.OnAcked,
			onLost:     frame.OnLost,
			retransmit: frame.RetransmitOnLoss,
		}
		c.framer.QueueControlFrameWithHandler(rf, h)
	} else {
		c.framer.QueueControlFrame(rf)
	}
	c.scheduleSending()
	return nil
}
