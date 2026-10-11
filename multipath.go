package quic

import (
	"fmt"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/internal/utils"
	"github.com/AeonDave/mp-quic-go/internal/wire"
	"github.com/AeonDave/mp-quic-go/qlog"
)

// multipathEnabledLocally says if IETF Multipath QUIC (draft-ietf-quic-multipath-21) is enabled
// for a connection with this multipath controller: it is enabled if a controller is configured.
func multipathEnabledLocally(ctrl MultipathController) bool {
	return ctrl != nil
}

// shouldAdvertiseMultipath says if a connection advertises the initial_max_path_id transport parameter.
// Section 2.1 of draft-ietf-quic-multipath-21: endpoints advertising it MUST use source and destination
// connection IDs with non-zero lengths.
var shouldAdvertiseMultipath = func(ctrl MultipathController, srcConnID, destConnID protocol.ConnectionID) bool {
	return multipathEnabledLocally(ctrl) && srcConnID.Len() > 0 && destConnID.Len() > 0
}

// localInitialMaxPathID is the value of the initial_max_path_id transport parameter.
// Config.MaxPaths is the number of path IDs that can be in use at the same time, including path 0.
func localInitialMaxPathID(conf *Config) protocol.PathID {
	return protocol.PathID(min(max(conf.MaxPaths, 1), protocol.MaxMultipathPaths) - 1)
}

// multipathConfigured says if the config enables multipath.
func multipathConfigured(conf *Config) bool {
	return conf != nil && (conf.MultipathController != nil || conf.MultipathControllerFactory != nil)
}

// peerPathStatus is the last PATH_STATUS_AVAILABLE or PATH_STATUS_BACKUP frame received for a path ID.
type peerPathStatus struct {
	seq    uint64
	backup bool
}

// multipathState is the state of IETF Multipath QUIC (draft-ietf-quic-multipath-21).
// It is created when both endpoints advertised the initial_max_path_id transport parameter.
// From then on, the frames of the extension are processed. They are only sent once the extension is active,
// i.e. after completion of the handshake (section 2 of the draft).
type multipathState struct {
	active bool

	// The maximum path ID announced to the peer.
	// It is increased by one every time a path is closed, such that the number of path IDs
	// that are not closed doesn't exceed Config.MaxPaths (section 4.6 of draft-ietf-quic-multipath-21).
	localMaxPathID protocol.PathID
	// the peer's initial_max_path_id, and the largest maximum path ID announced by the peer
	peerInitialMaxPathID protocol.PathID
	peerMaxPathID        protocol.PathID

	// The paths, including abandoned paths that are not closed yet.
	// Path 0 is the path that the handshake was performed on.
	paths map[protocol.PathID]*mpPath
	// the IDs of the paths, in ascending order
	pathIDs []protocol.PathID
	// Path IDs that the peer abandoned before they were used, and the time at which they are closed.
	unusedAbandoned map[protocol.PathID]monotime.Time
	// Path IDs that were closed. A path ID is never used again (section 3.4 of draft-ietf-quic-multipath-21).
	closed utils.PathIDSet
	// path status received for path IDs that are not open yet
	pendingPeerStatus map[protocol.PathID]peerPathStatus

	// The primary path. LocalAddr, RemoteAddr and ConnectionStats refer to this path.
	// It is path 0, until path 0 is abandoned, or the application switches to another path.
	primaryPathID protocol.PathID
	// The path that the application switched to (see Path.Switch).
	// As long as it can be used, data is only sent on this path.
	preferredPathID  protocol.PathID
	hasPreferredPath bool

	// detects paths that potentially failed
	failures *pathFailureDetector
	// the state shared by the coupled congestion controllers of the paths, if OLIA is used
	olia *oliaSharedState
	// Set when the status signaled for the paths might need to be updated,
	// because a path potentially failed or recovered, or the status of a path changed.
	statusUpdateDue bool

	// The addresses of the client that the server validated, the most recently validated address last.
	// Tokens are valid for these addresses (section 3.1.3 of draft-ietf-quic-multipath-21).
	validatedClientAddrs []net.Addr

	// the path of the last 1-RTT packet received
	lastRcvdPathID protocol.PathID

	// frames queued before the extension became active
	pendingFrames []ackhandler.Frame

	// requests from the application, processed on the connection's run loop
	requestsMx sync.Mutex
	requests   []mpRequest
	// paths that the application wants to open, waiting for an unused path ID (client only)
	pendingOpens []*mpPathHandle
	// the maximum path ID sent in the last PATHS_BLOCKED frame
	pathsBlockedSent bool
	pathsBlockedMax  protocol.PathID
	// the path ID and the next sequence number sent in the last PATH_CIDS_BLOCKED frame
	pathCIDsBlockedSent bool
	pathCIDsBlocked     wire.PathCIDsBlockedFrame
	// Did we send a PATH_CHALLENGE frame to validate a path?
	sentPathChallenge bool

	// used to pass the PATH_ACK frames of a sent packet to the sent packet handler, to avoid allocations
	pathAcks [4]ackhandler.PathAck
	// the path that the last packet selected by the scheduler was sent on
	lastSendPathID protocol.PathID
	// Set while a packet containing copies of frames sent on another path is registered (see sendFrameCopies).
	sendingCopies bool
	// used for the paths that are used for sending, to avoid allocations
	usablePaths    []*mpPath
	dataPaths      []*mpPath
	candidatePaths []*mpPath
	candidateInfos []PathInfo
	pathInfos      []PathInfo
}

func newMultipathState(localMaxPathID, peerMaxPathID protocol.PathID) *multipathState {
	return &multipathState{
		localMaxPathID:       localMaxPathID,
		peerInitialMaxPathID: peerMaxPathID,
		peerMaxPathID:        peerMaxPathID,
		paths:                map[protocol.PathID]*mpPath{0: {id: 0, state: mpPathActive, largestRcvdPN: protocol.InvalidPacketNumber}},
		pathIDs:              []protocol.PathID{0},
		failures:             newPathFailureDetector(),
	}
}

// checkPathID checks that a path ID received in a frame doesn't exceed the maximum path ID announced to the peer.
// Section 4 of draft-ietf-quic-multipath-21: this MUST be treated as a connection error of type PROTOCOL_VIOLATION.
func (m *multipathState) checkPathID(id protocol.PathID, frameType wire.FrameType) error {
	if id > m.localMaxPathID {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			FrameType:    uint64(frameType),
			ErrorMessage: fmt.Sprintf("path ID %d exceeds the maximum path ID (%d)", id, m.localMaxPathID),
		}
	}
	return nil
}

// isAbandoned says if a path ID was abandoned, including path IDs that were abandoned before they were used,
// and path IDs that were closed.
func (m *multipathState) isAbandoned(id protocol.PathID) bool {
	if path, ok := m.paths[id]; ok {
		return path.state == mpPathAbandoned
	}
	_, ok := m.unusedAbandoned[id]
	return ok || m.closed.Contains(id)
}

// isClosed says if a path ID was closed: it was abandoned, and all state was removed.
// Frames referring to a closed path ID are ignored (section 4 of draft-ietf-quic-multipath-21).
func (m *multipathState) isClosed(id protocol.PathID) bool {
	return m.closed.Contains(id)
}

// isUsed says if a path ID was used, i.e. if a path with this ID exists or was abandoned.
func (m *multipathState) isUsed(id protocol.PathID) bool {
	_, ok := m.paths[id]
	return ok || m.isAbandoned(id)
}

// isClosingPath says if a path ID will be closed: an abandoned path that is not a zombie,
// or a path ID that was abandoned before it was used.
func (m *multipathState) isClosingPath() bool {
	if len(m.unusedAbandoned) > 0 {
		return true
	}
	for _, id := range m.pathIDs {
		if path := m.paths[id]; path.state == mpPathAbandoned && (!path.zombie || path.abandonRcvd) {
			return true
		}
	}
	return false
}

// abandonUnusedPath is called when the peer abandons a path ID that was not used yet.
// The path ID is closed at closeTime.
func (m *multipathState) abandonUnusedPath(id protocol.PathID, closeTime monotime.Time) {
	if m.unusedAbandoned == nil {
		m.unusedAbandoned = make(map[protocol.PathID]monotime.Time)
	}
	m.unusedAbandoned[id] = closeTime
	delete(m.pendingPeerStatus, id)
}

// removePath removes a closed path, or a path ID that was abandoned before it was used.
func (m *multipathState) removePath(id protocol.PathID) {
	delete(m.paths, id)
	if idx, found := slices.BinarySearch(m.pathIDs, id); found {
		m.pathIDs = slices.Delete(m.pathIDs, idx, idx+1)
	}
	delete(m.unusedAbandoned, id)
	delete(m.pendingPeerStatus, id)
	m.failures.remove(id)
	m.closed.Add(id)
}

// addPath adds a new path, which is being validated.
// The path status that the peer sent for the path ID before is applied.
func (m *multipathState) addPath(id protocol.PathID, conn sendConn) *mpPath {
	path := &mpPath{id: id, state: mpPathValidating, conn: conn, largestRcvdPN: protocol.InvalidPacketNumber}
	if s, ok := m.pendingPeerStatus[id]; ok {
		path.peerStatus = s
		path.hasPeerStatus = true
		delete(m.pendingPeerStatus, id)
	}
	m.paths[id] = path
	idx, _ := slices.BinarySearch(m.pathIDs, id)
	m.pathIDs = slices.Insert(m.pathIDs, idx, id)
	return path
}

// hasOtherUsablePath says if a path other than the given one can be used for sending.
func (m *multipathState) hasOtherUsablePath(id protocol.PathID) bool {
	for _, pid := range m.pathIDs {
		if pid != id && m.paths[pid].usable() {
			return true
		}
	}
	return false
}

// hasOtherOpenPath says if a path other than the given one is open, i.e. not abandoned.
// This includes paths that are still being validated: a path is open once the first packet was sent or received
// on it (section 3.1 of draft-ietf-quic-multipath-21).
func (m *multipathState) hasOtherOpenPath(id protocol.PathID) bool {
	for _, pid := range m.pathIDs {
		if pid != id && m.paths[pid].state != mpPathAbandoned {
			return true
		}
	}
	return false
}

// pathForConn returns the path that is not abandoned, and that sends using the sendConn.
func (m *multipathState) pathForConn(conn sendConn) *mpPath {
	for _, id := range m.pathIDs {
		if path := m.paths[id]; path.conn == conn && path.state != mpPathAbandoned {
			return path
		}
	}
	return nil
}

// closePathID returns the path that a CONNECTION_CLOSE is sent on:
// the path that the last packet was received on, if it can be used for sending,
// and the active path with the lowest path ID otherwise.
// It returns false if no path can be used for sending.
func (m *multipathState) closePathID() (protocol.PathID, bool) {
	if path, ok := m.paths[m.lastRcvdPathID]; ok && path.usable() {
		return m.lastRcvdPathID, true
	}
	for _, id := range m.pathIDs {
		if m.paths[id].usable() {
			return id, true
		}
	}
	return 0, false
}

// nextTimeout returns the time of the next event of the multipath state:
// when a path validation times out, when the next PATH_CHALLENGE is due, when an abandoned path is closed,
// when a path is considered potentially failed, or when the status signaled for a path can be updated.
func (m *multipathState) nextTimeout() monotime.Time {
	var t monotime.Time
	update := func(deadline monotime.Time) {
		if !deadline.IsZero() && (t.IsZero() || deadline.Before(t)) {
			t = deadline
		}
	}
	for _, id := range m.pathIDs {
		path := m.paths[id]
		switch path.state {
		case mpPathValidating:
			update(path.validationDeadline)
			if !path.challengeDue {
				update(path.nextChallenge)
			}
		case mpPathActive:
			if d := m.failures.deadline(id); !d.IsZero() {
				update(monotime.FromTime(d))
			}
			update(path.statusUpdateTime)
		case mpPathAbandoned:
			if !path.zombie || path.abandonRcvd {
				update(path.retainUntil)
			}
		}
	}
	for _, closeTime := range m.unusedAbandoned {
		update(closeTime)
	}
	return t
}

// postRequest posts a request from the application to the connection's run loop.
// It is safe to call it from any goroutine.
func (m *multipathState) postRequest(r mpRequest) {
	m.requestsMx.Lock()
	defer m.requestsMx.Unlock()

	m.requests = append(m.requests, r)
}

func (m *multipathState) takeRequests() []mpRequest {
	m.requestsMx.Lock()
	defer m.requestsMx.Unlock()

	requests := m.requests
	m.requests = nil
	return requests
}

// maybeSendPathsBlocked sends a PATHS_BLOCKED frame, unless it was already sent for the peer's maximum path ID
// (sections 3.2.1 and 4.7 of draft-ietf-quic-multipath-21).
func (m *multipathState) maybeSendPathsBlocked(c *Conn) {
	if m.pathsBlockedSent && m.pathsBlockedMax == m.peerMaxPathID {
		return
	}
	m.pathsBlockedSent = true
	m.pathsBlockedMax = m.peerMaxPathID
	c.queueMultipathFrame(ackhandler.Frame{
		Frame:   &wire.PathsBlockedFrame{MaximumPathID: m.peerMaxPathID},
		Handler: &blockedFrameHandler{conn: c},
	})
}

// maybeSendPathCIDsBlocked sends a PATH_CIDS_BLOCKED frame, unless it was already sent for the path ID
// and the sequence number (sections 3.2.2 and 4.7 of draft-ietf-quic-multipath-21).
func (m *multipathState) maybeSendPathCIDsBlocked(c *Conn, id protocol.PathID, nextSeq uint64) {
	f := wire.PathCIDsBlockedFrame{PathID: id, NextSequenceNumber: nextSeq}
	if m.pathCIDsBlockedSent && m.pathCIDsBlocked == f {
		return
	}
	m.pathCIDsBlockedSent = true
	m.pathCIDsBlocked = f
	c.queueMultipathFrame(ackhandler.Frame{Frame: &f, Handler: &blockedFrameHandler{conn: c}})
}

// blockedFrameHandler retransmits lost PATHS_BLOCKED and PATH_CIDS_BLOCKED frames,
// if they are still the latest of their kind and opening a path is still blocked
// (section 4.7 of draft-ietf-quic-multipath-21).
type blockedFrameHandler struct {
	conn *Conn
}

var _ ackhandler.FrameHandler = &blockedFrameHandler{}

func (h *blockedFrameHandler) OnAcked(wire.Frame) {}

func (h *blockedFrameHandler) OnLost(f wire.Frame) {
	m := h.conn.mp
	if len(m.pendingOpens) == 0 {
		return
	}
	switch f := f.(type) {
	case *wire.PathsBlockedFrame:
		if f.MaximumPathID != m.peerMaxPathID {
			return
		}
	case *wire.PathCIDsBlockedFrame:
		if *f != m.pathCIDsBlocked || h.conn.peerConnIDs.HasConnID(f.PathID) {
			return
		}
	}
	h.conn.queueMultipathFrame(ackhandler.Frame{Frame: f, Handler: h})
}

// setPeerStatus handles a PATH_STATUS_AVAILABLE or PATH_STATUS_BACKUP frame.
// Frames with a sequence number that is not larger than the sequence number of the last frame received
// for the path ID are ignored (section 4.3 of draft-ietf-quic-multipath-21).
// The status of path IDs that are not open yet is applied when the path is opened.
func (m *multipathState) setPeerStatus(id protocol.PathID, status peerPathStatus) {
	if path, ok := m.paths[id]; ok {
		if path.hasPeerStatus && status.seq <= path.peerStatus.seq {
			return
		}
		path.peerStatus = status
		path.hasPeerStatus = true
		m.statusUpdateDue = true
		return
	}
	if s, ok := m.pendingPeerStatus[id]; ok && status.seq <= s.seq {
		return
	}
	if m.pendingPeerStatus == nil {
		m.pendingPeerStatus = make(map[protocol.PathID]peerPathStatus)
	}
	m.pendingPeerStatus[id] = status
}

// queuePathFrame queues a frame that needs to be sent on a specific path.
func (m *multipathState) queuePathFrame(id protocol.PathID, f ackhandler.Frame) {
	path, ok := m.paths[id]
	if !ok || path.state == mpPathAbandoned {
		return
	}
	// Only queue a limited number of frames per path.
	// This limit should be high enough to never be hit in practice, unless the peer is doing something malicious.
	if len(path.frames) >= maxPathResponses {
		return
	}
	path.frames = append(path.frames, f)
}

// HasPathFrames says if there are frames to send on a path.
func (m *multipathState) HasPathFrames(id protocol.PathID) bool {
	path, ok := m.paths[id]
	return ok && len(path.frames) > 0
}

// AppendPathFrames appends the frames that need to be sent on a path, as long as they fit into maxLen.
// Like the framer, it only packs a single PATH_RESPONSE frame per packet.
func (m *multipathState) AppendPathFrames(frames []ackhandler.Frame, id protocol.PathID, maxLen protocol.ByteCount, v protocol.Version) ([]ackhandler.Frame, protocol.ByteCount) {
	path, ok := m.paths[id]
	if !ok {
		return frames, 0
	}
	var length protocol.ByteCount
	var hasPathResponse bool
	for len(path.frames) > 0 {
		f := path.frames[0]
		if _, ok := f.Frame.(*wire.PathResponseFrame); ok {
			if hasPathResponse {
				break
			}
			hasPathResponse = true
		}
		l := f.Frame.Length(v)
		if length+l > maxLen {
			break
		}
		frames = append(frames, f)
		length += l
		path.frames[0] = ackhandler.Frame{}
		path.frames = path.frames[1:]
	}
	return frames, length
}

// queueMultipathFrame queues a frame of the multipath extension.
// Frames are only sent once the extension is active.
func (c *Conn) queueMultipathFrame(f ackhandler.Frame) {
	if !c.mp.active {
		c.mp.pendingFrames = append(c.mp.pendingFrames, f)
		return
	}
	c.framer.QueueControlFrameWithHandler(f.Frame, f.Handler)
	c.scheduleSending()
}

// maxPTO returns the PTO used for timers that apply to the whole connection.
// With IETF Multipath QUIC, it is the largest PTO among all paths (section 2.6 of draft-ietf-quic-multipath-21).
func (c *Conn) maxPTO(includeMaxAckDelay bool) time.Duration {
	if c.mp == nil {
		return c.rttStats.PTO(includeMaxAckDelay)
	}
	return c.sentPacketHandler.MaxPTO(includeMaxAckDelay)
}

// checkMultipathTransportParameters checks the initial_max_path_id transport parameter,
// if IETF Multipath QUIC is enabled locally.
// This includes connections that didn't advertise the extension because of zero-length connection IDs.
// Otherwise, the transport parameter is ignored, like every other unknown transport parameter
// (section 18.1 of RFC 9000).
func (c *Conn) checkMultipathTransportParameters(params *wire.TransportParameters) error {
	if !multipathEnabledLocally(c.multipathController) || !params.HasInitialMaxPathID {
		return nil
	}
	// section 2.1 of draft-ietf-quic-multipath-21
	if params.InitialMaxPathID > protocol.MaxPathID {
		return &qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: fmt.Sprintf("initial_max_path_id too large: %d", params.InitialMaxPathID),
		}
	}
	// The initial_source_connection_id is the source connection ID of the packet carrying the transport parameters.
	// The client receives the server's transport parameters in Handshake packets sent to the client's source
	// connection ID. The server receives the client's transport parameters in Initial packets sent to a
	// connection ID that the client chose with a length of at least 8 bytes (section 7.2 of RFC 9000),
	// or, after a Retry, to the source connection ID of the Retry, which might have a zero length.
	destConnIDLen := c.srcConnIDLen
	if c.perspective == protocol.PerspectiveServer {
		destConnIDLen = c.clientDestConnIDLen
	}
	if params.InitialSourceConnectionID.Len() == 0 || destConnIDLen == 0 {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "received initial_max_path_id in a packet with a zero-length connection ID",
		}
	}
	return nil
}

// maybeNegotiateMultipath is called when the peer's transport parameters are received.
// If both endpoints advertised the initial_max_path_id transport parameter, the frames of the
// multipath extension are processed from now on.
func (c *Conn) maybeNegotiateMultipath(params *wire.TransportParameters) error {
	if !c.advertisedMultipath || !params.HasInitialMaxPathID {
		return nil
	}
	c.mp = newMultipathState(localInitialMaxPathID(c.config), params.InitialMaxPathID)
	return c.cryptoStreamHandler.EnableMultipath(func() time.Duration {
		return c.sentPacketHandler.MaxPTO(true)
	})
}

// activateMultipath is called when the handshake completes.
// From now on, 1-RTT packets are acknowledged using PATH_ACK frames, connection IDs are issued and retired using
// PATH_NEW_CONNECTION_ID and PATH_RETIRE_CONNECTION_ID frames (for path 0 as well), and connection IDs are issued
// for the unused path IDs, such that the client can open new paths (sections 2.3, 3.2 and 3.2.1 of the draft).
func (c *Conn) activateMultipath() error {
	c.mp.active = true
	c.mp.paths[0].maxDatagramSize = protocol.ByteCount(c.config.InitialPacketSize)
	if c.config.MultipathCongestionControl == MultipathCongestionControlOLIA {
		// Every path has its own congestion controller, coupled to the controllers of the other paths
		// (section 5.3 of draft-ietf-quic-multipath-21). The factory also creates the controller of path 0,
		// which continues with the state of the controller used during the handshake.
		c.mp.olia = NewOLIASharedState()
		c.sentPacketHandler.SetCongestionControlFactory(NewOLIACongestionControlFactory(c.mp.olia))
	}
	c.sentPacketHandler.EnableMultipath(c.receivedPacketHandler.IgnorePacketsBelowForPath)
	c.receivedPacketHandler.EnableMultipath()
	c.peerConnIDs.EnableMultipath()
	c.packer.EnableMultipath(c.peerConnIDs.Get, c.mp)
	if err := c.connIDGenerator.EnableMultipath(c.mp.localMaxPathID, c.mp.peerMaxPathID); err != nil {
		return err
	}
	for _, f := range c.mp.pendingFrames {
		c.framer.QueueControlFrameWithHandler(f.Frame, f.Handler)
	}
	c.mp.pendingFrames = nil
	c.notifyMultipathActive()
	c.updatePathsSnapshot()
	c.scheduleSending()
	return nil
}

// multipathReceivePathID returns the path of a 1-RTT packet, based on its destination connection ID
// (section 3.2.2 of draft-ietf-quic-multipath-21).
// For the server, newPath is true if the packet was received on a path ID that is not in use yet.
// The path is created once the packet was decrypted (section 3.1).
// If the packet needs to be dropped, it returns the reason.
func (c *Conn) multipathReceivePathID(destConnID protocol.ConnectionID, remoteAddr net.Addr) (_ protocol.PathID, newPath bool, _ qlog.PacketDropReason) {
	id, ok := c.connIDGenerator.PathForConnID(destConnID)
	if !ok {
		return 0, false, qlog.PacketDropUnknownConnectionID
	}
	// Packets received on abandoned paths are processed, until the path's state is removed.
	if path, ok := c.mp.paths[id]; ok {
		if path.zombie {
			return 0, false, qlog.PacketDropUnexpectedPacket
		}
		// A client MUST discard packets from unknown server addresses (section 9 of RFC 9000).
		// Every path has its own server address.
		if c.perspective == protocol.PerspectiveClient && !c.isKnownServerAddr(path, remoteAddr) {
			return 0, false, qlog.PacketDropUnexpectedPacket
		}
		return id, false, ""
	}
	// Only the client opens paths. It drops packets for path IDs that it didn't open.
	// Path IDs that were abandoned before they were used are never used.
	if c.perspective == protocol.PerspectiveClient || !c.mp.active || c.mp.isAbandoned(id) {
		return 0, false, qlog.PacketDropUnexpectedPacket
	}
	return id, true, ""
}

// handleMultipathFrame handles the frames of the multipath extension, except for PATH_ACK.
func (c *Conn) handleMultipathFrame(f wire.Frame, destConnID protocol.ConnectionID, rcvTime monotime.Time) error {
	switch frame := f.(type) {
	case *wire.PathAbandonFrame:
		return c.handlePathAbandonFrame(frame, rcvTime)
	case *wire.PathStatusFrame:
		return c.handlePathStatusFrame(frame)
	case *wire.PathNewConnectionIDFrame:
		if err := c.mp.checkPathID(frame.PathID, wire.FrameTypePathNewConnectionID); err != nil {
			return err
		}
		// Connection IDs for abandoned and closed paths are ignored.
		if c.mp.isClosed(frame.PathID) {
			return nil
		}
		return c.peerConnIDs.Add(frame)
	case *wire.PathRetireConnectionIDFrame:
		if err := c.mp.checkPathID(frame.PathID, wire.FrameTypePathRetireConnectionID); err != nil {
			return err
		}
		// The connection IDs of closed paths were already removed.
		if c.mp.isClosed(frame.PathID) {
			return nil
		}
		return c.connIDGenerator.RetireForPath(frame.PathID, frame.SequenceNumber, destConnID, rcvTime.Add(3*c.maxPTO(false)))
	case *wire.MaxPathIDFrame:
		return c.handleMaxPathIDFrame(frame)
	case *wire.PathsBlockedFrame:
		// Section 4.7 of draft-ietf-quic-multipath-21.
		// PATHS_BLOCKED frames are informational.
		if frame.MaximumPathID > c.mp.localMaxPathID {
			return &qerr.TransportError{
				ErrorCode:    qerr.ProtocolViolation,
				FrameType:    uint64(wire.FrameTypePathsBlocked),
				ErrorMessage: fmt.Sprintf("PATHS_BLOCKED for maximum path ID %d, which exceeds the maximum path ID (%d)", frame.MaximumPathID, c.mp.localMaxPathID),
			}
		}
		return nil
	case *wire.PathCIDsBlockedFrame:
		return c.handlePathCIDsBlockedFrame(frame)
	default:
		return fmt.Errorf("unexpected frame type: %T", f)
	}
}

func (c *Conn) handlePathAbandonFrame(f *wire.PathAbandonFrame, rcvTime monotime.Time) error {
	if err := c.mp.checkPathID(f.PathID, wire.FrameTypePathAbandon); err != nil {
		return err
	}
	// The path was closed already, or the frame is a retransmission.
	if _, ok := c.mp.unusedAbandoned[f.PathID]; ok || c.mp.isClosed(f.PathID) {
		return nil
	}
	path, ok := c.mp.paths[f.PathID]
	if !ok {
		// The peer abandoned a path ID that is not in use. This is not an error (section 3.4).
		// The path ID can't be used anymore.
		c.logger.Debugf("Peer abandoned unused path %d (error code %d).", f.PathID, f.ErrorCode)
		// The connection IDs issued for this path ID are retained for 3 PTOs (section 3.4).
		c.mp.abandonUnusedPath(f.PathID, rcvTime.Add(3*c.maxPTO(false)))
		c.connIDGenerator.AbandonPath(f.PathID)
		c.peerConnIDs.AbandonPath(f.PathID)
		c.queuePathAbandonFrame(f.PathID, qerr.NoError)
		return nil
	}
	if path.state == mpPathAbandoned {
		// We abandoned the path before. This is the peer's PATH_ABANDON frame.
		// The path's state is retained for 3 PTOs after the PATH_ABANDON frames were exchanged.
		if !path.abandonRcvd {
			c.logger.Debugf("Peer abandoned path %d (error code %d).", f.PathID, f.ErrorCode)
			path.abandonRcvd = true
			path.retainUntil = rcvTime.Add(3 * max(c.maxPTO(false), path.abandonPTO))
		}
		return nil
	}
	if !c.mp.hasOtherOpenPath(f.PathID) {
		// Section 3.4 of draft-ietf-quic-multipath-21: if the peer abandons the only open path,
		// the receiving peer SHOULD send a CONNECTION_CLOSE frame and enter the closing state.
		// We don't reply with a PATH_ABANDON frame: we couldn't send the CONNECTION_CLOSE on the path afterwards.
		return &qerr.TransportError{
			ErrorCode:    qerr.NoViablePathError,
			FrameType:    uint64(wire.FrameTypePathAbandon),
			ErrorMessage: fmt.Sprintf("peer abandoned path %d, the only open path (error code %d)", f.PathID, f.ErrorCode),
		}
	}
	c.logger.Debugf("Peer abandoned path %d (error code %d).", f.PathID, f.ErrorCode)
	c.markPathAbandoned(path, rcvTime, ErrPathClosed)
	path.abandonRcvd = true
	// Section 3.4: we MUST reply with a PATH_ABANDON frame.
	// If the other open paths are still being validated, it is sent once one of them can be used for sending.
	// If their validation fails, no path is left, and the connection is closed (see handleMultipathEvents).
	c.queuePathAbandonFrame(f.PathID, qerr.NoError)
	return nil
}

// queuePathAbandonFrame queues a PATH_ABANDON frame.
// It is sent on any path that can be used for sending, i.e. never on the abandoned path itself,
// unless no other path is left (section 3.4 of draft-ietf-quic-multipath-21).
func (c *Conn) queuePathAbandonFrame(id protocol.PathID, code qerr.TransportErrorCode) {
	c.queueMultipathFrame(ackhandler.Frame{
		Frame:   &wire.PathAbandonFrame{PathID: id, ErrorCode: code},
		Handler: &pathAbandonFrameHandler{conn: c},
	})
}

// pathAbandonFrameHandler retransmits lost PATH_ABANDON frames (section 4.2 of draft-ietf-quic-multipath-21),
// until the path is closed. The peer needs our PATH_ABANDON frame to remove the path's state,
// also if it abandoned the path first.
type pathAbandonFrameHandler struct {
	conn *Conn
}

var _ ackhandler.FrameHandler = &pathAbandonFrameHandler{}

func (h *pathAbandonFrameHandler) OnAcked(wire.Frame) {}

func (h *pathAbandonFrameHandler) OnLost(f wire.Frame) {
	if h.conn.mp.isClosed(f.(*wire.PathAbandonFrame).PathID) {
		return
	}
	h.conn.queueMultipathFrame(ackhandler.Frame{Frame: f, Handler: h})
}

func (c *Conn) handlePathStatusFrame(f *wire.PathStatusFrame) error {
	frameType := wire.FrameTypePathStatusAvailable
	if f.Backup {
		frameType = wire.FrameTypePathStatusBackup
	}
	if err := c.mp.checkPathID(f.PathID, frameType); err != nil {
		return err
	}
	if c.mp.isAbandoned(f.PathID) {
		return nil
	}
	c.mp.setPeerStatus(f.PathID, peerPathStatus{seq: f.SequenceNumber, backup: f.Backup})
	return nil
}

// raiseMaxPathID is called when a path is closed.
// It increases the maximum path ID by one, so that the peer can open a new path (section 4.6 of the draft),
// and issues connection IDs for the path IDs that can be used now.
func (c *Conn) raiseMaxPathID() error {
	if c.mp.localMaxPathID >= protocol.MaxPathID {
		return nil
	}
	c.mp.localMaxPathID++
	c.queueMultipathFrame(ackhandler.Frame{
		Frame:   &wire.MaxPathIDFrame{MaximumPathID: c.mp.localMaxPathID},
		Handler: &maxPathIDFrameHandler{conn: c},
	})
	return c.connIDGenerator.IssueForUnusedPaths(c.mp.localMaxPathID)
}

// maxPathIDFrameHandler retransmits a lost MAX_PATH_ID frame,
// unless a MAX_PATH_ID frame with a larger maximum path ID was sent since (section 4.6 of the draft).
type maxPathIDFrameHandler struct {
	conn *Conn
}

var _ ackhandler.FrameHandler = &maxPathIDFrameHandler{}

func (h *maxPathIDFrameHandler) OnAcked(wire.Frame) {}

func (h *maxPathIDFrameHandler) OnLost(f wire.Frame) {
	if f.(*wire.MaxPathIDFrame).MaximumPathID != h.conn.mp.localMaxPathID {
		return
	}
	h.conn.queueMultipathFrame(ackhandler.Frame{Frame: f, Handler: h})
}

func (c *Conn) handleMaxPathIDFrame(f *wire.MaxPathIDFrame) error {
	// section 4.6 of draft-ietf-quic-multipath-21
	if f.MaximumPathID > protocol.MaxPathID || f.MaximumPathID < c.mp.peerInitialMaxPathID {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			FrameType:    uint64(wire.FrameTypeMaxPathID),
			ErrorMessage: fmt.Sprintf("invalid maximum path ID: %d (initial_max_path_id: %d)", f.MaximumPathID, c.mp.peerInitialMaxPathID),
		}
	}
	// MAX_PATH_ID frames that don't increase the limit MUST be ignored.
	if f.MaximumPathID <= c.mp.peerMaxPathID {
		return nil
	}
	c.mp.peerMaxPathID = f.MaximumPathID
	// Issue connection IDs for the path IDs that can be used now.
	return c.connIDGenerator.SetPeerMaxPathID(f.MaximumPathID)
}

func (c *Conn) handlePathCIDsBlockedFrame(f *wire.PathCIDsBlockedFrame) error {
	if err := c.mp.checkPathID(f.PathID, wire.FrameTypePathCIDsBlocked); err != nil {
		return err
	}
	// The state of closed paths was removed.
	if c.mp.isClosed(f.PathID) {
		return nil
	}
	// section 4.7 of draft-ietf-quic-multipath-21
	next := c.connIDGenerator.NextSequenceNumber(f.PathID)
	if f.NextSequenceNumber > next {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			FrameType:    uint64(wire.FrameTypePathCIDsBlocked),
			ErrorMessage: fmt.Sprintf("PATH_CIDS_BLOCKED for path %d with next sequence number %d, expected at most %d", f.PathID, f.NextSequenceNumber, next),
		}
	}
	// If we issued more connection IDs since the peer sent the frame, the peer isn't blocked anymore.
	if c.mp.isAbandoned(f.PathID) || f.NextSequenceNumber < next {
		return nil
	}
	// Issue connection IDs until the peer has as many as its active_connection_id_limit allows.
	// For path IDs that no connection ID was issued for (above the peer's maximum path ID), this is a no-op.
	return c.connIDGenerator.TopUpPath(f.PathID)
}

// maybeAdvertiseMultipath adds the initial_max_path_id transport parameter.
// The frame parser needs to know the frames of the extension from now on:
// receiving them in Initial, Handshake or 0-RTT packets is a PROTOCOL_VIOLATION (section 4 of the draft).
func (c *Conn) maybeAdvertiseMultipath(params *wire.TransportParameters, srcConnID, destConnID protocol.ConnectionID) {
	if !shouldAdvertiseMultipath(c.multipathController, srcConnID, destConnID) {
		if multipathEnabledLocally(c.multipathController) {
			c.logger.Debugf("Not advertising multipath support: zero-length connection IDs are used.")
		}
		return
	}
	c.advertisedMultipath = true
	params.InitialMaxPathID = localInitialMaxPathID(c.config)
	params.HasInitialMaxPathID = true
	c.frameParser.EnableMultipath()
}
