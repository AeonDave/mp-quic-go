package quic

import (
	"crypto/subtle"
	"fmt"
	"slices"
	"sync"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/internal/utils"
	"github.com/AeonDave/mp-quic-go/internal/wire"
)

type newConnID struct {
	SequenceNumber      uint64
	ConnectionID        protocol.ConnectionID
	StatelessResetToken protocol.StatelessResetToken
}

// resetTokenRunners registers the peer's stateless reset tokens with every Transport that the connection receives
// packets on, so that each of them recognizes a stateless reset sent to the connection (section 10.3.1 of RFC 9000).
type resetTokenRunners struct {
	mx      sync.Mutex
	runners []resetTokenRunner
	tokens  map[protocol.StatelessResetToken]struct{}
}

type resetTokenRunner struct {
	runner  connRunner
	handler packetHandler
}

func newResetTokenRunners(runner connRunner, handler packetHandler) *resetTokenRunners {
	return &resetTokenRunners{
		runners: []resetTokenRunner{{runner: runner, handler: handler}},
		tokens:  make(map[protocol.StatelessResetToken]struct{}),
	}
}

// AddRunner registers the stateless reset tokens with another Transport.
// The Transport passes the stateless resets to handler.
func (r *resetTokenRunners) AddRunner(runner connRunner, handler packetHandler) {
	r.mx.Lock()
	defer r.mx.Unlock()

	for _, rr := range r.runners {
		if rr.runner == runner {
			return
		}
	}
	r.runners = append(r.runners, resetTokenRunner{runner: runner, handler: handler})
	for token := range r.tokens {
		runner.AddResetToken(token, handler)
	}
}

func (r *resetTokenRunners) AddResetToken(token protocol.StatelessResetToken) {
	r.mx.Lock()
	defer r.mx.Unlock()

	r.tokens[token] = struct{}{}
	for _, rr := range r.runners {
		rr.runner.AddResetToken(token, rr.handler)
	}
}

func (r *resetTokenRunners) RemoveResetToken(token protocol.StatelessResetToken) {
	r.mx.Lock()
	defer r.mx.Unlock()

	delete(r.tokens, token)
	for _, rr := range r.runners {
		rr.runner.RemoveResetToken(token)
	}
}

type connIDManager struct {
	// With the multipath extension, every path ID has its own connIDManager.
	pathID protocol.PathID
	// If set, connection IDs are retired using PATH_RETIRE_CONNECTION_ID frames.
	multipath bool
	// Always set for path 0. Other paths of the multipath extension don't have an
	// active connection ID until the first connection ID is used.
	hasActiveConnID bool

	queue []newConnID
	// the sequence number following the largest sequence number received from the peer
	nextSeq uint64

	highestProbingID uint64
	pathMx           sync.Mutex
	pathProbing      map[pathID]newConnID // initialized lazily

	handshakeComplete         bool
	activeSequenceNumber      uint64
	highestRetired            uint64
	activeConnectionID        protocol.ConnectionID
	activeStatelessResetToken *protocol.StatelessResetToken

	// We change the connection ID after sending on average
	// protocol.PacketsPerConnectionID packets. The actual value is randomized
	// hide the packet loss rate from on-path observers.
	rand                   utils.Rand
	packetsSinceLastChange uint32
	packetsPerConnectionID uint32

	addStatelessResetToken    func(protocol.StatelessResetToken)
	removeStatelessResetToken func(protocol.StatelessResetToken)
	queueControlFrame         func(wire.Frame)

	closed bool
}

func newConnIDManager(
	initialDestConnID protocol.ConnectionID,
	addStatelessResetToken func(protocol.StatelessResetToken),
	removeStatelessResetToken func(protocol.StatelessResetToken),
	queueControlFrame func(wire.Frame),
) *connIDManager {
	return &connIDManager{
		hasActiveConnID:           true,
		nextSeq:                   1, // the initial connection ID has sequence number 0
		activeConnectionID:        initialDestConnID,
		addStatelessResetToken:    addStatelessResetToken,
		removeStatelessResetToken: removeStatelessResetToken,
		queueControlFrame:         queueControlFrame,
		queue:                     make([]newConnID, 0, protocol.MaxActiveConnectionIDs),
	}
}

// newPathConnIDManager creates the connIDManager for a path other than path 0 of the multipath extension.
// The first connection ID provided for the path is used when the path is used for the first time.
func newPathConnIDManager(
	id protocol.PathID,
	addStatelessResetToken func(protocol.StatelessResetToken),
	removeStatelessResetToken func(protocol.StatelessResetToken),
	queueControlFrame func(wire.Frame),
) *connIDManager {
	return &connIDManager{
		pathID:    id,
		multipath: true,
		// paths other than path 0 are only used after completion of the handshake
		handshakeComplete:         true,
		addStatelessResetToken:    addStatelessResetToken,
		removeStatelessResetToken: removeStatelessResetToken,
		queueControlFrame:         queueControlFrame,
		queue:                     make([]newConnID, 0, protocol.MaxActiveConnectionIDs),
	}
}

// EnableMultipath makes the connIDManager retire connection IDs using PATH_RETIRE_CONNECTION_ID frames.
func (h *connIDManager) EnableMultipath() {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	h.multipath = true
}

func (h *connIDManager) queueRetireConnectionIDFrame(seq uint64) {
	if h.multipath {
		h.queueControlFrame(&wire.PathRetireConnectionIDFrame{
			PathID:         h.pathID,
			SequenceNumber: seq,
		})
		return
	}
	h.queueControlFrame(&wire.RetireConnectionIDFrame{
		SequenceNumber: seq,
	})
}

// AddFromPreferredAddress adds the connection ID from the preferred_address transport parameter,
// which has the sequence number 1 (section 18.2 of RFC 9000).
func (h *connIDManager) AddFromPreferredAddress(connID protocol.ConnectionID, resetToken protocol.StatelessResetToken) error {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	h.nextSeq = max(h.nextSeq, 2)
	return h.addConnectionID(1, connID, resetToken)
}

// AddFromPreferredAddressForPath adds the connection ID from the preferred_address transport parameter,
// and allocates it for the path id, see GetConnIDForPath.
// The client uses it to migrate to the server's preferred address: this connection ID is provided
// to ensure that an unused connection ID is available for the migration (section 18.2 of RFC 9000).
func (h *connIDManager) AddFromPreferredAddressForPath(id pathID, connID protocol.ConnectionID, resetToken protocol.StatelessResetToken) {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	h.assertNotClosed()
	h.nextSeq = max(h.nextSeq, 2)
	if h.pathProbing == nil {
		h.pathProbing = make(map[pathID]newConnID)
	}
	h.pathProbing[id] = newConnID{
		SequenceNumber:      1,
		ConnectionID:        connID,
		StatelessResetToken: resetToken,
	}
	h.highestProbingID = max(h.highestProbingID, 1)
	h.addStatelessResetToken(resetToken)
}

func (h *connIDManager) Add(f *wire.NewConnectionIDFrame) error {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	h.nextSeq = max(h.nextSeq, f.SequenceNumber+1)
	if err := h.add(f); err != nil {
		return err
	}
	// The active connection ID and the connection IDs used for probing paths count towards the limit,
	// see section 5.1.1 of RFC 9000.
	// With the multipath extension, the limit applies to every path.
	numActive := len(h.queue) + len(h.pathProbing)
	if h.hasActiveConnID {
		numActive++
	}
	if numActive > protocol.MaxActiveConnectionIDs {
		return &qerr.TransportError{ErrorCode: qerr.ConnectionIDLimitError}
	}
	return nil
}

func (h *connIDManager) add(f *wire.NewConnectionIDFrame) error {
	if h.hasActiveConnID && h.activeConnectionID.Len() == 0 {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "received NEW_CONNECTION_ID frame but zero-length connection IDs are in use",
		}
	}
	// If the NEW_CONNECTION_ID frame is reordered, such that its sequence number is smaller than the currently active
	// connection ID or if it was already retired, send the RETIRE_CONNECTION_ID frame immediately.
	// Connection IDs with sequence numbers up to highestProbingID were already taken from the queue.
	// Before a path of the multipath extension is used, no connection ID was taken from the queue.
	if (h.hasActiveConnID && (f.SequenceNumber < h.activeSequenceNumber || f.SequenceNumber <= h.highestProbingID)) ||
		f.SequenceNumber < h.highestRetired {
		// The frame might be a retransmission of a NEW_CONNECTION_ID frame that was already received.
		// Connection IDs that are still in use must not be retired.
		if !h.isInUse(f.SequenceNumber) {
			h.queueRetireConnectionIDFrame(f.SequenceNumber)
		}
		return nil
	}

	if f.RetirePriorTo != 0 && h.pathProbing != nil {
		for id, entry := range h.pathProbing {
			if entry.SequenceNumber < f.RetirePriorTo {
				h.queueRetireConnectionIDFrame(entry.SequenceNumber)
				h.removeStatelessResetToken(entry.StatelessResetToken)
				delete(h.pathProbing, id)
			}
		}
	}
	// Retire elements in the queue.
	// Doesn't retire the active connection ID.
	if f.RetirePriorTo > h.highestRetired {
		var newQueue []newConnID
		for _, entry := range h.queue {
			if entry.SequenceNumber >= f.RetirePriorTo {
				newQueue = append(newQueue, entry)
			} else {
				h.queueRetireConnectionIDFrame(entry.SequenceNumber)
			}
		}
		h.queue = newQueue
		h.highestRetired = f.RetirePriorTo
	}

	if h.hasActiveConnID && f.SequenceNumber == h.activeSequenceNumber {
		return nil
	}

	if err := h.addConnectionID(f.SequenceNumber, f.ConnectionID, f.StatelessResetToken); err != nil {
		return err
	}

	// Retire the active connection ID, if necessary.
	if h.hasActiveConnID && h.activeSequenceNumber < f.RetirePriorTo {
		// The queue is guaranteed to have at least one element at this point.
		h.updateConnectionID()
	}
	return nil
}

// isInUse says if the connection ID with this sequence number is the active connection ID,
// or if it is used for probing a path.
// It must be called with the pathMx held.
func (h *connIDManager) isInUse(seq uint64) bool {
	if h.hasActiveConnID && seq == h.activeSequenceNumber {
		return true
	}
	for _, entry := range h.pathProbing {
		if entry.SequenceNumber == seq {
			return true
		}
	}
	return false
}

func (h *connIDManager) addConnectionID(seq uint64, connID protocol.ConnectionID, resetToken protocol.StatelessResetToken) error {
	// fast path: add to the end of the queue
	if len(h.queue) == 0 || h.queue[len(h.queue)-1].SequenceNumber < seq {
		h.queue = append(h.queue, newConnID{
			SequenceNumber:      seq,
			ConnectionID:        connID,
			StatelessResetToken: resetToken,
		})
		return nil
	}

	// slow path: insert in the middle
	for i, entry := range h.queue {
		if entry.SequenceNumber == seq {
			// see section 19.15 of RFC 9000
			if entry.ConnectionID != connID {
				return &qerr.TransportError{
					ErrorCode:    qerr.ProtocolViolation,
					ErrorMessage: fmt.Sprintf("received conflicting connection IDs for sequence number %d", seq),
				}
			}
			if entry.StatelessResetToken != resetToken {
				return &qerr.TransportError{
					ErrorCode:    qerr.ProtocolViolation,
					ErrorMessage: fmt.Sprintf("received conflicting stateless reset tokens for sequence number %d", seq),
				}
			}
			return nil
		}

		// insert at the correct position to maintain sorted order
		if entry.SequenceNumber > seq {
			h.queue = slices.Insert(h.queue, i, newConnID{
				SequenceNumber:      seq,
				ConnectionID:        connID,
				StatelessResetToken: resetToken,
			})
			return nil
		}
	}
	return nil // unreachable
}

func (h *connIDManager) updateConnectionID() {
	h.assertNotClosed()
	if h.hasActiveConnID {
		h.queueRetireConnectionIDFrame(h.activeSequenceNumber)
		h.highestRetired = max(h.highestRetired, h.activeSequenceNumber)
		if h.activeStatelessResetToken != nil {
			h.removeStatelessResetToken(*h.activeStatelessResetToken)
		}
	}

	front := h.queue[0]
	h.queue = h.queue[1:]
	h.hasActiveConnID = true
	h.activeSequenceNumber = front.SequenceNumber
	h.activeConnectionID = front.ConnectionID
	h.activeStatelessResetToken = &front.StatelessResetToken
	h.packetsSinceLastChange = 0
	h.packetsPerConnectionID = protocol.PacketsPerConnectionID/2 + uint32(h.rand.Int31n(protocol.PacketsPerConnectionID))
	h.addStatelessResetToken(*h.activeStatelessResetToken)
}

func (h *connIDManager) Close() {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	h.closed = true
	if h.activeStatelessResetToken != nil {
		h.removeStatelessResetToken(*h.activeStatelessResetToken)
	}
	for _, entry := range h.pathProbing {
		h.removeStatelessResetToken(entry.StatelessResetToken)
	}
	clear(h.pathProbing)
}

// is called when the server performs a Retry
// and when the server changes the connection ID in the first Initial sent
func (h *connIDManager) ChangeInitialConnID(newConnID protocol.ConnectionID) {
	if h.activeSequenceNumber != 0 {
		panic("expected first connection ID to have sequence number 0")
	}
	h.activeConnectionID = newConnID
}

// is called when the server provides a stateless reset token in the transport parameters
func (h *connIDManager) SetStatelessResetToken(token protocol.StatelessResetToken) {
	h.assertNotClosed()
	if h.activeSequenceNumber != 0 {
		panic("expected first connection ID to have sequence number 0")
	}
	h.activeStatelessResetToken = &token
	h.addStatelessResetToken(token)
}

func (h *connIDManager) SentPacket() {
	h.packetsSinceLastChange++
}

func (h *connIDManager) shouldUpdateConnID() bool {
	if !h.handshakeComplete {
		return false
	}
	// initiate the first change as early as possible (after handshake completion)
	// The first connection ID of other paths of the multipath extension was never used during the handshake.
	if h.pathID == 0 && len(h.queue) > 0 && h.activeSequenceNumber == 0 {
		return true
	}
	// For later changes, only change if
	// 1. The queue of connection IDs is filled more than 50%.
	// 2. We sent at least PacketsPerConnectionID packets
	return 2*len(h.queue) >= protocol.MaxActiveConnectionIDs &&
		h.packetsSinceLastChange >= h.packetsPerConnectionID
}

func (h *connIDManager) Get() protocol.ConnectionID {
	h.assertNotClosed()
	if h.shouldUpdateConnID() {
		h.updateConnectionID()
	}
	return h.activeConnectionID
}

// get returns the connection ID to use, and false if the peer didn't provide one.
// This only happens for paths other than path 0 of the multipath extension,
// before the first connection ID for the path was received.
func (h *connIDManager) get() (protocol.ConnectionID, bool) {
	h.assertNotClosed()
	if !h.hasActiveConnID {
		if len(h.queue) == 0 {
			return protocol.ConnectionID{}, false
		}
		h.updateConnectionID()
	}
	return h.Get(), true
}

func (h *connIDManager) SetHandshakeComplete() {
	h.handshakeComplete = true
}

// GetConnIDForPath retrieves a connection ID for a new path (i.e. not the active one).
// Once a connection ID is allocated for a path, it cannot be used for a different path.
// When called with the same pathID, it will return the same connection ID,
// unless the peer requested that this connection ID be retired.
func (h *connIDManager) GetConnIDForPath(id pathID) (protocol.ConnectionID, bool) {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	h.assertNotClosed()
	// if we're using zero-length connection IDs, we don't need to change the connection ID
	if h.hasActiveConnID && h.activeConnectionID.Len() == 0 {
		return protocol.ConnectionID{}, true
	}

	if h.pathProbing == nil {
		h.pathProbing = make(map[pathID]newConnID)
	}
	entry, ok := h.pathProbing[id]
	if ok {
		return entry.ConnectionID, true
	}
	// A path of the multipath extension uses its first connection ID itself.
	if !h.hasActiveConnID {
		if len(h.queue) == 0 {
			return protocol.ConnectionID{}, false
		}
		h.updateConnectionID()
	}
	if len(h.queue) == 0 {
		return protocol.ConnectionID{}, false
	}
	front := h.queue[0]
	h.queue = h.queue[1:]
	h.pathProbing[id] = front
	h.highestProbingID = front.SequenceNumber
	h.addStatelessResetToken(front.StatelessResetToken)
	return front.ConnectionID, true
}

// HasConnIDForPath says if a connection ID can be used for a path (see GetConnIDForPath):
// a connection ID was already taken for the path, or an unused connection ID is available.
func (h *connIDManager) HasConnIDForPath(id pathID) bool {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	if h.hasActiveConnID && h.activeConnectionID.Len() == 0 {
		return true
	}
	if _, ok := h.pathProbing[id]; ok {
		return true
	}
	return len(h.queue) > 0
}

// UseConnIDForPath is called when the peer migrated to a path (see GetConnIDForPath).
// The connection ID used for this path becomes the active connection ID.
// The previously active connection ID is used for the path prevID from now on, which is the previously active path
// (section 9.3.3 of RFC 9000). It is retired if prevID is invalidPathID, or if the peer didn't provide a stateless
// reset token for it (this only applies to the peer's connection ID used during the handshake).
// This way, a connection ID is never used towards more than one remote address,
// or from more than one local address (section 9.5 of RFC 9000).
// It returns false if no connection ID is used for the path.
func (h *connIDManager) UseConnIDForPath(id, prevID pathID) bool {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	h.assertNotClosed()
	entry, ok := h.pathProbing[id]
	if !ok {
		return false
	}
	delete(h.pathProbing, id)
	if h.hasActiveConnID {
		if prevID != invalidPathID && h.activeStatelessResetToken != nil {
			// The stateless reset token stays registered.
			h.pathProbing[prevID] = newConnID{
				SequenceNumber:      h.activeSequenceNumber,
				ConnectionID:        h.activeConnectionID,
				StatelessResetToken: *h.activeStatelessResetToken,
			}
			// All connection IDs up to the active one were taken from the queue.
			h.highestProbingID = max(h.highestProbingID, h.activeSequenceNumber)
		} else {
			h.queueRetireConnectionIDFrame(h.activeSequenceNumber)
			h.highestRetired = max(h.highestRetired, h.activeSequenceNumber)
			if h.activeStatelessResetToken != nil {
				h.removeStatelessResetToken(*h.activeStatelessResetToken)
			}
		}
	}
	// The stateless reset token was added when the connection ID was taken for the path.
	h.hasActiveConnID = true
	h.activeSequenceNumber = entry.SequenceNumber
	h.activeConnectionID = entry.ConnectionID
	h.activeStatelessResetToken = &entry.StatelessResetToken
	h.packetsSinceLastChange = 0
	h.packetsPerConnectionID = protocol.PacketsPerConnectionID/2 + uint32(h.rand.Int31n(protocol.PacketsPerConnectionID))
	return true
}

func (h *connIDManager) RetireConnIDForPath(pathID pathID) {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	entry, ok := h.pathProbing[pathID]
	if !ok {
		return
	}
	h.queueRetireConnectionIDFrame(entry.SequenceNumber)
	h.removeStatelessResetToken(entry.StatelessResetToken)
	delete(h.pathProbing, pathID)
}

func (h *connIDManager) IsActiveStatelessResetToken(token protocol.StatelessResetToken) bool {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	// The tokens are compared in constant time (section 10.3.1 of RFC 9000).
	if h.activeStatelessResetToken != nil {
		if subtle.ConstantTimeCompare(h.activeStatelessResetToken[:], token[:]) == 1 {
			return true
		}
	}
	if h.pathProbing != nil {
		for _, entry := range h.pathProbing {
			if subtle.ConstantTimeCompare(entry.StatelessResetToken[:], token[:]) == 1 {
				return true
			}
		}
	}
	return false
}

// Using the connIDManager after it has been closed can have disastrous effects:
// If the connection ID is rotated, a new entry would be inserted into the packet handler map,
// leading to a memory leak of the connection struct.
// See https://github.com/quic-go/quic-go/pull/4852 for more details.
func (h *connIDManager) assertNotClosed() {
	if h.closed {
		panic("connection ID manager is closed")
	}
}

// pathConnIDManagers holds the connection IDs provided by the peer for all paths of the multipath extension.
// Every path ID has its own connIDManager, with its own sequence number space, Retire Prior To value and
// active_connection_id_limit (see sections 2.2 and 3.2 of draft-ietf-quic-multipath-21).
// Path 0 uses the connIDManager that is also used without the multipath extension.
type pathConnIDManagers struct {
	path0 *connIDManager
	// Other paths, created when the first PATH_NEW_CONNECTION_ID frame for the path is received,
	// or when the path is abandoned.
	paths map[protocol.PathID]*connIDManager
}

func newPathConnIDManagers(path0 *connIDManager) *pathConnIDManagers {
	return &pathConnIDManagers{path0: path0}
}

// EnableMultipath makes path 0 retire connection IDs using PATH_RETIRE_CONNECTION_ID frames.
func (m *pathConnIDManagers) EnableMultipath() {
	m.path0.EnableMultipath()
}

func (m *pathConnIDManagers) get(id protocol.PathID) (*connIDManager, bool) {
	if id == 0 {
		return m.path0, true
	}
	h, ok := m.paths[id]
	return h, ok
}

func (m *pathConnIDManagers) getOrCreate(id protocol.PathID) *connIDManager {
	if h, ok := m.get(id); ok {
		return h
	}
	if m.paths == nil {
		m.paths = make(map[protocol.PathID]*connIDManager)
	}
	h := newPathConnIDManager(
		id,
		m.path0.addStatelessResetToken,
		m.path0.removeStatelessResetToken,
		m.path0.queueControlFrame,
	)
	m.paths[id] = h
	return h
}

// AddNewConnectionID handles a NEW_CONNECTION_ID frame.
// With the multipath extension, NEW_CONNECTION_ID frames provide connection IDs for path 0
// (see section 3.2 of draft-ietf-quic-multipath-21). They are ignored once path 0 was abandoned.
func (m *pathConnIDManagers) AddNewConnectionID(f *wire.NewConnectionIDFrame) error {
	if m.path0.closed {
		return nil
	}
	return m.path0.Add(f)
}

// Add handles a PATH_NEW_CONNECTION_ID frame.
// Frames for abandoned paths are ignored.
func (m *pathConnIDManagers) Add(f *wire.PathNewConnectionIDFrame) error {
	h := m.getOrCreate(f.PathID)
	if h.closed {
		return nil
	}
	return h.Add(&wire.NewConnectionIDFrame{
		SequenceNumber:      f.SequenceNumber,
		RetirePriorTo:       f.RetirePriorTo,
		ConnectionID:        f.ConnectionID,
		StatelessResetToken: f.StatelessResetToken,
	})
}

// Get returns the connection ID to use on a path.
// It returns false if the peer didn't provide a connection ID for the path, or if the path was abandoned.
func (m *pathConnIDManagers) Get(id protocol.PathID) (protocol.ConnectionID, bool) {
	h, ok := m.get(id)
	if !ok || h.closed {
		return protocol.ConnectionID{}, false
	}
	return h.get()
}

// GetConnIDForTuple returns a connection ID of a path for sending packets to another 4-tuple than the one the path
// uses. An endpoint must not use a connection ID from more than one local address, or towards more than one remote
// address (section 9.5 of RFC 9000), so every 4-tuple uses its own connection ID, which is never the path's
// active connection ID. slot identifies the 4-tuple, it is unique among the 4-tuples of the path.
// When called with the same slot, it returns the same connection ID, unless the peer requested that it be retired.
// It returns false if no unused connection ID is available, or if the path was abandoned.
func (m *pathConnIDManagers) GetConnIDForTuple(id protocol.PathID, slot pathID) (protocol.ConnectionID, bool) {
	h, ok := m.get(id)
	if !ok || h.closed {
		return protocol.ConnectionID{}, false
	}
	return h.GetConnIDForPath(slot)
}

// UseConnIDForTuple is called when a path migrated to a 4-tuple (see GetConnIDForTuple).
// The connection ID used for the 4-tuple becomes the path's active connection ID.
// The connection ID used by the path so far is used for the previously active 4-tuple, identified by prevSlot,
// or retired if prevSlot is invalidPathID (see connIDManager.UseConnIDForPath).
func (m *pathConnIDManagers) UseConnIDForTuple(id protocol.PathID, slot, prevSlot pathID) bool {
	h, ok := m.get(id)
	if !ok || h.closed {
		return false
	}
	return h.UseConnIDForPath(slot, prevSlot)
}

// RetireConnIDForTuple retires the connection ID used for a 4-tuple of a path.
func (m *pathConnIDManagers) RetireConnIDForTuple(id protocol.PathID, slot pathID) {
	if h, ok := m.get(id); ok && !h.closed {
		h.RetireConnIDForPath(slot)
	}
}

// HasConnID says if the peer provided a connection ID that can be used on a path.
// It returns false for abandoned paths.
func (m *pathConnIDManagers) HasConnID(id protocol.PathID) bool {
	h, ok := m.get(id)
	if !ok {
		return false
	}
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	return !h.closed && (h.hasActiveConnID || len(h.queue) > 0)
}

// NextSequenceNumber returns the sequence number of the next connection ID that the peer is expected to issue for a path:
// the sequence number following the largest sequence number received for the path.
// This is the value sent in a PATH_CIDS_BLOCKED frame (see section 4.7 of draft-ietf-quic-multipath-21).
func (m *pathConnIDManagers) NextSequenceNumber(id protocol.PathID) uint64 {
	h, ok := m.get(id)
	if !ok {
		return 0
	}
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	return h.nextSeq
}

// SentPacket is called when a packet is sent on a path.
func (m *pathConnIDManagers) SentPacket(id protocol.PathID) {
	if h, ok := m.get(id); ok && !h.closed {
		h.SentPacket()
	}
}

// AbandonPath treats all connection IDs that the peer provided for a path as retired,
// without sending any frames (see section 3.4 of draft-ietf-quic-multipath-21).
// Connection IDs provided for this path later are ignored.
func (m *pathConnIDManagers) AbandonPath(id protocol.PathID) {
	if h := m.getOrCreate(id); !h.closed {
		h.Close()
	}
}

// RemovePath removes the state of an abandoned path, once the path is closed.
// Frames for the path ID must not be passed to the pathConnIDManagers afterwards.
// The connIDManager of path 0 is kept (and closed).
func (m *pathConnIDManagers) RemovePath(id protocol.PathID) {
	h, ok := m.get(id)
	if !ok {
		return
	}
	if !h.closed {
		h.Close()
	}
	if id != 0 {
		delete(m.paths, id)
	}
}

// IsActiveStatelessResetToken says if the stateless reset token belongs to a connection ID
// that is in use on a path that was not abandoned.
func (m *pathConnIDManagers) IsActiveStatelessResetToken(token protocol.StatelessResetToken) bool {
	if !m.path0.closed && m.path0.IsActiveStatelessResetToken(token) {
		return true
	}
	for _, h := range m.paths {
		if !h.closed && h.IsActiveStatelessResetToken(token) {
			return true
		}
	}
	return false
}

// Close closes the connIDManagers of all paths.
func (m *pathConnIDManagers) Close() {
	if !m.path0.closed {
		m.path0.Close()
	}
	for _, h := range m.paths {
		if !h.closed {
			h.Close()
		}
	}
}
