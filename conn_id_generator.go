package quic

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/internal/utils"
	"github.com/AeonDave/mp-quic-go/internal/wire"
)

type connRunnerCallbacks struct {
	AddConnectionID    func(protocol.ConnectionID)
	RemoveConnectionID func(protocol.ConnectionID)
	ReplaceWithClosed  func([]protocol.ConnectionID, []byte, time.Duration)
}

// The memory address of the Transport is used as the key.
type connRunners map[connRunner]connRunnerCallbacks

// connIDLookup is implemented by the packet handler map of a Transport.
type connIDLookup interface {
	Get(protocol.ConnectionID) (packetHandler, bool)
}

// HasConnectionID says if the connection ID is used by a connection of any of the Transports.
func (cr connRunners) HasConnectionID(id protocol.ConnectionID) bool {
	for r := range cr {
		if l, ok := r.(connIDLookup); ok {
			if _, ok := l.Get(id); ok {
				return true
			}
		}
	}
	return false
}

// maxConnIDGenerationAttempts is the number of connection IDs generated to find one that is not in use yet.
const maxConnIDGenerationAttempts = 10

// generateUnusedConnID generates a connection ID that is not in use.
// A connection ID is never issued twice on a connection (section 5.1 of RFC 9000), and the connections of a Transport
// don't share connection IDs, since they share the stateless reset key (section 10.3.2 of RFC 9000).
// With the built-in generator, the connection IDs generated for a connection are all different (see
// connIDPermutation). Collisions with the connection IDs of other connections are rare, but not impossible for short
// connection IDs.
func generateUnusedConnID(generator ConnectionIDGenerator, inUse func(protocol.ConnectionID) bool) (protocol.ConnectionID, error) {
	for range maxConnIDGenerationAttempts {
		connID, err := generator.GenerateConnectionID()
		if err != nil {
			return protocol.ConnectionID{}, err
		}
		if connID.Len() == 0 || !inUse(connID) {
			return connID, nil
		}
	}
	return protocol.ConnectionID{}, errors.New("failed to generate an unused connection ID")
}

// connIDInUse says if a connection ID is used by this connection or by another connection of its Transports.
// The initial connection IDs are never issued again, even after they were retired and removed.
func (m *connIDGenerator) connIDInUse(connID protocol.ConnectionID) bool {
	if _, ok := m.pathOf[connID]; ok {
		return true
	}
	if slices.Contains(m.initialConnIDs, connID) {
		return true
	}
	return m.connRunners.HasConnectionID(connID)
}

func (cr connRunners) AddConnectionID(id protocol.ConnectionID) {
	for _, c := range cr {
		c.AddConnectionID(id)
	}
}

func (cr connRunners) RemoveConnectionID(id protocol.ConnectionID) {
	for _, c := range cr {
		c.RemoveConnectionID(id)
	}
}

func (cr connRunners) ReplaceWithClosed(ids []protocol.ConnectionID, b []byte, expiry time.Duration) {
	for _, c := range cr {
		c.ReplaceWithClosed(ids, b, expiry)
	}
}

type connIDToRetire struct {
	t      monotime.Time
	connID protocol.ConnectionID
}

// pathSrcConnIDs are the connection IDs issued for one path ID.
// With the multipath extension, every path ID has its own sequence number space, starting at 0
// (see section 3.2 of draft-ietf-quic-multipath-21).
type pathSrcConnIDs struct {
	nextSeq   uint64 // sequence number of the next connection ID issued for this path
	active    map[uint64]protocol.ConnectionID
	abandoned bool // no more connection IDs are issued for an abandoned path
}

type connIDGenerator struct {
	// The built-in generator of the Transport is replaced by a connIDPermutation for every connection.
	// A ConnectionIDGenerator configured by the application is responsible for generating unique connection IDs.
	generator   ConnectionIDGenerator
	connRunners connRunners
	// The connection IDs chosen before the connection was created: the initial connection ID, and the server's
	// initial client destination connection ID.
	initialConnIDs []protocol.ConnectionID

	path0 pathSrcConnIDs
	// Paths other than path 0, only used with the multipath extension:
	// the path IDs below nextUnusedPathID that were not removed yet.
	paths map[protocol.PathID]*pathSrcConnIDs
	// Path IDs that were abandoned before a connection ID was issued for them.
	// No connection IDs are ever issued for them. The peer can abandon any number of unused path IDs over the
	// lifetime of the connection, so they are stored as ranges instead of allocating an entry in paths.
	abandonedUnused utils.PathIDSet
	// The path of every connection ID that is active or about to be retired.
	// The initial connection IDs belong to path 0.
	pathOf                  map[protocol.ConnectionID]protocol.PathID
	connIDsToRetire         []connIDToRetire       // sorted by t
	initialClientDestConnID *protocol.ConnectionID // nil for the client

	// the peer's active_connection_id_limit, applies to every path
	activeConnIDLimit uint64

	multipath        bool
	localMaxPathID   protocol.PathID
	peerMaxPathID    protocol.PathID
	nextUnusedPathID protocol.PathID // the lowest path ID that no connection ID was issued for yet

	statelessResetter *statelessResetter

	queueControlFrame func(wire.Frame)
}

func newConnIDGenerator(
	runner connRunner,
	initialConnectionID protocol.ConnectionID,
	initialClientDestConnID *protocol.ConnectionID, // nil for the client
	statelessResetter *statelessResetter,
	callbacks connRunnerCallbacks,
	queueControlFrame func(wire.Frame),
	generator ConnectionIDGenerator,
) *connIDGenerator {
	if g, ok := generator.(*protocol.DefaultConnectionIDGenerator); ok && g.ConnLen > 0 {
		generator = newConnIDPermutation(g.ConnLen)
	}
	m := &connIDGenerator{
		generator:      generator,
		initialConnIDs: []protocol.ConnectionID{initialConnectionID},
		path0: pathSrcConnIDs{
			nextSeq: 1,
			active:  map[uint64]protocol.ConnectionID{0: initialConnectionID},
		},
		pathOf:            map[protocol.ConnectionID]protocol.PathID{initialConnectionID: 0},
		nextUnusedPathID:  1,
		statelessResetter: statelessResetter,
		connRunners:       map[connRunner]connRunnerCallbacks{runner: callbacks},
		queueControlFrame: queueControlFrame,
	}
	m.initialClientDestConnID = initialClientDestConnID
	if initialClientDestConnID != nil {
		m.pathOf[*initialClientDestConnID] = 0
		m.initialConnIDs = append(m.initialConnIDs, *initialClientDestConnID)
	}
	return m
}

func (m *connIDGenerator) SetMaxActiveConnIDs(limit uint64) error {
	m.activeConnIDLimit = limit
	if m.generator.ConnectionIDLen() == 0 {
		return nil
	}
	// The active_connection_id_limit transport parameter is the number of
	// connection IDs the peer will store. This limit includes the connection ID
	// used during the handshake, and the one sent in the preferred_address
	// transport parameter (see IssuePreferredAddressConnID).
	return m.topUp(0, &m.path0)
}

// IssuePreferredAddressConnID issues the connection ID sent in the preferred_address transport parameter
// (server only). It has the sequence number 1 (section 18.2 of RFC 9000), and, with IETF Multipath QUIC,
// belongs to path 0 (section 2.2 of draft-ietf-quic-multipath-21).
// It must be called before any other connection ID is issued.
func (m *connIDGenerator) IssuePreferredAddressConnID() (protocol.ConnectionID, protocol.StatelessResetToken, error) {
	if m.path0.nextSeq != 1 {
		panic("the connection ID of the preferred address has the sequence number 1")
	}
	connID, err := generateUnusedConnID(m.generator, m.connIDInUse)
	if err != nil {
		return protocol.ConnectionID{}, protocol.StatelessResetToken{}, err
	}
	m.path0.active[1] = connID
	m.path0.nextSeq++
	m.pathOf[connID] = 0
	m.connRunners.AddConnectionID(connID)
	return connID, m.statelessResetter.GetStatelessResetToken(connID), nil
}

// topUp issues connection IDs for a path until the peer has as many as its
// active_connection_id_limit allows, but not more than protocol.MaxIssuedConnectionIDs.
// With the multipath extension, the limit applies to every path.
func (m *connIDGenerator) topUp(id protocol.PathID, p *pathSrcConnIDs) error {
	for i := uint64(len(p.active)); i < min(m.activeConnIDLimit, protocol.MaxIssuedConnectionIDs); i++ {
		if err := m.issueNewConnID(id, p); err != nil {
			return err
		}
	}
	return nil
}

// EnableMultipath enables the multipath extension:
// From now on, connection IDs are issued in PATH_NEW_CONNECTION_ID frames, also for path 0,
// and one connection ID is issued for every unused path ID up to the smaller one of the
// local and the peer's maximum path ID.
func (m *connIDGenerator) EnableMultipath(localMaxPathID, peerMaxPathID protocol.PathID) error {
	m.multipath = true
	m.localMaxPathID = localMaxPathID
	m.peerMaxPathID = peerMaxPathID
	// If the peer already retired the initial connection ID, no replacement was issued for it.
	if err := m.TopUpPath(0); err != nil {
		return err
	}
	return m.issueForUnusedPaths()
}

// SetPeerMaxPathID is called when the peer increases its maximum path ID.
// It issues a connection ID for every path ID that can be used now.
func (m *connIDGenerator) SetPeerMaxPathID(maxPathID protocol.PathID) error {
	if maxPathID <= m.peerMaxPathID {
		return nil
	}
	m.peerMaxPathID = maxPathID
	return m.issueForUnusedPaths()
}

// IssueForUnusedPaths is called when the local maximum path ID increases.
// It issues a connection ID for every path ID that can be used now.
func (m *connIDGenerator) IssueForUnusedPaths(localMaxPathID protocol.PathID) error {
	m.localMaxPathID = max(m.localMaxPathID, localMaxPathID)
	return m.issueForUnusedPaths()
}

// issueForUnusedPaths issues one connection ID for every unused path ID up to the
// smaller one of the local and the peer's maximum path ID, starting with the lowest one,
// as recommended by section 3.2.1 of draft-ietf-quic-multipath-21.
// Connection IDs are never issued for path IDs larger than the peer's maximum path ID.
func (m *connIDGenerator) issueForUnusedPaths() error {
	if !m.multipath || m.generator.ConnectionIDLen() == 0 {
		return nil
	}
	maxPathID := min(m.localMaxPathID, m.peerMaxPathID, protocol.MaxPathID)
	for ; m.nextUnusedPathID <= maxPathID; m.nextUnusedPathID++ {
		id := m.nextUnusedPathID
		if m.abandonedUnused.Contains(id) {
			continue
		}
		if err := m.issueNewConnID(id, m.newPath(id)); err != nil {
			return err
		}
	}
	return nil
}

func (m *connIDGenerator) newPath(id protocol.PathID) *pathSrcConnIDs {
	if m.paths == nil {
		m.paths = make(map[protocol.PathID]*pathSrcConnIDs)
	}
	p := &pathSrcConnIDs{active: make(map[uint64]protocol.ConnectionID)}
	m.paths[id] = p
	return p
}

func (m *connIDGenerator) path(id protocol.PathID) *pathSrcConnIDs {
	if id == 0 {
		return &m.path0
	}
	return m.paths[id]
}

// TopUpPath issues connection IDs for a path until the peer has as many as its
// active_connection_id_limit allows, but not more than protocol.MaxIssuedConnectionIDs.
// It is a no-op for abandoned paths, and for path IDs that no connection ID was issued for yet.
func (m *connIDGenerator) TopUpPath(id protocol.PathID) error {
	if m.generator.ConnectionIDLen() == 0 {
		return nil
	}
	p := m.path(id)
	if p == nil || p.abandoned || p.nextSeq == 0 {
		return nil
	}
	return m.topUp(id, p)
}

// Retire handles a RETIRE_CONNECTION_ID frame, which always refers to path 0.
func (m *connIDGenerator) Retire(seq uint64, sentWithDestConnID protocol.ConnectionID, expiry monotime.Time) error {
	return m.RetireForPath(0, seq, sentWithDestConnID, expiry)
}

// RetireForPath handles a PATH_RETIRE_CONNECTION_ID frame.
// Unless the path was abandoned, a new connection ID is issued for the path.
// Without the multipath extension, the initial connection ID is not replaced.
func (m *connIDGenerator) RetireForPath(id protocol.PathID, seq uint64, sentWithDestConnID protocol.ConnectionID, expiry monotime.Time) error {
	p := m.path(id)
	if p == nil || seq >= p.nextSeq {
		var errMsg string
		switch {
		case id == 0:
			errMsg = fmt.Sprintf("retired connection ID %d (highest issued: %d)", seq, p.nextSeq-1)
		case p == nil || p.nextSeq == 0:
			errMsg = fmt.Sprintf("retired connection ID %d for path %d (none issued)", seq, id)
		default:
			errMsg = fmt.Sprintf("retired connection ID %d for path %d (highest issued: %d)", seq, id, p.nextSeq-1)
		}
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: errMsg,
		}
	}
	connID, ok := p.active[seq]
	// We might already have deleted this connection ID, if this is a duplicate frame.
	if !ok {
		return nil
	}
	if connID == sentWithDestConnID {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("retired connection ID %d (%s), which was used as the Destination Connection ID on this packet", seq, connID),
		}
	}
	m.queueConnIDForRetiring(connID, expiry)

	delete(p.active, seq)
	// Don't issue a replacement for the initial connection ID.
	// With the multipath extension, path 0 is treated like every other path:
	// its connection IDs are replaced while it is open (see section 3.2.2 of draft-ietf-quic-multipath-21).
	if id == 0 && seq == 0 && !m.multipath {
		return nil
	}
	// Don't issue a replacement for an abandoned path,
	// see section 4.5 of draft-ietf-quic-multipath-21.
	if p.abandoned {
		return nil
	}
	return m.issueNewConnID(id, p)
}

// AbandonPath is called when a path is abandoned.
// No more connection IDs are issued for this path ID.
// The connection IDs issued for it stay valid until the path is removed, so that packets still in flight
// on the path are processed, and don't trigger stateless resets (section 3.4.2 of draft-ietf-quic-multipath-21).
// The path ID might be unused, in which case connection IDs will never be issued for it.
func (m *connIDGenerator) AbandonPath(id protocol.PathID) {
	if p := m.path(id); p != nil {
		p.abandoned = true
		return
	}
	// Path IDs below nextUnusedPathID without an entry were abandoned or removed before.
	if id >= m.nextUnusedPathID {
		m.abandonedUnused.Add(id)
	}
}

// RemovePath is called when an abandoned path is closed.
// The connection IDs issued for the path are removed right away.
func (m *connIDGenerator) RemovePath(id protocol.PathID) {
	p := m.path(id)
	if p == nil {
		// no connection ID was issued for this path ID
		m.AbandonPath(id)
		return
	}
	p.abandoned = true
	for _, seq := range slices.Sorted(maps.Keys(p.active)) {
		connID := p.active[seq]
		m.connRunners.RemoveConnectionID(connID)
		delete(m.pathOf, connID)
	}
	clear(p.active)
	if id != 0 {
		delete(m.paths, id)
	}
}

// NextSequenceNumber returns the sequence number of the next connection ID issued for a path.
func (m *connIDGenerator) NextSequenceNumber(id protocol.PathID) uint64 {
	if p := m.path(id); p != nil {
		return p.nextSeq
	}
	return 0
}

// PathForConnID returns the path ID of a connection ID issued for this connection.
// This includes connection IDs that the peer retired, until they are removed.
func (m *connIDGenerator) PathForConnID(connID protocol.ConnectionID) (protocol.PathID, bool) {
	id, ok := m.pathOf[connID]
	return id, ok
}

func (m *connIDGenerator) queueConnIDForRetiring(connID protocol.ConnectionID, expiry monotime.Time) {
	idx := slices.IndexFunc(m.connIDsToRetire, func(c connIDToRetire) bool {
		return c.t.After(expiry)
	})
	if idx == -1 {
		idx = len(m.connIDsToRetire)
	}
	m.connIDsToRetire = slices.Insert(m.connIDsToRetire, idx, connIDToRetire{t: expiry, connID: connID})
}

func (m *connIDGenerator) issueNewConnID(id protocol.PathID, p *pathSrcConnIDs) error {
	connID, err := generateUnusedConnID(m.generator, m.connIDInUse)
	if err != nil {
		return err
	}
	p.active[p.nextSeq] = connID
	m.pathOf[connID] = id
	m.connRunners.AddConnectionID(connID)
	if m.multipath {
		m.queueControlFrame(&wire.PathNewConnectionIDFrame{
			PathID:              id,
			SequenceNumber:      p.nextSeq,
			ConnectionID:        connID,
			StatelessResetToken: m.statelessResetter.GetStatelessResetToken(connID),
		})
	} else {
		m.queueControlFrame(&wire.NewConnectionIDFrame{
			SequenceNumber:      p.nextSeq,
			ConnectionID:        connID,
			StatelessResetToken: m.statelessResetter.GetStatelessResetToken(connID),
		})
	}
	p.nextSeq++
	return nil
}

func (m *connIDGenerator) SetHandshakeComplete(connIDExpiry monotime.Time) {
	if m.initialClientDestConnID != nil {
		m.queueConnIDForRetiring(*m.initialClientDestConnID, connIDExpiry)
		m.initialClientDestConnID = nil
	}
}

func (m *connIDGenerator) RemoveRetiredConnIDs(now monotime.Time) {
	if len(m.connIDsToRetire) == 0 {
		return
	}
	for _, c := range m.connIDsToRetire {
		if c.t.After(now) {
			break
		}
		m.connRunners.RemoveConnectionID(c.connID)
		delete(m.pathOf, c.connID)
		m.connIDsToRetire = m.connIDsToRetire[1:]
	}
}

func (m *connIDGenerator) RemoveAll() {
	if m.initialClientDestConnID != nil {
		m.connRunners.RemoveConnectionID(*m.initialClientDestConnID)
	}
	for _, connID := range m.path0.active {
		m.connRunners.RemoveConnectionID(connID)
	}
	for _, p := range m.paths {
		for _, connID := range p.active {
			m.connRunners.RemoveConnectionID(connID)
		}
	}
	for _, c := range m.connIDsToRetire {
		m.connRunners.RemoveConnectionID(c.connID)
	}
	clear(m.pathOf)
}

func (m *connIDGenerator) ReplaceWithClosed(connClose []byte, expiry time.Duration) {
	m.connRunners.ReplaceWithClosed(m.allConnIDs(), connClose, expiry)
}

// ReplaceWithClosedPaths is ReplaceWithClosed for the multipath extension, with a packet containing the
// CONNECTION_CLOSE frame for every path that can be used for sending.
// The connection IDs of these paths are replaced with a closed connection that sends the path's packet.
// The connection IDs of all other paths, e.g. abandoned paths, are replaced with a closed connection that doesn't
// send anything: no packet is sent on an abandoned path, and a packet sent in response to a packet received on
// a path uses a connection ID of that path (sections 3.1 and 3.4 of draft-ietf-quic-multipath-21).
func (m *connIDGenerator) ReplaceWithClosedPaths(connClose map[protocol.PathID][]byte, expiry time.Duration) {
	connIDsByPath := make(map[protocol.PathID][]protocol.ConnectionID, len(connClose))
	var others []protocol.ConnectionID
	for _, connID := range m.allConnIDs() {
		if id, ok := m.pathOf[connID]; ok && connClose[id] != nil {
			connIDsByPath[id] = append(connIDsByPath[id], connID)
			continue
		}
		others = append(others, connID)
	}
	for _, id := range slices.Sorted(maps.Keys(connIDsByPath)) {
		m.connRunners.ReplaceWithClosed(connIDsByPath[id], connClose[id], expiry)
	}
	if len(others) > 0 {
		m.connRunners.ReplaceWithClosed(others, nil, expiry)
	}
}

// allConnIDs returns all connection IDs that are active or about to be retired.
func (m *connIDGenerator) allConnIDs() []protocol.ConnectionID {
	connIDs := make([]protocol.ConnectionID, 0, len(m.pathOf))
	if m.initialClientDestConnID != nil {
		connIDs = append(connIDs, *m.initialClientDestConnID)
	}
	for _, connID := range m.path0.active {
		connIDs = append(connIDs, connID)
	}
	for _, p := range m.paths {
		for _, connID := range p.active {
			connIDs = append(connIDs, connID)
		}
	}
	for _, c := range m.connIDsToRetire {
		connIDs = append(connIDs, c.connID)
	}
	return connIDs
}

func (m *connIDGenerator) AddConnRunner(runner connRunner, r connRunnerCallbacks) {
	// The transport might have already been added earlier.
	// This happens if the application migrates back to and old path.
	if _, ok := m.connRunners[runner]; ok {
		return
	}
	m.connRunners[runner] = r
	if m.initialClientDestConnID != nil {
		r.AddConnectionID(*m.initialClientDestConnID)
	}
	for _, connID := range m.path0.active {
		r.AddConnectionID(connID)
	}
	for _, p := range m.paths {
		for _, connID := range p.active {
			r.AddConnectionID(connID)
		}
	}
}
