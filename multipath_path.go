package quic

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/handshake"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/internal/utils"
	"github.com/AeonDave/mp-quic-go/internal/wire"
)

// errPathValidationFailed is returned by Path.Probe if the validation of a path of IETF Multipath QUIC timed out.
var errPathValidationFailed = errors.New("path validation failed")

// mpPathState is the state of a path of IETF Multipath QUIC.
type mpPathState uint8

const (
	// The path is being validated (section 3.1 of draft-ietf-quic-multipath-21).
	// Only probing frames and ACKs are sent on it.
	mpPathValidating mpPathState = iota
	// The path was validated, and can be used for sending.
	mpPathActive
	// The path was abandoned (section 3.4 of draft-ietf-quic-multipath-21).
	// Packets received on it are still processed, but it is never sent on again.
	// Its state is removed (and the path is closed) 3 PTOs after both endpoints sent a PATH_ABANDON frame.
	mpPathAbandoned
)

// A sentPathChallenge is a PATH_CHALLENGE frame sent to validate a path.
type sentPathChallenge struct {
	data     [8]byte
	sendTime monotime.Time
	// Was the datagram that contained the PATH_CHALLENGE expanded to 1200 bytes?
	padded bool
}

// mpPath is a path of IETF Multipath QUIC.
type mpPath struct {
	id    protocol.PathID
	state mpPathState

	// The sendConn used to send packets on this path.
	// It is nil for path 0, which uses the connection's sendConn.
	conn sendConn

	// Path validation, see section 8.2 of RFC 9000.
	// The PATH_CHALLENGE frames sent in the current validation.
	challenges []sentPathChallenge
	// Is a PATH_CHALLENGE frame due to be sent?
	challengeDue bool
	// When the next PATH_CHALLENGE frame is sent, and the interval to the one after that (exponential backoff).
	nextChallenge     monotime.Time
	challengeInterval time.Duration
	// The path is abandoned if the validation doesn't succeed by then.
	validationDeadline monotime.Time
	// A PATH_RESPONSE frame was received.
	addressValidated bool
	// A PATH_RESPONSE frame was received for a PATH_CHALLENGE frame sent in a datagram of at least 1200 bytes.
	mtuValidated bool

	// the status that the peer signaled for this path (section 3.3 of draft-ietf-quic-multipath-21)
	peerStatus    peerPathStatus
	hasPeerStatus bool

	// The status signaled to the peer (section 3.3 of draft-ietf-quic-multipath-21).
	// The status set by the application.
	status PathStatus
	// The path is signaled as a backup path because it potentially failed,
	// while data is sent on a backup path (MP-33, see updatePathStatus).
	autoBackup bool
	// when autoBackup was last changed
	autoBackupChanged monotime.Time
	// when autoBackup can be changed again
	statusUpdateTime monotime.Time
	// The status sent in the last PATH_STATUS_AVAILABLE or PATH_STATUS_BACKUP frame, if any.
	statusSent, sentBackup bool
	// the sequence number of the next PATH_STATUS_AVAILABLE or PATH_STATUS_BACKUP frame
	nextStatusSeq uint64

	// The largest packet number received on the path.
	// The path only migrates to another 4-tuple in response to the highest-numbered non-probing packet
	// (section 9.3 of RFC 9000).
	largestRcvdPN protocol.PacketNumber
	// Migration of the path to other 4-tuples of the client (server only), see section 3.1.2 of
	// draft-ietf-quic-multipath-21. Created when a packet is received from another 4-tuple.
	// Every 4-tuple uses its own connection ID of the path.
	migration *tupleManager
	// The packet info of the last packet received on the path's 4-tuple (server only).
	// It is used to validate this 4-tuple after the path migrated to another one (section 9.3.3 of RFC 9000).
	info packetInfo
	// Other server addresses that the client accepts packets from on this path (client only), see allowServerAddr.
	otherServerAddrs []net.Addr

	// Abandonment (section 3.4 of draft-ietf-quic-multipath-21).
	// The peer sent a PATH_ABANDON frame for the path.
	abandonRcvd bool
	// the largest PTO among all paths, including this one, when the path was abandoned
	abandonPTO time.Duration
	// The time at which the path is closed. If the peer didn't send a PATH_ABANDON frame by then,
	// the path becomes a zombie instead.
	retainUntil monotime.Time
	// The peer didn't respond to our PATH_ABANDON frame in time. The state of the path was removed,
	// except for our connection IDs, which the peer might still use. The path is closed 3 PTOs after the peer's
	// PATH_ABANDON frame is received, and it keeps counting towards Config.MaxPaths until then.
	zombie bool

	// frames that need to be sent on this path, e.g. PATH_RESPONSE frames
	frames []ackhandler.Frame

	// Path MTU discovery, started when the path becomes active.
	// It is nil for path 0, which uses the connection's mtuDiscoverer.
	mtuDiscoverer *mtuFinder
	// the maximum datagram size passed to the sent packet handler
	maxDatagramSize protocol.ByteCount

	// the Path that the application used to open this path (client only)
	handle *mpPathHandle
	// The multipath controller was informed about the path (see notifyPathActive).
	registered bool
	// The frames of the outstanding packets were reinjected on another path when the probe timeout expired
	// (see maybeReinjectOnPTO). It is reset once the path doesn't need to send probe packets anymore.
	reinjectedOnPTO bool
	// The path potentially failed. Its outstanding packets are declared lost once another path works
	// (see handleFailedPaths).
	failureDue bool
	// A PING frame is sent on the path, to detect when the path recovers (see handleFailedPaths).
	pingDue bool
}

// usable says if packets other than path validation packets can be sent on this path.
func (p *mpPath) usable() bool {
	return p.state == mpPathActive
}

// isBackup says if the application or the peer marked the path as a backup path.
// Data is only sent on backup paths if no other path can be used.
// Paths signaled as backup paths because they potentially failed (autoBackup) are avoided because they
// potentially failed, and used again as soon as they recover.
func (p *mpPath) isBackup() bool {
	return p.status == PathStatusBackup || (p.hasPeerStatus && p.peerStatus.backup)
}

// mpPathHandleState is the state of a Path of IETF Multipath QUIC, as seen by the application.
type mpPathHandleState uint8

const (
	mpPathHandleIdle mpPathHandleState = iota
	mpPathHandleProbing
	mpPathHandleValidated
	mpPathHandleClosed
)

// mpPathHandle is the part of a Path that opens a path of IETF Multipath QUIC.
// The path is opened by the connection's run loop when the application calls Probe.
type mpPathHandle struct {
	conn *Conn
	mp   *multipathState
	// returns the sendConn used to send on the path,
	// called on the connection's run loop when the path is opened
	newSendConn func() sendConn

	mx     sync.Mutex
	state  mpPathHandleState
	id     protocol.PathID
	hasID  bool
	status PathStatus    // the status set by the application
	done   chan struct{} // closed when the path was validated or closed
	err    error         // the error returned by Probe once the path is closed
}

func newMPPathHandle(c *Conn, newSendConn func() sendConn) *mpPathHandle {
	return &mpPathHandle{
		conn:        c,
		mp:          c.mp,
		newSendConn: newSendConn,
		done:        make(chan struct{}),
	}
}

func (h *mpPathHandle) pathID() (protocol.PathID, bool) {
	h.mx.Lock()
	defer h.mx.Unlock()

	return h.id, h.hasID
}

func (h *mpPathHandle) setPathID(id protocol.PathID) {
	h.mx.Lock()
	defer h.mx.Unlock()

	h.id = id
	h.hasID = true
}

func (h *mpPathHandle) getStatus() PathStatus {
	h.mx.Lock()
	defer h.mx.Unlock()

	return h.status
}

// setValidated is called when the path was validated.
// It returns false if the path was closed in the meantime.
func (h *mpPathHandle) setValidated() bool {
	h.mx.Lock()
	defer h.mx.Unlock()

	if h.state != mpPathHandleProbing {
		return false
	}
	h.state = mpPathHandleValidated
	close(h.done)
	return true
}

// setClosed is called when the path is closed.
// Calls to Probe return err from now on.
func (h *mpPathHandle) setClosed(err error) {
	h.mx.Lock()
	defer h.mx.Unlock()

	h.closeLocked(err)
}

func (h *mpPathHandle) closeLocked(err error) {
	switch h.state {
	case mpPathHandleClosed:
		return
	case mpPathHandleIdle, mpPathHandleProbing:
		close(h.done)
	case mpPathHandleValidated:
		// done was closed when the path was validated
	}
	h.state = mpPathHandleClosed
	h.err = err
}

// Probe opens the path and validates it.
// If the context is canceled before the path is validated, the path is abandoned.
func (h *mpPathHandle) Probe(ctx context.Context) error {
	h.mx.Lock()
	switch h.state {
	case mpPathHandleValidated:
		h.mx.Unlock()
		return nil
	case mpPathHandleClosed:
		err := h.err
		h.mx.Unlock()
		return err
	case mpPathHandleIdle:
		h.state = mpPathHandleProbing
		h.mp.postRequest(mpRequest{typ: mpRequestOpen, handle: h})
		h.conn.scheduleSending()
	case mpPathHandleProbing:
		// another call to Probe is waiting for the validation
	}
	h.mx.Unlock()

	select {
	case <-h.done:
		h.mx.Lock()
		defer h.mx.Unlock()
		return h.err
	case <-ctx.Done():
		h.mx.Lock()
		if h.state == mpPathHandleValidated {
			h.mx.Unlock()
			return nil
		}
		h.closeLocked(ErrPathClosed)
		h.mx.Unlock()
		// Section 3.4 of draft-ietf-quic-multipath-21: the path ID is consumed, so the path needs to be abandoned.
		h.mp.postRequest(mpRequest{typ: mpRequestAbandon, handle: h, errorCode: qerr.ApplicationAbandonPath})
		h.conn.scheduleSending()
		return context.Cause(ctx)
	case <-h.conn.Context().Done():
		return ErrPathClosed
	}
}

// Switch makes the path the preferred path for sending. This is a local scheduling preference:
// data is only sent on this path as long as it can be used, and LocalAddr, RemoteAddr and ConnectionStats refer to it.
// The other paths stay open. The preference is not signaled to the peer, see SetStatus for that.
// It returns an error unless the path was validated.
// The connection switches to the path before it sends the next packet.
func (h *mpPathHandle) Switch() error {
	h.mx.Lock()
	defer h.mx.Unlock()

	switch h.state {
	case mpPathHandleValidated:
		h.mp.postRequest(mpRequest{typ: mpRequestSwitch, handle: h})
		h.conn.scheduleSending()
		return nil
	case mpPathHandleClosed:
		return ErrPathClosed
	case mpPathHandleIdle, mpPathHandleProbing:
		return ErrPathNotValidated
	default:
		panic("unknown path state")
	}
}

// SetStatus sets the status of the path, which is signaled to the peer.
// If the path wasn't opened yet, the status is signaled when the path is opened.
func (h *mpPathHandle) SetStatus(status PathStatus) error {
	if status != PathStatusAvailable && status != PathStatusBackup {
		return fmt.Errorf("invalid path status: %s", status)
	}
	h.mx.Lock()
	if h.state == mpPathHandleClosed {
		h.mx.Unlock()
		return ErrPathClosed
	}
	h.status = status
	h.mx.Unlock()

	h.mp.postRequest(mpRequest{typ: mpRequestSetStatus, handle: h})
	h.conn.scheduleSending()
	return nil
}

// Close abandons the path using the APPLICATION_ABANDON_PATH error code.
// The last path that can be used for sending can't be closed.
func (h *mpPathHandle) Close() error {
	h.mx.Lock()
	switch h.state {
	case mpPathHandleClosed:
		h.mx.Unlock()
		return nil
	case mpPathHandleIdle:
		h.closeLocked(ErrPathClosed)
		h.mx.Unlock()
		return nil
	case mpPathHandleProbing, mpPathHandleValidated:
		// The path might already have been opened. It is abandoned on the connection's run loop.
	}
	h.mx.Unlock()

	result := make(chan error, 1)
	h.mp.postRequest(mpRequest{typ: mpRequestAbandon, handle: h, errorCode: qerr.ApplicationAbandonPath, result: result})
	h.conn.scheduleSending()
	select {
	case err := <-result:
		return err
	case <-h.conn.Context().Done():
		return nil
	}
}

type mpRequestType uint8

const (
	mpRequestOpen mpRequestType = iota
	mpRequestAbandon
	mpRequestSetStatus
	mpRequestSwitch
)

// An mpRequest is a request from the application, processed on the connection's run loop.
type mpRequest struct {
	typ    mpRequestType
	handle *mpPathHandle
	// the path ID of an mpRequestAbandon or an mpRequestSetStatus without a handle
	pathID    protocol.PathID
	errorCode qerr.TransportErrorCode // the error code used to abandon the path
	status    PathStatus              // the status of an mpRequestSetStatus without a handle
	result    chan<- error            // if set, the result of an mpRequestAbandon or an mpRequestSetStatus
}

// newMultipathPath returns a Path that opens a path of IETF Multipath QUIC.
func (c *Conn) newMultipathPath(newSendConn func() sendConn) *Path {
	return &Path{
		mp:      newMPPathHandle(c, newSendConn),
		abandon: make(chan struct{}),
	}
}

// waitForMultipathNegotiation says if the kind of a path added by the application is not known yet:
// if the client advertised IETF Multipath QUIC, it depends on the server's transport parameters,
// which are only known once the handshake completed.
func (c *Conn) waitForMultipathNegotiation() bool {
	if !c.advertisedMultipath {
		return false
	}
	select {
	case <-c.handshakeCompleteChan:
		return false
	default:
		return true
	}
}

// AddPathFromAddr creates a new path of IETF Multipath QUIC, using the connection's underlying network connection.
// Packets are sent to remote, or to the server address of the path that the handshake was performed on if remote is nil.
// If local is set, packets are sent from this local address. This requires a connection that allows setting the source
// address of packets, e.g. a UDP socket bound to an unspecified address, or a [MultiSocketManager].
// The path is opened and validated by calling [Path.Probe].
//
// Paths can only be added by the client, if IETF Multipath QUIC was negotiated.
// If the server sent the disable_active_migration transport parameter, no path to the server's handshake address
// can be added (section 2.2 of draft-ietf-quic-multipath-21). Paths to other addresses of the server, e.g. its
// preferred address, can be added.
// A path added before completion of the handshake is created when it is probed: [Path.Probe] waits for the handshake
// to complete, and returns the error if the path can't be added.
func (c *Conn) AddPathFromAddr(local, remote net.Addr) (*Path, error) {
	if c.perspective == protocol.PerspectiveServer {
		return nil, errors.New("server cannot open paths")
	}
	if c.waitForMultipathNegotiation() {
		return newDeferredPath(c, func() (*Path, error) { return c.addPathFromAddr(local, remote) }), nil
	}
	return c.addPathFromAddr(local, remote)
}

func (c *Conn) addPathFromAddr(local, remote net.Addr) (*Path, error) {
	if c.mp == nil {
		return nil, errors.New("IETF Multipath QUIC was not negotiated")
	}
	if remote == nil {
		// This is the server's handshake address, unless path 0 migrated to the server's preferred address.
		remote = c.conn.RemoteAddr()
	}
	if c.peerParams.DisableActiveMigration && peerAddrsEqual(remote, c.peerHandshakeAddr) {
		return nil, errors.New("server disabled active migration to its handshake address")
	}
	var info packetInfo
	if local != nil {
		info = packetInfoFromPathInfo(PathInfo{LocalAddr: local})
	}
	return c.newMultipathPath(func() sendConn { return c.conn.newPathConn(remote, info) }), nil
}

// Paths returns the paths of IETF Multipath QUIC, in ascending order of their path IDs.
// This includes paths that are being validated, and abandoned paths whose state wasn't removed yet.
// It returns nil if IETF Multipath QUIC is not used.
// The paths are a snapshot, taken by the connection when the extension becomes active (on completion of the
// handshake), when a path is validated or abandoned, and after processing packets and timers.
func (c *Conn) Paths() []PathInfo {
	paths := c.mpPaths.Load()
	if paths == nil {
		return nil
	}
	return slices.Clone(*paths)
}

// mpPathInfo returns the PathInfo of a path of IETF Multipath QUIC.
func (c *Conn) mpPathInfo(path *mpPath) PathInfo {
	conn := c.pathSendConn(path)
	info := PathInfo{
		ID:         path.id,
		LocalAddr:  conn.LocalAddr(),
		RemoteAddr: conn.RemoteAddr(),
		Status:     path.status,
	}
	switch path.state {
	case mpPathValidating:
		info.State = PathStateValidating
	case mpPathActive:
		info.State = PathStateActive
	case mpPathAbandoned:
		info.State = PathStateAbandoned
	}
	if path.hasPeerStatus {
		info.PeerStatus = PathStatusAvailable
		if path.peerStatus.backup {
			info.PeerStatus = PathStatusBackup
		}
	}
	if c.addrDisc != nil {
		info.ObservedAddr, _ = c.addrDisc.observedAddr(path.id)
	}
	return info
}

// updatePathsSnapshot updates the paths returned by Paths, if they changed.
func (c *Conn) updatePathsSnapshot() {
	infos := c.mp.pathInfos[:0]
	for _, id := range c.mp.pathIDs {
		infos = append(infos, c.mpPathInfo(c.mp.paths[id]))
	}
	c.mp.pathInfos = infos
	if old := c.mpPaths.Load(); old != nil && slices.EqualFunc(*old, infos, samePathInfo) {
		return
	}
	paths := slices.Clone(infos)
	c.mpPaths.Store(&paths)
}

func samePathInfo(a, b PathInfo) bool {
	return a.ID == b.ID && a.State == b.State && a.Status == b.Status && a.PeerStatus == b.PeerStatus &&
		a.IfIndex == b.IfIndex && a.ObservedAddr == b.ObservedAddr &&
		sameNetAddr(a.LocalAddr, b.LocalAddr) && sameNetAddr(a.RemoteAddr, b.RemoteAddr)
}

// sameNetAddr says if two addresses are the same.
func sameNetAddr(a, b net.Addr) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if ua, ok := a.(*net.UDPAddr); ok {
		ub, ok := b.(*net.UDPAddr)
		return ok && (ua == ub || (ua.IP.Equal(ub.IP) && ua.Port == ub.Port && ua.Zone == ub.Zone))
	}
	return addrsEqual(a, b)
}

// handleMultipathEvents handles the events of IETF Multipath QUIC that are processed independently of
// sending and receiving packets: requests from the application, errors when sending on a path,
// and the path validation timers.
func (c *Conn) handleMultipathEvents(now monotime.Time) error {
	c.processMultipathRequests(now)
	if err := c.handlePathWriteErrors(now); err != nil {
		return err
	}
	if err := c.handleMultipathTimers(now); err != nil {
		return err
	}
	// No path is left if the last open paths were abandoned while they were being validated,
	// e.g. because their validation failed after the peer abandoned the last validated path.
	// No packet can be sent anymore, not even a CONNECTION_CLOSE frame.
	if !c.mp.hasOtherOpenPath(protocol.InvalidPathID) {
		return &qerr.TransportError{
			ErrorCode:    qerr.NoViablePathError,
			ErrorMessage: "no open path left",
		}
	}
	c.updatePathsSnapshot()
	return nil
}

// processMultipathRequests processes the requests made by the application,
// and opens the paths that the application requested, if possible.
func (c *Conn) processMultipathRequests(now monotime.Time) {
	for _, r := range c.mp.takeRequests() {
		switch r.typ {
		case mpRequestOpen:
			c.mp.pendingOpens = append(c.mp.pendingOpens, r.handle)
		case mpRequestAbandon:
			err := c.handleAbandonRequest(r, now)
			if r.result != nil {
				r.result <- err
			}
		case mpRequestSetStatus:
			if r.handle == nil {
				r.result <- c.setPathStatus(r.pathID, r.status)
				continue
			}
			// If the path wasn't opened yet, the status is applied when it is opened.
			if id, ok := r.handle.pathID(); ok {
				if path, ok := c.mp.paths[id]; ok && path.state != mpPathAbandoned {
					path.status = r.handle.getStatus()
					c.signalPathStatus(path)
					c.mp.statusUpdateDue = true
				}
			}
		case mpRequestSwitch:
			c.handleSwitchRequest(r.handle)
		}
	}
	// Section 9 of RFC 9000: paths can only be opened after confirmation of the handshake.
	if c.handshakeConfirmed {
		c.maybeOpenPaths(now)
	}
}

func (c *Conn) handleAbandonRequest(r mpRequest, now monotime.Time) error {
	id := r.pathID
	if h := r.handle; h != nil {
		var ok bool
		id, ok = h.pathID()
		if !ok {
			// The path wasn't opened yet.
			c.mp.pendingOpens = slices.DeleteFunc(c.mp.pendingOpens, func(p *mpPathHandle) bool { return p == h })
			h.setClosed(ErrPathClosed)
			return nil
		}
	}
	path, ok := c.mp.paths[id]
	if !ok || path.state == mpPathAbandoned {
		if r.handle != nil {
			r.handle.setClosed(ErrPathClosed)
			return nil
		}
		return ErrPathClosed
	}
	// Closing the last path that can be used for sending would leave the connection without a path.
	if r.result != nil && path.usable() && !c.mp.hasOtherUsablePath(id) {
		return errors.New("cannot close the last usable path")
	}
	c.abandonPath(path, r.errorCode, now, ErrPathClosed)
	return nil
}

// handleSwitchRequest makes a path the preferred path for sending, and the primary path.
// Nothing happens if the path was abandoned in the meantime.
func (c *Conn) handleSwitchRequest(h *mpPathHandle) {
	id, ok := h.pathID()
	if !ok {
		return
	}
	path, ok := c.mp.paths[id]
	if !ok || !path.usable() {
		return
	}
	if c.logger.Debug() {
		c.logger.Debugf("Switching to path %d.", id)
	}
	c.mp.preferredPathID = id
	c.mp.hasPreferredPath = true
	c.setPrimaryPath(path)
	c.scheduleSending()
}

// ClosePath abandons the path of IETF Multipath QUIC with the given path ID, like [Path.Close]
// (section 3.4 of draft-ietf-quic-multipath-21). It can be used for paths that the application didn't open
// using [Conn.AddPath] or [Conn.AddPathFromAddr], for example path 0 (the path of the handshake),
// paths opened by [Config.MultipathAutoPaths], and paths opened by the client (when called by the server).
// The last path that can be used for sending can't be closed.
// It returns [ErrPathClosed] if there's no such path, or if the path was already abandoned.
// It returns an error if IETF Multipath QUIC is not used.
func (c *Conn) ClosePath(id PathID) error {
	select {
	case <-c.handshakeCompleteChan:
	default:
		return errors.New("IETF Multipath QUIC is not used")
	}
	if c.mp == nil {
		return errors.New("IETF Multipath QUIC is not used")
	}
	return c.closeMultipathPath(id)
}

// SetPathStatus sets the status of the path of IETF Multipath QUIC with the given path ID, and signals it
// to the peer, like [Path.SetStatus] (section 3.3 of draft-ietf-quic-multipath-21). It can be used for paths
// that the application didn't open using [Conn.AddPath] or [Conn.AddPathFromAddr], for example path 0
// (the path of the handshake), paths opened by [Config.MultipathAutoPaths], and paths opened by the client
// (when called by the server).
// It returns [ErrPathClosed] if there's no such path, or if the path was abandoned.
// It returns an error if IETF Multipath QUIC is not used.
func (c *Conn) SetPathStatus(id PathID, status PathStatus) error {
	if status != PathStatusAvailable && status != PathStatusBackup {
		return fmt.Errorf("invalid path status: %s", status)
	}
	select {
	case <-c.handshakeCompleteChan:
	default:
		return errors.New("IETF Multipath QUIC is not used")
	}
	if c.mp == nil {
		return errors.New("IETF Multipath QUIC is not used")
	}
	result := make(chan error, 1)
	c.mp.postRequest(mpRequest{typ: mpRequestSetStatus, pathID: id, status: status, result: result})
	c.scheduleSending()
	select {
	case err := <-result:
		return err
	case <-c.Context().Done():
		return ErrPathClosed
	}
}

// setPathStatus sets the status of a path, for an mpRequestSetStatus without a handle.
func (c *Conn) setPathStatus(id protocol.PathID, status PathStatus) error {
	path, ok := c.mp.paths[id]
	if !ok || path.state == mpPathAbandoned {
		return ErrPathClosed
	}
	path.status = status
	c.signalPathStatus(path)
	c.mp.statusUpdateDue = true
	return nil
}

// closeMultipathPath abandons a path using the APPLICATION_ABANDON_PATH error code.
func (c *Conn) closeMultipathPath(id protocol.PathID) error {
	result := make(chan error, 1)
	c.mp.postRequest(mpRequest{typ: mpRequestAbandon, pathID: id, errorCode: qerr.ApplicationAbandonPath, result: result})
	c.scheduleSending()
	select {
	case err := <-result:
		return err
	case <-c.Context().Done():
		return ErrPathClosed
	}
}

// maybeOpenPaths opens the paths requested by the application, in the order of the requests.
func (c *Conn) maybeOpenPaths(now monotime.Time) {
	for len(c.mp.pendingOpens) > 0 {
		h := c.mp.pendingOpens[0]
		id, ok, err := c.nextPathIDToOpen()
		if err != nil {
			c.mp.pendingOpens = c.mp.pendingOpens[1:]
			h.setClosed(err)
			continue
		}
		if !ok {
			return
		}
		c.mp.pendingOpens = c.mp.pendingOpens[1:]
		c.openPath(h, id, now)
	}
}

// nextPathIDToOpen returns the path ID used for the next path opened by the client:
// the smallest unused path ID for which both endpoints issued connection IDs
// (sections 3, 3.1.1 and 3.2.1 of draft-ietf-quic-multipath-21).
// If no path can be opened, it returns false. If the peer's maximum path ID prevents opening a path,
// a PATHS_BLOCKED frame is sent. If the peer didn't provide a connection ID for an unused path ID,
// a PATH_CIDS_BLOCKED frame is sent (section 3.2.2).
// If our own limit prevents opening a path, it returns ErrTooManyPaths,
// unless an abandoned path is about to be closed, which will allow opening another path.
func (c *Conn) nextPathIDToOpen() (protocol.PathID, bool, error) {
	maxPathID := min(c.mp.localMaxPathID, c.mp.peerMaxPathID)
	firstUnused := protocol.InvalidPathID
	for id := protocol.PathID(1); id <= maxPathID; id++ {
		if c.mp.isUsed(id) {
			continue
		}
		if firstUnused == protocol.InvalidPathID {
			firstUnused = id
		}
		if c.connIDGenerator.NextSequenceNumber(id) > 0 && c.peerConnIDs.HasConnID(id) {
			return id, true, nil
		}
	}
	if firstUnused == protocol.InvalidPathID {
		if c.mp.peerMaxPathID >= c.mp.localMaxPathID {
			if c.mp.isClosingPath() {
				return 0, false, nil
			}
			return 0, false, ErrTooManyPaths
		}
		c.mp.maybeSendPathsBlocked(c)
		return 0, false, nil
	}
	if !c.peerConnIDs.HasConnID(firstUnused) {
		c.mp.maybeSendPathCIDsBlocked(c, firstUnused, c.peerConnIDs.NextSequenceNumber(firstUnused))
	}
	return 0, false, nil
}

// openPath opens a path (client only).
func (c *Conn) openPath(h *mpPathHandle, id protocol.PathID, now monotime.Time) {
	path := c.mp.addPath(id, h.newSendConn())
	path.handle = h
	h.setPathID(id)
	// The client doesn't need to validate the server's address before sending.
	c.sentPacketHandler.AddPath(id, true)
	if c.addrDisc != nil {
		c.addrDisc.addPath(id)
	}
	if c.logger.Debug() {
		c.logger.Debugf("Opening path %d to %s.", id, path.conn.RemoteAddr())
	}
	c.startPathValidation(path, now)
	// The status set before the path was opened is sent together with the first PATH_CHALLENGE.
	path.status = h.getStatus()
	c.signalPathStatus(path)
}

// newServerPath creates a path when the first packet on a new path ID was received (server only).
// See section 3.1 of draft-ietf-quic-multipath-21.
// The packet was successfully decrypted.
func (c *Conn) newServerPath(id protocol.PathID, p receivedPacket) {
	path := c.mp.addPath(id, c.conn.newPathConn(p.remoteAddr, p.info))
	path.info = p.info
	// Until the client's address is validated, the anti-amplification limit applies to the path.
	c.sentPacketHandler.AddPath(id, false)
	if c.addrDisc != nil {
		c.addrDisc.addPath(id)
	}
	if c.logger.Debug() {
		c.logger.Debugf("Peer opened path %d from %s.", id, p.remoteAddr)
	}
	c.startPathValidation(path, p.rcvTime)
}

// startPathValidation starts the validation of a path (section 8.2 of RFC 9000).
// PATH_CHALLENGE frames are sent with exponential backoff, starting at the PTO of the path,
// i.e. not more frequently than an Initial packet would be sent (section 8.2.1 of RFC 9000).
func (c *Conn) startPathValidation(path *mpPath, now monotime.Time) {
	path.state = mpPathValidating
	path.challenges = path.challenges[:0]
	path.challengeDue = true
	pathPTO := c.sentPacketHandler.GetPathRTTStats(path.id).PTO(true)
	path.challengeInterval = pathPTO
	// Section 8.2.4 of RFC 9000: three times the larger of the current PTO and the PTO of the new path.
	// The largest PTO among all paths is used as the current PTO.
	path.validationDeadline = now.Add(3 * max(c.sentPacketHandler.MaxPTO(true), pathPTO))
	c.scheduleSending()
}

// handlePathValidationResponse handles a PATH_RESPONSE frame received for a PATH_CHALLENGE frame
// sent to validate a path. It returns false if the PATH_RESPONSE doesn't belong to any PATH_CHALLENGE
// of a path that is being validated.
// The PATH_RESPONSE frame might be received on any path (section 8.2.3 of RFC 9000).
func (c *Conn) handlePathValidationResponse(f *wire.PathResponseFrame, now monotime.Time) (bool, error) {
	for _, id := range c.mp.pathIDs {
		path := c.mp.paths[id]
		if path.state != mpPathValidating {
			continue
		}
		idx := slices.IndexFunc(path.challenges, func(ch sentPathChallenge) bool { return ch.data == f.Data })
		if idx == -1 {
			continue
		}
		if !path.addressValidated {
			path.addressValidated = true
			c.sentPacketHandler.SetPathAddressValidated(id, now)
		}
		// Until a packet sent on the path is acknowledged, the PATH_CHALLENGE / PATH_RESPONSE exchange provides
		// the only RTT measurement of the path. This allows the scheduler to compare the path to other paths.
		if rttStats := c.sentPacketHandler.GetPathRTTStats(id); !rttStats.HasMeasurement() {
			rttStats.UpdateRTT(now.Sub(path.challenges[idx].sendTime), 0)
		}
		if path.challenges[idx].padded {
			path.mtuValidated = true
		}
		if path.mtuValidated {
			return true, c.activatePath(path, now)
		}
		// The PATH_CHALLENGE wasn't sent in a datagram of at least 1200 bytes,
		// because of the anti-amplification limit of the path.
		// Another validation is needed to validate the path MTU (section 8.2.3 of RFC 9000).
		if c.logger.Debug() {
			c.logger.Debugf("Validated the peer's address on path %d. Validating the path MTU.", id)
		}
		c.startPathValidation(path, now)
		return true, nil
	}
	return false, nil
}

// activatePath is called when a path was validated.
// Resources that are only needed on validated paths are allocated now
// (section 7.1 of draft-ietf-quic-multipath-21).
func (c *Conn) activatePath(path *mpPath, now monotime.Time) error {
	if c.logger.Debug() {
		c.logger.Debugf("Path %d validated.", path.id)
	}
	path.state = mpPathActive
	path.challenges = nil
	path.challengeDue = false
	// Provide connection IDs for migrations of this path.
	if err := c.connIDGenerator.TopUpPath(path.id); err != nil {
		return err
	}
	initialPacketSize := protocol.ByteCount(c.config.InitialPacketSize)
	path.mtuDiscoverer = newMTUDiscoverer(c.sentPacketHandler.GetPathRTTStats(path.id), initialPacketSize, c.peerMaxUDPPayloadSize(), nil)
	path.maxDatagramSize = initialPacketSize
	if !c.config.DisablePathMTUDiscovery && c.pathSendConn(path).capabilities().DF {
		path.mtuDiscoverer.Start(now)
	}
	c.updateMaxPayloadSizeEstimate()
	// The primary path was abandoned while no other path could be used for sending.
	if primary, ok := c.mp.paths[c.mp.primaryPathID]; !ok || !primary.usable() {
		c.movePrimaryPath()
	}
	c.notifyPathActive(path)
	// Path.Probe returns now: Conn.Paths must already list the path as active.
	c.updatePathsSnapshot()
	if path.handle != nil {
		// If the application closed the path in the meantime, the path will be abandoned.
		path.handle.setValidated()
	}
	// The server sends a token that is valid for the client's new address (section 3.1.3 of the draft).
	if c.perspective == protocol.PerspectiveServer {
		c.addValidatedClientAddr(c.pathSendConn(path).RemoteAddr())
	}
	c.mp.statusUpdateDue = true
	c.scheduleSending()
	return nil
}

// peerMaxUDPPayloadSize returns the maximum packet size the peer is willing to receive.
func (c *Conn) peerMaxUDPPayloadSize() protocol.ByteCount {
	maxPacketSize := protocol.ByteCount(protocol.MaxPacketBufferSize)
	if c.peerParams.MaxUDPPayloadSize > 0 && c.peerParams.MaxUDPPayloadSize < maxPacketSize {
		maxPacketSize = c.peerParams.MaxUDPPayloadSize
	}
	return maxPacketSize
}

// handleMultipathTimers handles the timers of the paths:
// It abandons paths whose validation timed out, schedules PATH_CHALLENGE frames,
// detects paths that potentially failed, and closes abandoned paths.
func (c *Conn) handleMultipathTimers(now monotime.Time) error {
	var newZombie bool
	for i := 0; i < len(c.mp.pathIDs); i++ {
		id := c.mp.pathIDs[i]
		path := c.mp.paths[id]
		switch path.state {
		case mpPathValidating:
			if !now.Before(path.validationDeadline) {
				// Section 3.1 of draft-ietf-quic-multipath-21: the path MUST be closed.
				code := qerr.PathUnstableOrPoor
				if !c.peerConnIDs.HasConnID(id) {
					// We never received a connection ID that would allow us to send on the path.
					code = qerr.NoCIDAvailableForPath
				}
				if c.logger.Debug() {
					c.logger.Debugf("Validation of path %d timed out.", id)
				}
				c.abandonPath(path, code, now, errPathValidationFailed)
				continue
			}
			if !path.challengeDue && !now.Before(path.nextChallenge) {
				path.challengeDue = true
			}
		case mpPathActive:
			if changed, failed := c.mp.failures.check(id, now.ToTime()); changed {
				if c.logger.Debug() && failed {
					c.logger.Debugf("Path %d potentially failed.", id)
				}
				c.pathFailureStateChanged(path, failed)
			}
			if !path.statusUpdateTime.IsZero() && !now.Before(path.statusUpdateTime) {
				path.statusUpdateTime = 0
				c.mp.statusUpdateDue = true
			}
		case mpPathAbandoned:
			if now.Before(path.retainUntil) || (path.zombie && !path.abandonRcvd) {
				continue
			}
			if !path.abandonRcvd {
				// Section 3.4 of draft-ietf-quic-multipath-21: the peer never responded to our PATH_ABANDON frame.
				// The connection IDs we issued for the path are kept, the peer might still use them.
				if c.logger.Debug() {
					c.logger.Debugf("Peer didn't respond to the PATH_ABANDON frame for path %d.", id)
				}
				path.zombie = true
				c.removePathState(path, now)
				newZombie = true
				continue
			}
			if err := c.closePath(path, now); err != nil {
				return err
			}
			i-- // the path was removed from pathIDs
		}
	}
	if len(c.mp.unusedAbandoned) > 0 {
		for _, id := range slices.Sorted(maps.Keys(c.mp.unusedAbandoned)) {
			if now.Before(c.mp.unusedAbandoned[id]) {
				continue
			}
			c.connIDGenerator.RemovePath(id)
			c.peerConnIDs.RemovePath(id)
			c.mp.removePath(id)
			if err := c.raiseMaxPathID(); err != nil {
				return err
			}
		}
	}
	// The paths that the application wants to open might have been waiting for the zombie path to be closed.
	// They can't be opened if our limit doesn't allow another path (see nextPathIDToOpen).
	if newZombie && c.handshakeConfirmed {
		c.maybeOpenPaths(now)
	}
	if c.mp.statusUpdateDue {
		c.mp.statusUpdateDue = false
		c.updatePathStatus(now)
	}
	return nil
}

// abandonPath abandons a path (section 3.4 of draft-ietf-quic-multipath-21) and sends a PATH_ABANDON frame.
// Calls to Path.Probe return pathErr.
func (c *Conn) abandonPath(path *mpPath, code qerr.TransportErrorCode, now monotime.Time, pathErr error) {
	if c.logger.Debug() {
		c.logger.Debugf("Abandoning path %d (error code %s).", path.id, code)
	}
	c.markPathAbandoned(path, now, pathErr)
	c.queuePathAbandonFrame(path.id, code)
}

// markPathAbandoned stops using a path.
// Its outstanding packets are declared lost, the peer's connection IDs for the path are retired,
// and the packets received on it are acknowledged promptly, on other paths (section 3.4 of draft-ietf-quic-multipath-21).
// Packets received on the path are processed until it is closed, 3 PTOs after both endpoints sent a PATH_ABANDON frame.
// Our connection IDs for the path are retired when it is closed.
func (c *Conn) markPathAbandoned(path *mpPath, now monotime.Time, pathErr error) {
	// Packets that the peer sent on the path before it received our PATH_ABANDON might still arrive.
	// They take up to the path's PTO, which is included in the largest PTO before the path is abandoned.
	path.abandonPTO = c.maxPTO(false)
	path.retainUntil = now.Add(3 * path.abandonPTO)
	path.state = mpPathAbandoned
	path.frames = nil
	path.migration = nil
	path.challenges = nil
	path.challengeDue = false
	path.statusUpdateTime = 0
	if c.addrDisc != nil {
		c.addrDisc.removePath(path.id)
	}
	c.sentPacketHandler.AbandonPath(path.id, now)
	c.receivedPacketHandler.AbandonPath(path.id)
	c.peerConnIDs.AbandonPath(path.id)
	c.connIDGenerator.AbandonPath(path.id)
	c.mp.failures.remove(path.id)
	c.mp.statusUpdateDue = true
	if c.mp.hasPreferredPath && path.id == c.mp.preferredPathID {
		c.mp.hasPreferredPath = false
	}
	if path.id == c.mp.primaryPathID {
		c.movePrimaryPath()
	}
	c.updateMaxPayloadSizeEstimate()
	c.notifyPathAbandoned(path)
	c.updatePathsSnapshot()
	if path.handle != nil {
		path.handle.setClosed(pathErr)
	}
	c.scheduleSending()
}

// removePathState removes the state of an abandoned path, except for the connection IDs.
// The peer's connection IDs for the path were retired when the path was abandoned,
// and later PATH_NEW_CONNECTION_ID frames for the path are ignored until it is closed.
func (c *Conn) removePathState(path *mpPath, now monotime.Time) {
	c.sentPacketHandler.RemovePath(path.id, now)
	c.receivedPacketHandler.RemovePath(path.id)
	c.cryptoStreamHandler.DropPath(path.id)
	c.mp.failures.remove(path.id)
}

// closePath closes an abandoned path: its state is removed, and its path ID is never used again.
// This happens 3 PTOs after both endpoints sent a PATH_ABANDON frame (section 3.4 of draft-ietf-quic-multipath-21).
// The maximum path ID is increased, so that the peer can open another path.
func (c *Conn) closePath(path *mpPath, now monotime.Time) error {
	if c.logger.Debug() {
		c.logger.Debugf("Closing path %d.", path.id)
	}
	if !path.zombie {
		c.removePathState(path, now)
	}
	c.connIDGenerator.RemovePath(path.id)
	c.peerConnIDs.RemovePath(path.id)
	c.mp.removePath(path.id)
	if c.addrDisc != nil {
		c.addrDisc.forgetPath(path.id)
	}
	return c.raiseMaxPathID()
}

// A primaryPath is the path that LocalAddr, RemoteAddr and ConnectionStats refer to.
// It can be read concurrently with the connection's run loop.
type primaryPath struct {
	id       protocol.PathID
	conn     sendConn
	rttStats *utils.RTTStats
}

// movePrimaryPath is called when the primary path is abandoned.
// The usable path with the lowest path ID becomes the primary path.
func (c *Conn) movePrimaryPath() {
	for _, id := range c.mp.pathIDs {
		path := c.mp.paths[id]
		if !path.usable() {
			continue
		}
		c.setPrimaryPath(path)
		return
	}
}

// setPrimaryPath makes a path the primary path.
func (c *Conn) setPrimaryPath(path *mpPath) {
	if c.logger.Debug() {
		c.logger.Debugf("Path %d is the primary path now.", path.id)
	}
	c.mp.primaryPathID = path.id
	c.primaryPath.Store(&primaryPath{id: path.id, conn: c.pathSendConn(path), rttStats: c.sentPacketHandler.GetPathRTTStats(path.id)})
}

// primarySendConn returns the sendConn of the primary path.
func (c *Conn) primarySendConn() sendConn {
	if p := c.primaryPath.Load(); p != nil {
		return p.conn
	}
	return c.conn
}

// primaryRTTStats returns the RTT statistics of the primary path.
func (c *Conn) primaryRTTStats() *utils.RTTStats {
	if p := c.primaryPath.Load(); p != nil {
		return p.rttStats
	}
	return c.rttStats
}

// signalPathStatus sends a PATH_STATUS_AVAILABLE or PATH_STATUS_BACKUP frame, if the status of a path changed
// (section 3.3 of draft-ietf-quic-multipath-21). No frame is sent for a path whose status is unknown.
// While the path is being validated, the frame is sent together with the PATH_CHALLENGE or PATH_RESPONSE frames
// (section 4.3).
func (c *Conn) signalPathStatus(path *mpPath) {
	backup := path.status == PathStatusBackup || path.autoBackup
	if path.statusSent {
		if path.sentBackup == backup {
			return
		}
	} else if !backup && path.status == PathStatusUnknown {
		return
	}
	f := &wire.PathStatusFrame{PathID: path.id, SequenceNumber: path.nextStatusSeq, Backup: backup}
	path.nextStatusSeq++
	path.statusSent = true
	path.sentBackup = backup
	if c.logger.Debug() {
		c.logger.Debugf("Signaling status of path %d: backup: %t", path.id, backup)
	}
	c.queuePathStatusFrame(path, ackhandler.Frame{Frame: f, Handler: &pathStatusFrameHandler{conn: c}})
}

func (c *Conn) queuePathStatusFrame(path *mpPath, f ackhandler.Frame) {
	if path.state == mpPathValidating {
		c.mp.queuePathFrame(path.id, f)
		c.scheduleSending()
		return
	}
	c.queueMultipathFrame(f)
}

// pathStatusFrameHandler retransmits a lost PATH_STATUS_AVAILABLE or PATH_STATUS_BACKUP frame,
// if it contains the last status sent for the path (section 4.3 of draft-ietf-quic-multipath-21).
type pathStatusFrameHandler struct {
	conn *Conn
}

var _ ackhandler.FrameHandler = &pathStatusFrameHandler{}

func (h *pathStatusFrameHandler) OnAcked(wire.Frame) {}

func (h *pathStatusFrameHandler) OnLost(f wire.Frame) {
	frame := f.(*wire.PathStatusFrame)
	path, ok := h.conn.mp.paths[frame.PathID]
	if !ok || path.state == mpPathAbandoned || frame.SequenceNumber+1 != path.nextStatusSeq {
		return
	}
	h.conn.queuePathStatusFrame(path, ackhandler.Frame{Frame: f, Handler: h})
}

// updatePathStatus follows the recommendation of section 3.3 of draft-ietf-quic-multipath-21 (MP-33):
// When data is sent on a backup path because all available paths potentially failed,
// the potentially failed paths are signaled as backup paths, such that the peer avoids them as well.
// They are signaled as available again once they recover.
// The status of a path is changed at most once per PTO of the path.
func (c *Conn) updatePathStatus(now monotime.Time) {
	var haveAvailable, haveBackup bool
	for _, id := range c.mp.pathIDs {
		path := c.mp.paths[id]
		if !path.usable() || c.mp.failures.potentiallyFailed(id) {
			continue
		}
		if path.isBackup() {
			haveBackup = true
		} else {
			haveAvailable = true
		}
	}
	usesBackupPath := !haveAvailable && haveBackup
	for _, id := range c.mp.pathIDs {
		path := c.mp.paths[id]
		if !path.usable() {
			continue
		}
		autoBackup := path.autoBackup
		if !c.mp.failures.potentiallyFailed(id) {
			autoBackup = false
		} else if usesBackupPath && !path.isBackup() {
			autoBackup = true
		}
		if autoBackup == path.autoBackup {
			path.statusUpdateTime = 0
			continue
		}
		if !path.autoBackupChanged.IsZero() {
			if next := path.autoBackupChanged.Add(c.sentPacketHandler.GetPathRTTStats(id).PTO(true)); now.Before(next) {
				path.statusUpdateTime = next
				continue
			}
		}
		path.autoBackup = autoBackup
		path.autoBackupChanged = now
		path.statusUpdateTime = 0
		c.signalPathStatus(path)
	}
}

// multipathSentPacket is called when an ack-eliciting packet was sent on a path.
func (c *Conn) multipathSentPacket(id protocol.PathID, now monotime.Time) {
	path, ok := c.mp.paths[id]
	if !ok || !path.usable() {
		return
	}
	if changed, failed := c.mp.failures.sent(id, now.ToTime()); changed {
		c.pathFailureStateChanged(path, failed)
	}
}

// pathFailureStateChanged is called when a path potentially failed, or when it recovered.
func (c *Conn) pathFailureStateChanged(path *mpPath, failed bool) {
	c.mp.statusUpdateDue = true
	if failed {
		path.failureDue = true
	} else {
		// The data sent on paths that failed at the same time as this path can now be retransmitted on this path.
		for _, id := range c.mp.pathIDs {
			if id != path.id && c.mp.failures.potentiallyFailed(id) {
				c.mp.paths[id].failureDue = true
			}
		}
	}
	c.notifyPathFailureState(path.id, failed)
	c.scheduleSending()
}

// hasOtherWorkingPath says if a path other than the given one can be used for sending, and didn't potentially fail.
func (c *Conn) hasOtherWorkingPath(id protocol.PathID) bool {
	for _, pid := range c.mp.pathIDs {
		if pid != id && c.mp.paths[pid].usable() && !c.mp.failures.potentiallyFailed(pid) {
			return true
		}
	}
	return false
}

// handleFailedPaths handles the paths that potentially failed.
// Packets sent on a path are only declared lost when an acknowledgment is received for the path, or when its probe
// timeout expires (section 5.7 of draft-ietf-quic-multipath-21). On a path that failed, the data sent on the path would
// only be retransmitted slowly. If another path can be used, the outstanding packets of the path are declared lost,
// so that their frames are retransmitted on the other paths. Like any other loss, this reduces the congestion window
// of the path (section 7.3.2 of RFC 9002).
// Until the path recovers, only PING frames are sent on it: right away, and in its probe packets.
// While no other path works, the path is still used for sending. Its data is moved once another path works,
// i.e. when another path is validated or recovers.
func (c *Conn) handleFailedPaths(now monotime.Time) {
	for _, id := range c.mp.pathIDs {
		path := c.mp.paths[id]
		if !path.failureDue {
			continue
		}
		if !path.usable() || !c.mp.failures.potentiallyFailed(id) {
			path.failureDue = false
			continue
		}
		if !c.hasOtherWorkingPath(id) {
			continue
		}
		path.failureDue = false
		if c.logger.Debug() {
			c.logger.Debugf("Retransmitting the data sent on path %d on other paths.", id)
		}
		c.sentPacketHandler.DeclareOutstandingLost(id, now)
		if c.multipathReinjectionManager != nil {
			// no packets are outstanding on the path anymore
			c.multipathReinjectionManager.forgetPacketsExcept(id, nil)
		}
		path.pingDue = true
	}
}

// multipathAckReceived is called when an ACK or PATH_ACK frame acknowledged a packet sent on a path.
func (c *Conn) multipathAckReceived(path *mpPath) {
	var smoothedRTT time.Duration
	if rttStats := c.sentPacketHandler.GetPathRTTStats(path.id); rttStats != nil && rttStats.HasMeasurement() {
		smoothedRTT = rttStats.SmoothedRTT()
	}
	if c.mp.failures.acked(path.id, smoothedRTT) {
		if c.logger.Debug() {
			c.logger.Debugf("Path %d recovered.", path.id)
		}
		c.pathFailureStateChanged(path, false)
	}
}

// A pathWriteError is an error that occurred when sending a packet on the sendConn of a path.
type pathWriteError struct {
	conn sendConn
	err  error
}

// handlePathWriteError is called by the send queue when sending a packet on the sendConn of a path fails.
// It is called from the send queue's goroutine.
func (c *Conn) handlePathWriteError(conn sendConn, err error) {
	c.pathWriteErrorsMx.Lock()
	c.pathWriteErrors = append(c.pathWriteErrors, pathWriteError{conn: conn, err: err})
	c.pathWriteErrorsMx.Unlock()
	c.scheduleSending()
}

// handlePathWriteErrors abandons the paths that couldn't be sent on.
// If no other path is open, the connection is closed, as it is for errors on the connection's sendConn.
func (c *Conn) handlePathWriteErrors(now monotime.Time) error {
	c.pathWriteErrorsMx.Lock()
	errs := c.pathWriteErrors
	c.pathWriteErrors = nil
	c.pathWriteErrorsMx.Unlock()

	for _, e := range errs {
		path := c.mp.pathForConn(e.conn)
		if path == nil {
			continue
		}
		// A path that is being validated might still become usable.
		if !c.mp.hasOtherOpenPath(path.id) {
			return e.err
		}
		if c.logger.Debug() {
			c.logger.Debugf("Error sending on path %d: %s", path.id, e.err)
		}
		c.abandonPath(path, qerr.PathUnstableOrPoor, now, e.err)
	}
	return nil
}

// handleMultipathPacketOnPath is called for every 1-RTT packet received on a path, once IETF Multipath QUIC is active.
// It responds to the PATH_CHALLENGE frames of the packet on the path, to the 4-tuple that the packet was received on
// (section 3.1 of draft-ietf-quic-multipath-21).
//
// A packet received from another 4-tuple than the one the path uses is a migration of the path (section 3.1.2):
// the server validates the new 4-tuple using a connection ID of the path that is only used for this 4-tuple,
// and switches the path to it in response to the highest-numbered non-probing packet (section 9.3 of RFC 9000).
// The path only switches once the path MTU of the new 4-tuple was validated as well (section 8.2.1 of RFC 9000).
// After switching, the previously active 4-tuple is validated (section 9.3.3 of RFC 9000).
// Only the client migrates paths, and it drops packets from unknown server addresses (section 9 of RFC 9000).
func (c *Conn) handleMultipathPacketOnPath(path *mpPath, p receivedPacket, pn protocol.PacketNumber, isNonProbing bool, challenges []*wire.PathChallengeFrame) error {
	if path.state == mpPathAbandoned {
		return nil
	}
	conn := c.pathSendConn(path)
	if pathUsesAddrs(conn, p.remoteAddr, p.info) {
		if c.perspective == protocol.PerspectiveServer {
			path.info = p.info
		}
		c.queuePathResponses(path.id, challenges)
		return nil
	}
	// The client only sends from the local address of the path. It never sends packets to unknown server addresses,
	// these packets were dropped before.
	if c.perspective == protocol.PerspectiveClient {
		return nil
	}
	localAddr := p.info.addr.Unmap()
	pm := c.pathMigrationManager(path)
	// The anti-amplification limit applies until the client's address is validated.
	// The packets sent in response to this datagram share 3 times its size.
	budget := amplificationFactor * p.Size()
	if pm.AddrValidated(p.remoteAddr, localAddr) {
		budget = protocol.MaxByteCount
	}
	var shouldSwitch bool
	for i := 0; i == 0 || i < len(challenges); i++ {
		var challenge *wire.PathChallengeFrame
		if i < len(challenges) {
			challenge = challenges[i]
		}
		// If no unused connection ID of the path is available, the 4-tuple is not validated,
		// and the PATH_CHALLENGE is not answered. This includes the case that the client didn't provide
		// any connection ID for the path yet (section 3.1 of draft-ietf-quic-multipath-21).
		connID, frames, switchPath := pm.HandlePacketOnTuple(p.remoteAddr, p.info, p.rcvTime, challenge, isNonProbing)
		shouldSwitch = shouldSwitch || switchPath
		if len(frames) == 0 {
			continue
		}
		frames = c.observedAddrProbeFrame(frames, path.id, multipathObservationTuple(p.remoteAddr, p.info))
		sent, err := c.sendMultipathProbeToTuple(path, connID, frames, p.remoteAddr, p.info, budget, p.rcvTime)
		if err != nil {
			return err
		}
		budget -= sent
	}
	// Section 9.3 of RFC 9000: the path only switches in response to the highest-numbered non-probing packet.
	if !shouldSwitch || pn != path.largestRcvdPN || !path.usable() {
		return nil
	}
	prevAddr, prevInfo := conn.RemoteAddr(), path.info
	slot, ok := pm.SwitchToTuple(p.remoteAddr, localAddr)
	if c.logger.Debug() {
		c.logger.Debugf("Path %d migrated to %s.", path.id, p.remoteAddr)
	}
	prevSlot := invalidPathID
	if c.prefAddr.isMigration(path.id, p.info) {
		// Path 0 migrated to the preferred address (section 2.2 of draft-ietf-quic-multipath-21).
		// Packets received on the original address are dropped (section 9.6.2 of RFC 9000),
		// so the previous 4-tuple is not validated.
		c.prefAddr.migrated(localAddr)
	} else {
		// Section 9.3.3 of RFC 9000: the previously active 4-tuple is validated.
		// This defends against an attacker that forwards packets from another address:
		// a non-probing packet received on the previous 4-tuple switches the path back.
		prevSlot = pm.AddPreviousTuple(prevAddr, prevInfo, p.rcvTime)
	}
	// The connection ID used to validate the 4-tuple was only used towards this 4-tuple (section 9.5 of RFC 9000).
	// The path keeps using it. The connection ID used so far is used to validate the previous 4-tuple,
	// or retired if the previous 4-tuple is not validated.
	if ok {
		c.peerConnIDs.UseConnIDForTuple(path.id, slot, prevSlot)
	}
	c.migrateMultipathPath(path, p.remoteAddr, p.info, p.rcvTime)
	// Section 9.3 of RFC 9000: the server SHOULD send a new address validation token.
	c.addValidatedClientAddr(p.remoteAddr)
	return nil
}

// sendMultipathProbeToTuple sends a packet with PATH_CHALLENGE and PATH_RESPONSE frames on a path,
// to the 4-tuple of remoteAddr and the local address in info. The datagram is expanded to 1200 bytes, unless the budget
// of the anti-amplification limit doesn't allow this (section 8.2.1 of RFC 9000).
// It returns the size of the packet sent.
func (c *Conn) sendMultipathProbeToTuple(
	path *mpPath,
	connID protocol.ConnectionID,
	frames []ackhandler.Frame,
	remoteAddr net.Addr,
	info packetInfo,
	budget protocol.ByteCount,
	now monotime.Time,
) (protocol.ByteCount, error) {
	maxSize := min(c.pathMaxPacketSize(path), budget)
	var padTo protocol.ByteCount
	if maxSize >= protocol.MinInitialPacketSize {
		padTo = protocol.MinInitialPacketSize
	}
	packet, buf, err := c.packer.PackMultipathProbePacket(path.id, connID, frames, maxSize, padTo, now, c.version)
	if err != nil {
		if err != errNothingToPack {
			return 0, err
		}
		// The frames don't fit. The 4-tuple is validated once the next packet is received from it.
		for _, f := range frames {
			switch f.Frame.(type) {
			case *wire.PathChallengeFrame, *wire.ObservedAddressFrame:
				f.Handler.OnLost(f.Frame)
			}
		}
		return 0, nil
	}
	if packet.Length < protocol.MinInitialPacketSize {
		for _, f := range frames {
			if f, ok := f.Frame.(*wire.PathChallengeFrame); ok {
				path.migration.ChallengeNotExpanded(f.Data)
			}
		}
	}
	if c.logger.Debug() {
		c.logger.Debugf("Sending path probe packet on path %d to %s.", path.id, remoteAddr)
	}
	// ECN is not used on unvalidated paths.
	ecn := c.sentPacketHandler.ECNMode(false)
	c.logShortHeaderPacket(packet, ecn, buf.Len())
	c.registerPackedShortHeaderPacket(packet, ecn, now)
	if err := c.pathSendConn(path).WriteTo(buf.Data, remoteAddr, info); err != nil {
		c.logger.Debugf("Error sending path probe packet on path %d to %s: %s", path.id, remoteAddr, err)
	}
	buf.Release()
	return packet.Length, nil
}

// sendDueTupleChallenges sends the PATH_CHALLENGE frames that are due on other 4-tuples of a path (server only):
// the second PATH_CHALLENGE that validates the path MTU of a 4-tuple, and the PATH_CHALLENGE that validates the
// previously active 4-tuple after the path migrated. The client's address was validated for these 4-tuples,
// so the datagrams are expanded to 1200 bytes (section 8.2.1 of RFC 9000).
func (c *Conn) sendDueTupleChallenges(path *mpPath, now monotime.Time) error {
	if path.migration == nil {
		return nil
	}
	for {
		connID, addr, info, f, ok := path.migration.PopDueChallenge(now)
		if !ok {
			return nil
		}
		if _, err := c.sendMultipathProbeToTuple(path, connID, []ackhandler.Frame{f}, addr, info, protocol.MaxByteCount, now); err != nil {
			return err
		}
	}
}

// pathMigrationManager returns the tupleManager that validates other 4-tuples of a path (server only).
// Every 4-tuple uses its own connection ID of the path (section 3.1.2 of draft-ietf-quic-multipath-21).
func (c *Conn) pathMigrationManager(path *mpPath) *tupleManager {
	if path.migration == nil {
		id := path.id
		path.migration = newTupleManager(
			func(slot pathID) (protocol.ConnectionID, bool) { return c.peerConnIDs.GetConnIDForTuple(id, slot) },
			func(slot pathID) { c.peerConnIDs.RetireConnIDForTuple(id, slot) },
			func() time.Duration {
				if rttStats := c.sentPacketHandler.GetPathRTTStats(id); rttStats != nil {
					return rttStats.PTO(true)
				}
				return c.maxPTO(true)
			},
			c.logger,
		)
	}
	return path.migration
}

// migrateMultipathPath migrates a path to another 4-tuple (section 5.1 of draft-ietf-quic-multipath-21).
// The path's congestion controller and RTT estimate are reset (section 9.4 of RFC 9000),
// and Path MTU Discovery and ECN validation start again (section 9.2 of RFC 9000). Other paths are not affected.
// The server uses it when a path of the client migrated. The client can use it for path 0, when path 0 migrates
// to the server's preferred address (section 2.2 of draft-ietf-quic-multipath-21, see allowServerAddr).
func (c *Conn) migrateMultipathPath(path *mpPath, remoteAddr net.Addr, info packetInfo, now monotime.Time) {
	initialPacketSize := protocol.ByteCount(c.config.InitialPacketSize)
	c.sentPacketHandler.MigratedPathForPath(path.id, now, initialPacketSize)
	path.maxDatagramSize = initialPacketSize
	conn := c.pathSendConn(path)
	if d := c.pathMTUDiscoverer(path); d != nil && !c.config.DisablePathMTUDiscovery && conn.capabilities().DF {
		d.Reset(now, initialPacketSize, c.peerMaxUDPPayloadSize())
	}
	conn.ChangeRemoteAddr(remoteAddr, info)
	path.info = info
	c.observedAddrPathSwitched(path.id, multipathObservationTuple(remoteAddr, info))
	c.mp.failures.remove(path.id)
	c.mp.statusUpdateDue = true
	c.updateMaxPayloadSizeEstimate()
	c.scheduleSending()
}

// allowServerAddr makes the client accept packets on a path from a server address other than the one the path
// sends to (section 9 of RFC 9000). This is needed when path 0 migrates to the server's preferred address:
// the connection ID provided in the preferred_address transport parameter is the connection ID with sequence
// number 1 of path 0 (section 2.2 of draft-ietf-quic-multipath-21), and the server responds from the preferred address
// before path 0 migrated there (see migrateMultipathPath).
func (m *multipathState) allowServerAddr(id protocol.PathID, addr net.Addr) {
	if path, ok := m.paths[id]; ok {
		path.otherServerAddrs = append(path.otherServerAddrs, addr)
	}
}

// isKnownServerAddr says if the client accepts packets on a path from a server address:
// the address the path sends to, or another address allowed by allowServerAddr.
func (c *Conn) isKnownServerAddr(path *mpPath, addr net.Addr) bool {
	sendAddr := c.pathSendConn(path).RemoteAddr()
	if peerAddrsEqual(addr, sendAddr) {
		return true
	}
	// The client dialed an unspecified IP address, see isKnownServerAddr0.
	if c.unspecifiedServerAddr != nil && peerAddrsEqual(sendAddr, c.peerHandshakeAddr) && peerAddrsEqual(addr, c.unspecifiedServerAddr) {
		return true
	}
	return slices.ContainsFunc(path.otherServerAddrs, func(a net.Addr) bool { return peerAddrsEqual(addr, a) })
}

// addValidatedClientAddr is called by the server when an address of the client was validated,
// on a new path or after a path migrated. If the address is new, the server sends a NEW_TOKEN frame with a token
// that is valid for this address and the most recently validated addresses, up to handshake.MaxTokenAddrs addresses
// (section 3.1.3 of draft-ietf-quic-multipath-21).
func (c *Conn) addValidatedClientAddr(addr net.Addr) {
	addrs := c.mp.validatedClientAddrs
	if idx := slices.IndexFunc(addrs, func(a net.Addr) bool { return handshake.SameTokenAddr(a, addr) }); idx >= 0 {
		// The token sent last is valid for this address already.
		c.mp.validatedClientAddrs = append(slices.Delete(addrs, idx, idx+1), addr)
		return
	}
	addrs = append(addrs, addr)
	if len(addrs) > handshake.MaxTokenAddrs {
		addrs = slices.Delete(addrs, 0, len(addrs)-handshake.MaxTokenAddrs)
	}
	c.mp.validatedClientAddrs = addrs
	// the most recently validated address first
	others := make([]net.Addr, 0, len(addrs)-1)
	for i := len(addrs) - 2; i >= 0; i-- {
		others = append(others, addrs[i])
	}
	token, err := c.tokenGenerator.NewToken(addr, c.primaryRTTStats().SmoothedRTT(), c.version, others...)
	if err != nil {
		c.logger.Debugf("Failed to create a token: %s", err)
		return
	}
	c.queueControlFrame(&wire.NewTokenFrame{Token: token})
}

// pathSendConn returns the sendConn used for a path.
func (c *Conn) pathSendConn(path *mpPath) sendConn {
	if path.conn == nil {
		return c.conn
	}
	return path.conn
}

// pathUsesAddrs says if a packet received from remoteAddr, on the local address in info,
// was received on the 4-tuple that the sendConn sends on.
// The local addresses are only compared if both are known.
func pathUsesAddrs(conn sendConn, remoteAddr net.Addr, info packetInfo) bool {
	if !peerAddrsEqual(remoteAddr, conn.RemoteAddr()) {
		return false
	}
	if !info.addr.IsValid() {
		return true
	}
	localIP, ok := netip.AddrFromSlice(ipFromAddr(conn.LocalAddr()))
	if !ok || localIP.Unmap().IsUnspecified() {
		return true
	}
	return localIP.Unmap() == info.addr.Unmap()
}

// newPathChallenge returns a new PATH_CHALLENGE frame with unpredictable data (section 8.2.1 of RFC 9000).
func newPathChallenge() *wire.PathChallengeFrame {
	f := &wire.PathChallengeFrame{}
	_, _ = rand.Read(f.Data[:])
	return f
}
