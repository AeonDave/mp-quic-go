package quic

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/wire"
)

var (
	// ErrPathClosed can be returned by [Path.Probe] or [Path.Switch] after the path has been closed.
	ErrPathClosed = errors.New("path closed")
	// ErrPathNotValidated is returned by [Path.Switch] when the path has not yet been validated.
	ErrPathNotValidated = errors.New("path not yet validated")
	// ErrTooManyPaths is returned by [Path.Probe] if the path can't be opened
	// because as many paths as allowed by [Config.MaxPaths] are in use.
	ErrTooManyPaths = errors.New("too many paths")
)

var errPathDoesNotExist = errors.New("path does not exist")

// Path is a network path.
type Path struct {
	id          pathID
	pathManager *pathManagerOutgoing
	tr          *Transport
	initialRTT  time.Duration

	enablePath func()
	validated  atomic.Bool
	abandon    chan struct{}

	// set for a path of IETF Multipath QUIC
	mp *mpPathHandle
	// set for a path added before completion of the handshake, see deferredPath
	deferred *deferredPath
}

// Probe validates the path.
// With IETF Multipath QUIC, it first opens the path, using an unused path ID.
// If all path IDs allowed by [Config.MaxPaths] are in use, it returns [ErrTooManyPaths].
// If all path IDs allowed by the peer are in use, it sends a PATHS_BLOCKED frame and waits until the peer
// allows more paths using a MAX_PATH_ID frame (section 3.2.1 of draft-ietf-quic-multipath-21).
// The peer might never do so, so the context should have a deadline.
// If the context is canceled before the path is validated, the path is abandoned.
// For a path added before completion of the handshake, Probe waits for the handshake to complete.
func (p *Path) Probe(ctx context.Context) error {
	if p.deferred != nil {
		path, err := p.deferred.resolve(ctx)
		if err != nil {
			return err
		}
		return path.Probe(ctx)
	}
	if p.mp != nil {
		return p.mp.Probe(ctx)
	}
	path := p.pathManager.addPath(p, p.enablePath)

	p.pathManager.enqueueProbe(p)
	nextProbeDur := p.initialRTT
	var timer *time.Timer
	var timerChan <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-path.Validated():
			p.validated.Store(true)
			return nil
		case <-timerChan:
			nextProbeDur *= 2 // exponential backoff
			p.pathManager.enqueueProbe(p)
		case <-path.ProbeSent():
		case <-p.abandon:
			return ErrPathClosed
		}

		if timer != nil {
			timer.Stop()
		}
		timer = time.NewTimer(nextProbeDur)
		timerChan = timer.C
	}
}

// ID returns the path ID of a path of IETF Multipath QUIC.
// It returns false until the path was opened by [Path.Probe], and for paths that are not paths of
// IETF Multipath QUIC, i.e. if IETF Multipath QUIC was not negotiated.
func (p *Path) ID() (PathID, bool) {
	if p.deferred != nil {
		path := p.deferred.resolved()
		if path == nil {
			return 0, false
		}
		return path.ID()
	}
	if p.mp == nil {
		return 0, false
	}
	return p.mp.pathID()
}

// Switch switches the QUIC connection to this path.
// It immediately stops sending on the old path, and sends on this new path.
// With IETF Multipath QUIC, all validated paths are used for sending. Switch makes the path the preferred path:
// as long as it can be used, data is only sent on this path. The other paths stay open.
func (p *Path) Switch() error {
	if p.deferred != nil {
		path := p.deferred.resolved()
		if path == nil {
			return p.deferred.errUnresolved(ErrPathNotValidated)
		}
		return path.Switch()
	}
	if p.mp != nil {
		return p.mp.Switch()
	}
	if err := p.pathManager.switchToPath(p.id); err != nil {
		switch {
		case errors.Is(err, ErrPathNotValidated):
			return err
		case errors.Is(err, errPathDoesNotExist) && !p.validated.Load():
			select {
			case <-p.abandon:
				return ErrPathClosed
			default:
				return ErrPathNotValidated
			}
		default:
			return ErrPathClosed
		}
	}
	return nil
}

// SetStatus sets the status of the path, and signals it to the peer
// (see section 3.3 of draft-ietf-quic-multipath-21).
// Data is only sent on a backup path if no other path can be used. The peer is asked to do the same.
// The status can be set before the path is probed: it is then sent together with the frames validating the path.
// It is only supported for paths of IETF Multipath QUIC.
func (p *Path) SetStatus(status PathStatus) error {
	if p.deferred != nil {
		return p.deferred.setStatus(status)
	}
	if p.mp == nil {
		return errors.New("path status requires IETF Multipath QUIC")
	}
	return p.mp.SetStatus(status)
}

// Close abandons a path.
// It is not possible to close the path that’s currently active.
// With IETF Multipath QUIC, the last path that can be used for sending can't be closed.
// After closing, the path cannot be successfully probed again with [Path.Probe].
func (p *Path) Close() error {
	if p.deferred != nil {
		return p.deferred.close()
	}
	if p.mp != nil {
		return p.mp.Close()
	}
	select {
	case <-p.abandon:
		return nil
	default:
	}

	if err := p.pathManager.removePath(p.id); err != nil {
		return err
	}
	close(p.abandon)
	return nil
}

// A deferredPath is a path that a client added before completion of the handshake, after it advertised
// IETF Multipath QUIC. Whether it is a path of IETF Multipath QUIC or a path used for connection migration
// (RFC 9000) depends on the server's transport parameters. This is resolved by Path.Probe, once the handshake
// completed.
type deferredPath struct {
	handshakeComplete <-chan struct{}
	connDone          <-chan struct{}
	// creates the path, once the handshake completed
	newPath func() (*Path, error)

	mx     sync.Mutex
	path   *Path
	err    error
	closed bool
	status PathStatus // the status set before the path was resolved
}

func newDeferredPath(c *Conn, newPath func() (*Path, error)) *Path {
	return &Path{deferred: &deferredPath{
		handshakeComplete: c.HandshakeComplete(),
		connDone:          c.Context().Done(),
		newPath:           newPath,
	}}
}

// resolve waits for the handshake to complete, and creates the path.
func (d *deferredPath) resolve(ctx context.Context) (*Path, error) {
	select {
	case <-d.handshakeComplete:
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-d.connDone:
		return nil, ErrPathClosed
	}
	d.mx.Lock()
	defer d.mx.Unlock()

	if d.closed {
		return nil, ErrPathClosed
	}
	if d.path == nil && d.err == nil {
		d.path, d.err = d.newPath()
		if d.err == nil && d.path.mp != nil && d.status != PathStatusUnknown {
			if err := d.path.mp.SetStatus(d.status); err != nil {
				d.path, d.err = nil, err
			}
		}
	}
	return d.path, d.err
}

// resolved returns the path, if it was already created.
func (d *deferredPath) resolved() *Path {
	d.mx.Lock()
	defer d.mx.Unlock()

	return d.path
}

// errUnresolved returns the error returned by a method of a path that wasn't created yet.
func (d *deferredPath) errUnresolved(err error) error {
	d.mx.Lock()
	defer d.mx.Unlock()

	if d.closed {
		return ErrPathClosed
	}
	return err
}

// setStatus sets the status of the path. If the path wasn't created yet, the status is applied when it is created,
// if it is a path of IETF Multipath QUIC.
func (d *deferredPath) setStatus(status PathStatus) error {
	if status != PathStatusAvailable && status != PathStatusBackup {
		return fmt.Errorf("invalid path status: %s", status)
	}
	d.mx.Lock()
	path := d.path
	if path == nil {
		defer d.mx.Unlock()
		if d.closed {
			return ErrPathClosed
		}
		d.status = status
		return nil
	}
	d.mx.Unlock()
	return path.SetStatus(status)
}

func (d *deferredPath) close() error {
	d.mx.Lock()
	path := d.path
	if path == nil {
		d.closed = true
		d.mx.Unlock()
		return nil
	}
	d.mx.Unlock()
	return path.Close()
}

type pathOutgoing struct {
	pathChallenges [][8]byte // length is implicitly limited by exponential backoff
	tr             *Transport
	isValidated    bool
	probeSent      chan struct{} // receives when a PATH_CHALLENGE is sent
	validated      chan struct{} // closed when the path the corresponding PATH_RESPONSE is received
	enablePath     func()
}

func (p *pathOutgoing) ProbeSent() <-chan struct{} { return p.probeSent }
func (p *pathOutgoing) Validated() <-chan struct{} { return p.validated }

// handshakePathID is the ID of the path used for the handshake.
// Paths added with AddPath use IDs starting at 1.
const handshakePathID pathID = 0

type pathManagerOutgoing struct {
	getConnID       func(pathID) (_ protocol.ConnectionID, ok bool)
	retireConnID    func(pathID)
	scheduleSending func()
	// the Transport used for the handshake, if known
	handshakeTransport *Transport

	mx             sync.Mutex
	activePath     pathID
	pathsToProbe   []pathID
	paths          map[pathID]*pathOutgoing
	nextPathID     pathID
	pathToSwitchTo *pathOutgoing
}

// newPathManagerOutgoing creates a new pathManagerOutgoing object. This
// function must be side-effect free as it may be called multiple times for a
// single connection.
func newPathManagerOutgoing(
	getConnID func(pathID) (_ protocol.ConnectionID, ok bool),
	retireConnID func(pathID),
	scheduleSending func(),
	handshakeTransport *Transport,
) *pathManagerOutgoing {
	return &pathManagerOutgoing{
		activePath:         handshakePathID, // at initialization time, we're guaranteed to be using the handshake path
		nextPathID:         handshakePathID + 1,
		getConnID:          getConnID,
		retireConnID:       retireConnID,
		scheduleSending:    scheduleSending,
		handshakeTransport: handshakeTransport,
		paths:              make(map[pathID]*pathOutgoing, 4),
	}
}

func (pm *pathManagerOutgoing) addPath(p *Path, enablePath func()) *pathOutgoing {
	pm.mx.Lock()
	defer pm.mx.Unlock()

	// path might already exist, and just being re-probed
	if existingPath, ok := pm.paths[p.id]; ok {
		existingPath.validated = make(chan struct{})
		return existingPath
	}

	path := &pathOutgoing{
		tr:         p.tr,
		probeSent:  make(chan struct{}, 1),
		validated:  make(chan struct{}),
		enablePath: enablePath,
	}
	pm.paths[p.id] = path
	return path
}

func (pm *pathManagerOutgoing) enqueueProbe(p *Path) {
	pm.mx.Lock()
	pm.pathsToProbe = append(pm.pathsToProbe, p.id)
	pm.mx.Unlock()
	pm.scheduleSending()
}

func (pm *pathManagerOutgoing) removePath(id pathID) error {
	if err := pm.removePathImpl(id); err != nil {
		return err
	}
	pm.scheduleSending()
	return nil
}

func (pm *pathManagerOutgoing) removePathImpl(id pathID) error {
	pm.mx.Lock()
	defer pm.mx.Unlock()

	if id == pm.activePath {
		return errors.New("cannot close active path")
	}
	if _, ok := pm.paths[id]; !ok {
		return nil
	}
	pm.retireConnID(id)
	delete(pm.paths, id)
	return nil
}

func (pm *pathManagerOutgoing) switchToPath(id pathID) error {
	pm.mx.Lock()
	defer pm.mx.Unlock()

	p, ok := pm.paths[id]
	if !ok {
		return errPathDoesNotExist
	}
	if !p.isValidated {
		return ErrPathNotValidated
	}
	pm.pathToSwitchTo = p
	pm.activePath = id
	return nil
}

func (pm *pathManagerOutgoing) NewPath(t *Transport, initialRTT time.Duration, enablePath func()) *Path {
	pm.mx.Lock()
	defer pm.mx.Unlock()

	id := pm.nextPathID
	pm.nextPathID++
	return &Path{
		pathManager: pm,
		id:          id,
		tr:          t,
		enablePath:  enablePath,
		initialRTT:  initialRTT,
		abandon:     make(chan struct{}),
	}
}

func (pm *pathManagerOutgoing) NextPathToProbe() (_ protocol.ConnectionID, _ ackhandler.Frame, _ *Transport, hasPath bool) {
	pm.mx.Lock()
	defer pm.mx.Unlock()

	var p *pathOutgoing
	id := invalidPathID
	for _, pID := range pm.pathsToProbe {
		var ok bool
		p, ok = pm.paths[pID]
		if ok {
			id = pID
			break
		}
		// if the path doesn't exist in the map, it might have been abandoned
		pm.pathsToProbe = pm.pathsToProbe[1:]
	}
	if id == invalidPathID {
		return protocol.ConnectionID{}, ackhandler.Frame{}, nil, false
	}

	connID, ok := pm.getConnID(id)
	if !ok {
		return protocol.ConnectionID{}, ackhandler.Frame{}, nil, false
	}

	var b [8]byte
	_, _ = rand.Read(b[:])
	p.pathChallenges = append(p.pathChallenges, b)

	pm.pathsToProbe = pm.pathsToProbe[1:]
	p.enablePath()
	select {
	case p.probeSent <- struct{}{}:
	default:
	}
	frame := ackhandler.Frame{
		Frame:   &wire.PathChallengeFrame{Data: b},
		Handler: (*pathManagerOutgoingAckHandler)(pm),
	}
	return connID, frame, p.tr, true
}

// InactivePathConnID returns the connection ID used to answer a PATH_CHALLENGE received on the Transport tr,
// if tr isn't the Transport of the active path. The PATH_RESPONSE is sent from tr, using a connection ID that isn't
// used on any other path (sections 8.2.2 and 9.5 of RFC 9000).
// This is the connection ID of a path added with AddPath that uses tr (the one added first, if multiple paths use tr).
// After the client switched away from the path used for the handshake, PATH_CHALLENGE frames can arrive on the
// Transport used for the handshake, e.g. when the server validates the previous path (section 9.3.3 of RFC 9000).
// They are answered using a new connection ID, since the connection ID used before was retired.
// isInactive is false if tr is the Transport of the active path, or a Transport unknown to the path manager.
// ok is false if no connection ID is available for the path.
func (pm *pathManagerOutgoing) InactivePathConnID(tr *Transport) (_ protocol.ConnectionID, isInactive, ok bool) {
	pm.mx.Lock()
	defer pm.mx.Unlock()

	if tr == pm.activeTransport() {
		return protocol.ConnectionID{}, false, false
	}
	id := invalidPathID
	for pID, p := range pm.paths {
		if p.tr != tr {
			continue
		}
		if id == invalidPathID || pID < id {
			id = pID
		}
	}
	if id == invalidPathID && tr == pm.handshakeTransport {
		id = handshakePathID
	}
	if id == invalidPathID {
		return protocol.ConnectionID{}, false, false
	}
	connID, ok := pm.getConnID(id)
	return connID, true, ok
}

// activeTransport returns the Transport of the active path.
// It must be called with the mutex held.
func (pm *pathManagerOutgoing) activeTransport() *Transport {
	if pm.activePath == handshakePathID {
		return pm.handshakeTransport
	}
	if p, ok := pm.paths[pm.activePath]; ok {
		return p.tr
	}
	return nil
}

func (pm *pathManagerOutgoing) HandlePathResponseFrame(f *wire.PathResponseFrame) {
	pm.mx.Lock()
	defer pm.mx.Unlock()

	for _, p := range pm.paths {
		if slices.Contains(p.pathChallenges, f.Data) {
			// path validated
			if !p.isValidated {
				// make sure that duplicate PATH_RESPONSE frames are ignored
				p.isValidated = true
				p.pathChallenges = nil
				close(p.validated)
			}
			break
		}
	}
}

// ShouldSwitchPath returns the Transport and the ID of the path that the connection switches to.
// canSwitch says if a connection ID can be used on the path. If not, the switch is delayed:
// using the connection ID of the current path would link the two paths (section 9.5 of RFC 9000).
func (pm *pathManagerOutgoing) ShouldSwitchPath(canSwitch func(pathID) bool) (*Transport, pathID, bool) {
	pm.mx.Lock()
	defer pm.mx.Unlock()

	if pm.pathToSwitchTo == nil || !canSwitch(pm.activePath) {
		return nil, invalidPathID, false
	}
	p := pm.pathToSwitchTo
	pm.pathToSwitchTo = nil
	return p.tr, pm.activePath, true
}

type pathManagerOutgoingAckHandler pathManagerOutgoing

var _ ackhandler.FrameHandler = &pathManagerOutgoingAckHandler{}

// OnAcked is called when the PATH_CHALLENGE is acked.
// This doesn't validate the path, only receiving the PATH_RESPONSE does.
func (pm *pathManagerOutgoingAckHandler) OnAcked(wire.Frame) {}

func (pm *pathManagerOutgoingAckHandler) OnLost(wire.Frame) {}
