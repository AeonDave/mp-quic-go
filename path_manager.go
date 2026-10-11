package quic

import (
	"crypto/rand"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/utils"
	"github.com/AeonDave/mp-quic-go/internal/wire"
)

type pathID int64

const invalidPathID pathID = -1

// Maximum number of paths to keep track of.
// If the peer probes another path (before the pathTimeout of an existing path expires),
// this probing attempt is ignored.
const maxPaths = 3

// If no packet is received for a path for pathTimeout,
// the path can be evicted when the peer probes another path.
// This prevents an attacker from churning through paths by duplicating packets and
// sending them with spoofed source addresses.
const pathTimeout = 5 * time.Second

// The maximum number of PATH_CHALLENGE frames sent to validate a path.
// The peer might not respond to a PATH_CHALLENGE, e.g. if it doesn't have an unused connection ID because a
// NEW_CONNECTION_ID frame was lost, or the PATH_RESPONSE might be lost, while the packet containing the
// PATH_CHALLENGE was acknowledged.
const maxPathChallenges = 5

// A sentChallenge is a PATH_CHALLENGE frame sent to validate a path (or a 4-tuple, see tupleManager).
type sentChallenge struct {
	data [8]byte
	// The datagram containing the PATH_CHALLENGE couldn't be expanded to 1200 bytes, because of the
	// anti-amplification limit. Its PATH_RESPONSE only validates the peer's address, not the path MTU
	// (section 8.2.1 of RFC 9000).
	notExpanded bool
}

// pathChallenges are the PATH_CHALLENGE frames sent to validate a path.
// If the peer doesn't respond, another PATH_CHALLENGE is sent when a packet is received on the path,
// but not more frequently than an Initial packet would be sent: after a PTO, with exponential backoff
// (section 8.2.1 of RFC 9000). A PATH_RESPONSE to any of them validates the path.
type pathChallenges struct {
	sent     []sentChallenge // the most recent one at the end
	lastSent monotime.Time
}

// add generates a new PATH_CHALLENGE that is sent now.
func (c *pathChallenges) add(now monotime.Time) [8]byte {
	var data [8]byte
	rand.Read(data[:])
	c.sent = append(c.sent, sentChallenge{data: data})
	c.lastSent = now
	return data
}

// get returns the PATH_CHALLENGE with this data, or nil.
func (c *pathChallenges) get(data [8]byte) *sentChallenge {
	for i := range c.sent {
		if c.sent[i].data == data {
			return &c.sent[i]
		}
	}
	return nil
}

func (c *pathChallenges) isLast(data [8]byte) bool {
	return len(c.sent) > 0 && c.sent[len(c.sent)-1].data == data
}

func (c *pathChallenges) reset() {
	c.sent = c.sent[:0]
}

// retryDue says if another PATH_CHALLENGE should be sent now.
func (c *pathChallenges) retryDue(now monotime.Time, pto time.Duration) bool {
	if len(c.sent) == 0 || len(c.sent) >= maxPathChallenges {
		return false
	}
	return !now.Before(c.lastSent.Add(pto << (len(c.sent) - 1)))
}

type path struct {
	id   pathID
	addr net.Addr
	// The local address that the packets were received on, if the server distinguishes local addresses,
	// see HandlePacketOnLocalAddr.
	local netip.Addr
	// the packet info used to send packets on this path
	info           packetInfo
	lastPacketTime monotime.Time
	challenges     pathChallenges
	// The peer's address was validated. The anti-amplification limit doesn't apply anymore.
	addrValidated bool
	// A PATH_CHALLENGE needs to be sent in a datagram of at least 1200 bytes, see PopDueChallenge.
	challengeDue   bool
	validated      bool
	rcvdNonProbing bool
}

type pathManager struct {
	nextPathID pathID
	// ordered by lastPacketTime, with the most recently used path at the end
	paths []*path

	getConnID    func(pathID) (_ protocol.ConnectionID, ok bool)
	retireConnID func(pathID)
	pto          func() time.Duration

	logger utils.Logger
}

func newPathManager(
	getConnID func(pathID) (_ protocol.ConnectionID, ok bool),
	retireConnID func(pathID),
	pto func() time.Duration,
	logger utils.Logger,
) *pathManager {
	return &pathManager{
		paths:        make([]*path, 0, maxPaths+1),
		getConnID:    getConnID,
		retireConnID: retireConnID,
		pto:          pto,
		logger:       logger,
	}
}

// Returns a path challenge frame if one should be sent.
// May return nil.
func (pm *pathManager) HandlePacket(
	remoteAddr net.Addr,
	t monotime.Time,
	pathChallenge *wire.PathChallengeFrame, // may be nil if the packet didn't contain a PATH_CHALLENGE
	isNonProbing bool,
) (_ protocol.ConnectionID, _ []ackhandler.Frame, shouldSwitch bool) {
	return pm.HandlePacketOnLocalAddr(remoteAddr, netip.Addr{}, packetInfo{}, t, pathChallenge, isNonProbing)
}

// HandlePacketOnLocalAddr is HandlePacket for a server that distinguishes the local addresses that packets are
// received on: the paths to the same remote address from different local addresses are different paths.
// A server with a preferred address uses it for the packets received on the preferred address (section 9.6 of
// RFC 9000), and the invalid address for all other packets.
// info is the packet info of the packet, which is used to send packets on a new path.
// If the path is not validated yet, the packet can trigger another PATH_CHALLENGE, see pathChallenges.
func (pm *pathManager) HandlePacketOnLocalAddr(
	remoteAddr net.Addr,
	local netip.Addr,
	info packetInfo,
	t monotime.Time,
	pathChallenge *wire.PathChallengeFrame, // may be nil if the packet didn't contain a PATH_CHALLENGE
	isNonProbing bool,
) (_ protocol.ConnectionID, _ []ackhandler.Frame, shouldSwitch bool) {
	var p *path
	var retryChallenge bool
	for i, path := range pm.paths {
		if addrsEqual(path.addr, remoteAddr) && path.local == local {
			p = path
			p.lastPacketTime = t
			// already sent a PATH_CHALLENGE for this path
			if isNonProbing {
				path.rcvdNonProbing = true
			}
			if pm.logger.Debug() {
				pm.logger.Debugf("received packet for path %s that was already probed, validated: %t", remoteAddr, path.validated)
			}
			shouldSwitch = path.validated && path.rcvdNonProbing
			if i != len(pm.paths)-1 {
				// move the path to the end of the list
				pm.paths = slices.Delete(pm.paths, i, i+1)
				pm.paths = append(pm.paths, p)
			}
			// The peer didn't respond to the PATH_CHALLENGE (yet).
			// A PATH_CHALLENGE that is due is sent by PopDueChallenge.
			retryChallenge = !path.validated && !path.challengeDue && path.challenges.retryDue(t, pm.pto())
			if pathChallenge == nil && !retryChallenge {
				return protocol.ConnectionID{}, nil, shouldSwitch
			}
			break
		}
	}

	// A PATH_CHALLENGE received on a known path is always answered (section 8.2.2 of RFC 9000).
	// The path already uses a connection ID, so the limit only applies to previously unseen paths.
	if p == nil && len(pm.paths) >= maxPaths {
		if pm.paths[0].lastPacketTime.Add(pathTimeout).After(t) {
			if pm.logger.Debug() {
				pm.logger.Debugf("received packet for previously unseen path %s, but already have %d paths", remoteAddr, len(pm.paths))
			}
			return protocol.ConnectionID{}, nil, shouldSwitch
		}
		// evict the oldest path, if the last packet was received more than pathTimeout ago
		pm.retireConnID(pm.paths[0].id)
		pm.paths = pm.paths[1:]
	}

	var pathID pathID
	if p != nil {
		pathID = p.id
	} else {
		pathID = pm.nextPathID
	}

	// previously unseen path, initiate path validation by sending a PATH_CHALLENGE
	connID, ok := pm.getConnID(pathID)
	if !ok {
		pm.logger.Debugf("skipping validation of new path %s since no connection ID is available", remoteAddr)
		return protocol.ConnectionID{}, nil, shouldSwitch
	}

	frames := make([]ackhandler.Frame, 0, 2)
	if p == nil || retryChallenge {
		if p == nil {
			p = &path{
				id:             pm.nextPathID,
				addr:           remoteAddr,
				local:          local,
				info:           info,
				lastPacketTime: t,
				rcvdNonProbing: isNonProbing,
			}
			pm.nextPathID++
			pm.paths = append(pm.paths, p)
			pm.logger.Debugf("enqueueing PATH_CHALLENGE for new path %s", remoteAddr)
		} else {
			pm.logger.Debugf("enqueueing another PATH_CHALLENGE for path %s", remoteAddr)
		}
		frames = append(frames, ackhandler.Frame{
			Frame:   &wire.PathChallengeFrame{Data: p.challenges.add(t)},
			Handler: (*pathManagerAckHandler)(pm),
		})
	}
	if pathChallenge != nil {
		frames = append(frames, ackhandler.Frame{
			Frame:   &wire.PathResponseFrame{Data: pathChallenge.Data},
			Handler: (*pathManagerAckHandler)(pm),
		})
	}
	return connID, frames, shouldSwitch
}

func (pm *pathManager) HandlePathResponseFrame(f *wire.PathResponseFrame) {
	for _, p := range pm.paths {
		// A response to any of the PATH_CHALLENGEs sent on the path validates the path.
		challenge := p.challenges.get(f.Data)
		if challenge == nil {
			continue
		}
		p.addrValidated = true
		if challenge.notExpanded {
			// Section 8.2.1 of RFC 9000: a second path validation, using a PATH_CHALLENGE in a datagram
			// of at least 1200 bytes, validates the path MTU.
			p.challenges.reset()
			p.challengeDue = true
			pm.logger.Debugf("address %s validated, validating the path MTU", p.addr)
			break
		}
		// path validated
		p.validated = true
		pm.logger.Debugf("path %s validated", p.addr)
		break
	}
}

// ChallengeNotExpanded is called when the datagram containing the PATH_CHALLENGE frame couldn't be expanded
// to 1200 bytes, because of the anti-amplification limit (section 8.2.1 of RFC 9000).
// Once the peer's address is validated, another PATH_CHALLENGE is sent in an expanded datagram (see PopDueChallenge),
// and the path is only validated once the response to that PATH_CHALLENGE is received.
func (pm *pathManager) ChallengeNotExpanded(data [8]byte) {
	for _, p := range pm.paths {
		if challenge := p.challenges.get(data); challenge != nil {
			challenge.notExpanded = true
			return
		}
	}
}

// AddrValidated says if the peer's address of a path was validated, see HandlePacketOnLocalAddr.
// Packets sent to a validated address are not limited by the anti-amplification limit.
func (pm *pathManager) AddrValidated(remoteAddr net.Addr, local netip.Addr) bool {
	for _, p := range pm.paths {
		if addrsEqual(p.addr, remoteAddr) && p.local == local {
			return p.addrValidated
		}
	}
	return false
}

// AddPreviousPath is called after the connection switched to a new path (see SwitchToPathOnLocalAddr),
// which removed all other paths. The previously active path is validated (section 9.3.3 of RFC 9000),
// see PopDueChallenge. If the validation succeeds, a non-probing packet received on that path makes the connection
// switch back to it.
// It returns the ID of the path, which identifies the connection ID used for it.
func (pm *pathManager) AddPreviousPath(addr net.Addr, local netip.Addr, info packetInfo, t monotime.Time) pathID {
	p := &path{
		id:             pm.nextPathID,
		addr:           addr,
		local:          local,
		info:           info,
		lastPacketTime: t,
		// The address was validated before.
		addrValidated: true,
		challengeDue:  true,
	}
	pm.nextPathID++
	pm.paths = append(pm.paths, p)
	return p.id
}

// PopDueChallenge returns a PATH_CHALLENGE frame that needs to be sent on a path whose peer address was validated,
// together with the connection ID, the remote address and the packet info used for that path:
// the second PATH_CHALLENGE that validates the path MTU (see ChallengeNotExpanded), or the PATH_CHALLENGE that
// validates the previously active path (see AddPreviousPath).
// The datagram containing the frame needs to be expanded to at least 1200 bytes.
// Paths that no connection ID is available for are removed.
func (pm *pathManager) PopDueChallenge(now monotime.Time) (_ protocol.ConnectionID, _ net.Addr, _ packetInfo, _ ackhandler.Frame, ok bool) {
	for i := 0; i < len(pm.paths); i++ {
		p := pm.paths[i]
		if !p.challengeDue {
			continue
		}
		p.challengeDue = false
		connID, ok := pm.getConnID(p.id)
		if !ok {
			pm.logger.Debugf("skipping validation of path %s since no connection ID is available", p.addr)
			pm.paths = slices.Delete(pm.paths, i, i+1)
			pm.retireConnID(p.id)
			i--
			continue
		}
		f := ackhandler.Frame{
			Frame:   &wire.PathChallengeFrame{Data: p.challenges.add(now)},
			Handler: (*pathManagerAckHandler)(pm),
		}
		return connID, p.addr, p.info, f, true
	}
	return protocol.ConnectionID{}, nil, packetInfo{}, ackhandler.Frame{}, false
}

// SwitchToPath is called when the connection switches to a new path
func (pm *pathManager) SwitchToPath(addr net.Addr) {
	pm.SwitchToPathOnLocalAddr(addr, netip.Addr{})
}

// SwitchToPathOnLocalAddr is SwitchToPath for a server that distinguishes local addresses,
// see HandlePacketOnLocalAddr.
// It returns the ID of the path, which identifies the connection ID used for it.
func (pm *pathManager) SwitchToPathOnLocalAddr(addr net.Addr, local netip.Addr) (_ pathID, ok bool) {
	id := invalidPathID
	// retire all other paths
	for _, path := range pm.paths {
		if addrsEqual(path.addr, addr) && path.local == local {
			pm.logger.Debugf("switching to path %d (%s)", path.id, addr)
			id = path.id
			continue
		}
		pm.retireConnID(path.id)
	}
	clear(pm.paths)
	pm.paths = pm.paths[:0]
	return id, id != invalidPathID
}

type pathManagerAckHandler pathManager

var _ ackhandler.FrameHandler = &pathManagerAckHandler{}

// Acknowledging the frame doesn't validate the path, only receiving the PATH_RESPONSE does.
// If the PATH_RESPONSE is lost, another PATH_CHALLENGE is sent, see pathChallenges.
func (pm *pathManagerAckHandler) OnAcked(f wire.Frame) {}

func (pm *pathManagerAckHandler) OnLost(f wire.Frame) {
	pc, ok := f.(*wire.PathChallengeFrame)
	if !ok {
		return
	}
	for i, path := range pm.paths {
		// A response to an earlier PATH_CHALLENGE can still be received.
		if path.challenges.isLast(pc.Data) {
			pm.paths = slices.Delete(pm.paths, i, i+1)
			pm.retireConnID(path.id)
			break
		}
	}
}

func addrsEqual(addr1, addr2 net.Addr) bool {
	if addr1 == nil || addr2 == nil {
		return false
	}
	a1, ok1 := addr1.(*net.UDPAddr)
	a2, ok2 := addr2.(*net.UDPAddr)
	if ok1 && ok2 {
		return a1.IP.Equal(a2.IP) && a1.Port == a2.Port
	}
	return addr1.String() == addr2.String()
}
