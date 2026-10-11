package quic

import (
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

// The maximum number of 4-tuples, other than the path's own 4-tuple, that are validated on a path (server only).
// Every 4-tuple uses up a connection ID of the path.
const maxTuplesPerPath = 3

// A tuple is a 4-tuple (remote address and local address) that the peer probed on a path of IETF Multipath QUIC.
type tuple struct {
	// identifies the connection ID used for this 4-tuple
	id   pathID
	addr net.Addr
	// The local address that the packets were received on, and the packet info used to send to this 4-tuple.
	// The local address is invalid if it is not known.
	localAddr      netip.Addr
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

// The tupleManager validates the 4-tuples that the client probes on a path of IETF Multipath QUIC (server only),
// and decides when the path migrates to another 4-tuple (section 3.1.2 of draft-ietf-quic-multipath-21).
// It works like the pathManager used for RFC 9000 connection migration, but it distinguishes 4-tuples by the
// local address as well, validates the path MTU of a 4-tuple whose PATH_CHALLENGE was limited by the
// anti-amplification limit (section 8.2.1 of RFC 9000), and validates the previously active 4-tuple after a
// migration (section 9.3.3 of RFC 9000). If the client doesn't respond, another PATH_CHALLENGE is sent, see
// pathChallenges.
// Every 4-tuple uses its own connection ID of the path: getConnID and retireConnID take the ID of the 4-tuple.
type tupleManager struct {
	nextID pathID
	// ordered by lastPacketTime, with the most recently used 4-tuple at the end
	tuples []*tuple

	getConnID    func(pathID) (_ protocol.ConnectionID, ok bool)
	retireConnID func(pathID)
	pto          func() time.Duration // the PTO of the path

	logger utils.Logger
}

func newTupleManager(
	getConnID func(pathID) (_ protocol.ConnectionID, ok bool),
	retireConnID func(pathID),
	pto func() time.Duration,
	logger utils.Logger,
) *tupleManager {
	return &tupleManager{
		tuples:       make([]*tuple, 0, maxTuplesPerPath+1),
		getConnID:    getConnID,
		retireConnID: retireConnID,
		pto:          pto,
		logger:       logger,
	}
}

// HandlePacketOnTuple is called for a packet received from remoteAddr on the local address in info.
// It returns the frames that need to be sent to that 4-tuple (a PATH_CHALLENGE for a 4-tuple that wasn't seen
// before, and a PATH_RESPONSE if the packet contained a PATH_CHALLENGE), and the connection ID used to send them.
// It also returns if the path should switch to that 4-tuple: the 4-tuple was validated,
// and a non-probing packet was received from it.
// If the 4-tuple is not validated yet, the packet can trigger another PATH_CHALLENGE, see pathChallenges.
func (m *tupleManager) HandlePacketOnTuple(
	remoteAddr net.Addr,
	info packetInfo,
	t monotime.Time,
	pathChallenge *wire.PathChallengeFrame, // may be nil if the packet didn't contain a PATH_CHALLENGE
	isNonProbing bool,
) (_ protocol.ConnectionID, _ []ackhandler.Frame, shouldSwitch bool) {
	localAddr := info.addr.Unmap()
	var tup *tuple
	var retryChallenge bool
	for i, tu := range m.tuples {
		if addrsEqual(tu.addr, remoteAddr) && tu.localAddr == localAddr {
			tup = tu
			tup.lastPacketTime = t
			// already sent a PATH_CHALLENGE for this 4-tuple
			if isNonProbing {
				tu.rcvdNonProbing = true
			}
			if m.logger.Debug() {
				m.logger.Debugf("received packet for 4-tuple %s that was already probed, validated: %t", remoteAddr, tu.validated)
			}
			shouldSwitch = tu.validated && tu.rcvdNonProbing
			if i != len(m.tuples)-1 {
				// move the 4-tuple to the end of the list
				m.tuples = slices.Delete(m.tuples, i, i+1)
				m.tuples = append(m.tuples, tup)
			}
			// The client didn't respond to the PATH_CHALLENGE (yet).
			// A PATH_CHALLENGE that is due is sent by PopDueChallenge.
			retryChallenge = !tu.validated && !tu.challengeDue && tu.challenges.retryDue(t, m.pto())
			if pathChallenge == nil && !retryChallenge {
				return protocol.ConnectionID{}, nil, shouldSwitch
			}
			break
		}
	}

	// A PATH_CHALLENGE received on a known 4-tuple is always answered (section 8.2.2 of RFC 9000).
	// The 4-tuple already uses a connection ID, so the limit only applies to previously unseen 4-tuples.
	if tup == nil && len(m.tuples) >= maxTuplesPerPath {
		if m.tuples[0].lastPacketTime.Add(pathTimeout).After(t) {
			if m.logger.Debug() {
				m.logger.Debugf("received packet for previously unseen 4-tuple %s, but already have %d 4-tuples", remoteAddr, len(m.tuples))
			}
			return protocol.ConnectionID{}, nil, shouldSwitch
		}
		// evict the oldest 4-tuple, if the last packet was received more than pathTimeout ago
		m.retireConnID(m.tuples[0].id)
		m.tuples = m.tuples[1:]
	}

	var id pathID
	if tup != nil {
		id = tup.id
	} else {
		id = m.nextID
	}

	// previously unseen 4-tuple, initiate validation by sending a PATH_CHALLENGE
	connID, ok := m.getConnID(id)
	if !ok {
		m.logger.Debugf("skipping validation of new 4-tuple %s since no connection ID is available", remoteAddr)
		return protocol.ConnectionID{}, nil, shouldSwitch
	}

	frames := make([]ackhandler.Frame, 0, 2)
	if tup == nil || retryChallenge {
		if tup == nil {
			tup = &tuple{
				id:             m.nextID,
				addr:           remoteAddr,
				localAddr:      localAddr,
				info:           info,
				lastPacketTime: t,
				rcvdNonProbing: isNonProbing,
			}
			m.nextID++
			m.tuples = append(m.tuples, tup)
			m.logger.Debugf("enqueueing PATH_CHALLENGE for new 4-tuple %s", remoteAddr)
		} else {
			m.logger.Debugf("enqueueing another PATH_CHALLENGE for 4-tuple %s", remoteAddr)
		}
		frames = append(frames, ackhandler.Frame{
			Frame:   &wire.PathChallengeFrame{Data: tup.challenges.add(t)},
			Handler: (*tupleManagerAckHandler)(m),
		})
	}
	if pathChallenge != nil {
		frames = append(frames, ackhandler.Frame{
			Frame:   &wire.PathResponseFrame{Data: pathChallenge.Data},
			Handler: (*tupleManagerAckHandler)(m),
		})
	}
	return connID, frames, shouldSwitch
}

func (m *tupleManager) HandlePathResponseFrame(f *wire.PathResponseFrame) {
	for _, tup := range m.tuples {
		// A response to any of the PATH_CHALLENGEs sent to the 4-tuple validates it.
		challenge := tup.challenges.get(f.Data)
		if challenge == nil {
			continue
		}
		tup.addrValidated = true
		if challenge.notExpanded {
			// Section 8.2.1 of RFC 9000: a second path validation, using a PATH_CHALLENGE in a datagram
			// of at least 1200 bytes, validates the path MTU.
			tup.challenges.reset()
			tup.challengeDue = true
			m.logger.Debugf("address %s validated, validating the path MTU", tup.addr)
			break
		}
		tup.validated = true
		m.logger.Debugf("4-tuple %s validated", tup.addr)
		break
	}
}

// ChallengeNotExpanded is called when the datagram containing the PATH_CHALLENGE frame couldn't be expanded
// to 1200 bytes, because of the anti-amplification limit (section 8.2.1 of RFC 9000).
// Once the peer's address is validated, another PATH_CHALLENGE is sent in an expanded datagram,
// and the 4-tuple is only validated once the response to that PATH_CHALLENGE is received.
func (m *tupleManager) ChallengeNotExpanded(data [8]byte) {
	for _, tup := range m.tuples {
		if challenge := tup.challenges.get(data); challenge != nil {
			challenge.notExpanded = true
			return
		}
	}
}

// AddrValidated says if the address of a 4-tuple was validated, see HandlePacketOnTuple.
// Packets sent to a validated address are not limited by the anti-amplification limit.
func (m *tupleManager) AddrValidated(remoteAddr net.Addr, localAddr netip.Addr) bool {
	for _, tup := range m.tuples {
		if addrsEqual(tup.addr, remoteAddr) && tup.localAddr == localAddr {
			return tup.addrValidated
		}
	}
	return false
}

// AddPreviousTuple is called after the path switched to another 4-tuple (see SwitchToTuple),
// which removed all other 4-tuples. The previously active 4-tuple is validated (section 9.3.3 of RFC 9000),
// see PopDueChallenge.
// If the validation succeeds, a non-probing packet received on that 4-tuple switches the path back to it.
// It returns the ID of the 4-tuple, which identifies the connection ID used for it.
func (m *tupleManager) AddPreviousTuple(addr net.Addr, info packetInfo, t monotime.Time) pathID {
	tup := &tuple{
		id:             m.nextID,
		addr:           addr,
		localAddr:      info.addr.Unmap(),
		info:           info,
		lastPacketTime: t,
		// The address was validated before.
		addrValidated: true,
		challengeDue:  true,
	}
	m.nextID++
	m.tuples = append(m.tuples, tup)
	return tup.id
}

// PopDueChallenge returns a PATH_CHALLENGE frame that needs to be sent to a 4-tuple whose address
// was validated, together with the connection ID, the remote address and the packet info used for that 4-tuple:
// the second PATH_CHALLENGE that validates the path MTU (see ChallengeNotExpanded), or the PATH_CHALLENGE that
// validates the previously active 4-tuple (see AddPreviousTuple).
// The datagram containing the frame needs to be expanded to at least 1200 bytes.
// 4-tuples that no connection ID is available for are removed.
func (m *tupleManager) PopDueChallenge(now monotime.Time) (_ protocol.ConnectionID, _ net.Addr, _ packetInfo, _ ackhandler.Frame, ok bool) {
	for i := 0; i < len(m.tuples); i++ {
		tup := m.tuples[i]
		if !tup.challengeDue {
			continue
		}
		tup.challengeDue = false
		connID, ok := m.getConnID(tup.id)
		if !ok {
			m.logger.Debugf("skipping validation of 4-tuple %s since no connection ID is available", tup.addr)
			m.tuples = slices.Delete(m.tuples, i, i+1)
			m.retireConnID(tup.id)
			i--
			continue
		}
		f := ackhandler.Frame{
			Frame:   &wire.PathChallengeFrame{Data: tup.challenges.add(now)},
			Handler: (*tupleManagerAckHandler)(m),
		}
		return connID, tup.addr, tup.info, f, true
	}
	return protocol.ConnectionID{}, nil, packetInfo{}, ackhandler.Frame{}, false
}

// SwitchToTuple is called when the path switches to a 4-tuple, see HandlePacketOnTuple.
// The connection IDs of all other 4-tuples are retired.
// It returns the ID of that 4-tuple, which identifies the connection ID used for it.
func (m *tupleManager) SwitchToTuple(addr net.Addr, localAddr netip.Addr) (_ pathID, ok bool) {
	id := invalidPathID
	for _, tup := range m.tuples {
		if addrsEqual(tup.addr, addr) && tup.localAddr == localAddr {
			m.logger.Debugf("switching to 4-tuple %d (%s)", tup.id, addr)
			id = tup.id
			continue
		}
		m.retireConnID(tup.id)
	}
	clear(m.tuples)
	m.tuples = m.tuples[:0]
	return id, id != invalidPathID
}

type tupleManagerAckHandler tupleManager

var _ ackhandler.FrameHandler = &tupleManagerAckHandler{}

// Acknowledging the frame doesn't validate the 4-tuple, only receiving the PATH_RESPONSE does.
// If the PATH_RESPONSE is lost, another PATH_CHALLENGE is sent, see pathChallenges.
func (m *tupleManagerAckHandler) OnAcked(f wire.Frame) {}

func (m *tupleManagerAckHandler) OnLost(f wire.Frame) {
	pc, ok := f.(*wire.PathChallengeFrame)
	if !ok {
		return
	}
	for i, tup := range m.tuples {
		// A response to an earlier PATH_CHALLENGE can still be received.
		if tup.challenges.isLast(pc.Data) {
			m.tuples = slices.Delete(m.tuples, i, i+1)
			m.retireConnID(tup.id)
			break
		}
	}
}
