package quic

import (
	"fmt"
	"slices"

	"github.com/AeonDave/mp-quic-go/internal/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/wire"
)

// The anti-amplification factor, see section 8 of RFC 9000.
const amplificationFactor = 3

// The length of the authentication tag of the AEADs used with TLS 1.3.
const aeadTagLen = 16

// triggerSendingMultipath sends packets once IETF Multipath QUIC is active and the handshake is confirmed.
//
// It sends, in this order:
//  1. packets with frames that are bound to a path (PATH_CHALLENGE, PATH_RESPONSE), on that path,
//     not limited by congestion control (as path probing packets in RFC 9000),
//  2. PTO probe packets on the paths whose PTO expired (section 5.7 of draft-ietf-quic-multipath-21),
//  3. MTU probe packets, on the paths whose MTU discovery asks for one,
//  4. all other packets, on the active paths selected by the scheduler.
func (c *Conn) triggerSendingMultipath(now monotime.Time) error {
	c.pacingDeadline = 0

	if offset := c.connFlowController.GetWindowUpdate(now); offset > 0 {
		c.framer.QueueControlFrame(&wire.MaxDataFrame{MaximumData: offset})
	}
	if cf := c.cryptoStreamManager.GetPostHandshakeData(protocol.MaxPostHandshakeCryptoFrameSize); cf != nil {
		c.queueControlFrame(cf)
	}

	c.handleFailedPaths(now)
	if err := c.sendMultipathPathProbes(now); err != nil {
		return err
	}
	if c.sendQueue.WouldBlock() {
		return nil
	}
	if err := c.sendMultipathPTOProbes(now); err != nil {
		return err
	}
	if c.sendQueue.WouldBlock() {
		return nil
	}
	sentMTUProbe, err := c.maybeSendMultipathMTUProbe(now)
	if err != nil {
		return err
	}
	if sentMTUProbe {
		// There's (likely) more data to send. Loop around again.
		c.scheduleSending()
		return nil
	}
	return c.sendMultipathPackets(now)
}

// sendMultipathPathProbes sends the PATH_CHALLENGE and PATH_RESPONSE frames on the paths they belong to.
func (c *Conn) sendMultipathPathProbes(now monotime.Time) error {
	for _, id := range c.mp.pathIDs {
		path := c.mp.paths[id]
		if path.state == mpPathAbandoned {
			continue
		}
		if err := c.sendDueTupleChallenges(path, now); err != nil {
			return err
		}
		for path.challengeDue || len(path.frames) > 0 || c.observedAddrDue(path.id) {
			if c.sendQueue.WouldBlock() {
				return nil
			}
			sent, err := c.sendMultipathProbePacket(path, now)
			if err != nil {
				return err
			}
			if !sent {
				break
			}
		}
	}
	return nil
}

// sendMultipathProbePacket sends a packet with the PATH_CHALLENGE and PATH_RESPONSE frames of a path,
// and the OBSERVED_ADDRESS frame of QUIC Address Discovery, which is a probing frame as well
// (section 4.1 of draft-ietf-quic-address-discovery-01).
// Datagrams containing these frames are expanded to 1200 bytes, unless the anti-amplification limit
// of the path doesn't allow this (sections 8.2.1 and 8.2.2 of RFC 9000). A packet that only contains an
// OBSERVED_ADDRESS frame is not expanded.
// It returns false if no packet could be sent.
func (c *Conn) sendMultipathProbePacket(path *mpPath, now monotime.Time) (bool, error) {
	// Section 3.1 of draft-ietf-quic-multipath-21: the PATH_RESPONSE is delayed until the peer provides
	// a connection ID for the path.
	connID, ok := c.pathDestConnID(path)
	if !ok {
		return false, nil
	}
	maxSize := c.pathMaxPacketSize(path)
	padTo := protocol.ByteCount(protocol.MinInitialPacketSize)
	if budget := c.sentPacketHandler.AmplificationBudgetForPath(path.id); budget < protocol.MinInitialPacketSize {
		padTo = 0
		maxSize = min(maxSize, budget)
	}
	overhead := c.shortHeaderPacketOverhead(path, connID)
	if maxSize <= overhead {
		return false, nil
	}
	maxFramesLen := maxSize - overhead
	var frames []ackhandler.Frame
	var challenge *wire.PathChallengeFrame
	if path.challengeDue {
		challenge = newPathChallenge()
		if challenge.Length(c.version) > maxFramesLen {
			return false, nil
		}
		frames = append(frames, ackhandler.Frame{Frame: challenge})
		maxFramesLen -= challenge.Length(c.version)
	}
	frames, length := c.mp.AppendPathFrames(frames, path.id, maxFramesLen, c.version)
	if c.addrDisc != nil {
		var l protocol.ByteCount
		frames, l = c.addrDisc.AppendObservedAddress(frames, path.id, maxFramesLen-length, c.version)
		length += l
	}
	if len(frames) == 0 {
		return false, nil
	}
	if !slices.ContainsFunc(frames, func(f ackhandler.Frame) bool { _, ok := f.Frame.(*wire.ObservedAddressFrame); return !ok }) {
		padTo = 0
	}
	// Section 9.3.3 of RFC 9000: a PATH_CHALLENGE received on an active path is answered with a non-probing packet.
	// If the peer migrated the path because an attacker forwarded packets from another address,
	// this packet migrates the path back.
	if path.usable() && length < maxFramesLen && slices.ContainsFunc(frames, func(f ackhandler.Frame) bool {
		_, ok := f.Frame.(*wire.PathResponseFrame)
		return ok
	}) {
		frames = append(frames, ackhandler.Frame{Frame: &wire.PingFrame{}})
	}
	p, buf, err := c.packer.PackMultipathProbePacket(path.id, connID, frames, maxSize, padTo, now, c.version)
	if err != nil {
		if err == errNothingToPack {
			return false, nil
		}
		return false, err
	}
	if challenge != nil {
		path.challengeDue = false
		path.challenges = append(path.challenges, sentPathChallenge{
			data:     challenge.Data,
			sendTime: now,
			padded:   p.Length >= protocol.MinInitialPacketSize,
		})
		path.nextChallenge = now.Add(path.challengeInterval)
		path.challengeInterval *= 2
		c.mp.sentPathChallenge = true
	}
	// ECN is not used on unvalidated paths.
	ecn := c.sentPacketHandler.ECNMode(false)
	c.logShortHeaderPacket(p, ecn, buf.Len())
	c.registerPackedShortHeaderPacket(p, ecn, now)
	c.sendOnPath(path, buf, 0, ecn)
	return true, nil
}

// pathDestConnID returns the connection ID used for packets sent on the 4-tuple of a path.
// It returns false if the peer didn't provide a connection ID for the path.
func (c *Conn) pathDestConnID(path *mpPath) (protocol.ConnectionID, bool) {
	if path.id == 0 {
		return c.connIDManager.Get(), true
	}
	return c.peerConnIDs.Get(path.id)
}

// shortHeaderPacketOverhead returns the size of the short header and the AEAD tag of the next packet sent on a path
// to connID.
func (c *Conn) shortHeaderPacketOverhead(path *mpPath, connID protocol.ConnectionID) protocol.ByteCount {
	_, pnLen := c.sentPacketHandler.PeekPacketNumber(path.id, protocol.Encryption1RTT)
	return wire.ShortHeaderLen(connID, pnLen) + aeadTagLen
}

// sendMultipathPTOProbes sends the PTO probe packets on the paths whose PTO expired.
// On paths that potentially failed, only PING frames are sent, if another path can be used (see handleFailedPaths).
func (c *Conn) sendMultipathPTOProbes(now monotime.Time) error {
	for _, id := range c.mp.pathIDs {
		path := c.mp.paths[id]
		if !path.usable() {
			continue
		}
		failed := c.mp.failures.potentiallyFailed(id) && c.hasOtherWorkingPath(id)
		if path.pingDue && c.sentPacketHandler.SendModeForPath(id, now) != ackhandler.SendNone {
			path.pingDue = false
			if failed {
				if err := c.sendMultipathPing(path, now); err != nil {
					return err
				}
			}
		}
		if c.sentPacketHandler.SendModeForPath(id, now) != ackhandler.SendPTOAppData {
			path.reinjectedOnPTO = false
			continue
		}
		if failed {
			for c.sentPacketHandler.SendModeForPath(id, now) == ackhandler.SendPTOAppData {
				if c.sendQueue.WouldBlock() {
					c.scheduleSending()
					return nil
				}
				if err := c.sendMultipathPing(path, now); err != nil {
					return err
				}
			}
			continue
		}
		if !path.reinjectedOnPTO {
			path.reinjectedOnPTO = true
			c.maybeReinjectOnPTO(path, now)
		}
		for c.sentPacketHandler.SendModeForPath(id, now) == ackhandler.SendPTOAppData {
			if c.sendQueue.WouldBlock() {
				c.scheduleSending()
				return nil
			}
			if err := c.sendMultipathPTOProbe(path, now); err != nil {
				return err
			}
		}
	}
	return nil
}

// sendMultipathPing sends a packet containing a PING frame on a path.
func (c *Conn) sendMultipathPing(path *mpPath, now monotime.Time) error {
	p, buf, err := c.packer.PackPathPacket(path.id, []ackhandler.Frame{{Frame: &wire.PingFrame{}}}, nil, c.pathMaxPacketSize(path), c.version)
	if err != nil {
		return err
	}
	ecn := c.pathECN(path)
	c.logShortHeaderPacket(p, ecn, buf.Len())
	c.registerPackedShortHeaderPacket(p, ecn, now)
	c.sendOnPath(path, buf, 0, ecn)
	return nil
}

func (c *Conn) sendMultipathPTOProbe(path *mpPath, now monotime.Time) error {
	maxSize := c.pathMaxPacketSize(path)
	// Queue probe packets until we actually send out a packet,
	// or until there are no more packets to queue.
	var packet *coalescedPacket
	for packet == nil {
		if wasQueued := c.sentPacketHandler.QueueProbePacketForPath(path.id); !wasQueued {
			break
		}
		var err error
		packet, err = c.packer.PackPTOProbePacket(protocol.Encryption1RTT, maxSize, false, now, c.version, path.id)
		if err != nil {
			return err
		}
	}
	if packet == nil {
		var err error
		packet, err = c.packer.PackPTOProbePacket(protocol.Encryption1RTT, maxSize, true, now, c.version, path.id)
		if err != nil {
			return err
		}
	}
	if packet == nil || packet.shortHdrPacket == nil {
		return fmt.Errorf("connection BUG: couldn't pack a probe packet for path %d", path.id)
	}
	p := packet.shortHdrPacket
	ecn := c.pathECN(path)
	c.logShortHeaderPacket(*p, ecn, p.Length)
	c.registerPackedShortHeaderPacket(*p, ecn, now)
	c.sendOnPath(path, packet.buffer, 0, ecn)
	return nil
}

// maybeSendMultipathMTUProbe sends an MTU probe packet on a path whose MTU discovery asks for one.
// Every path performs its own Path MTU Discovery (section 5.8 of draft-ietf-quic-multipath-21).
func (c *Conn) maybeSendMultipathMTUProbe(now monotime.Time) (bool, error) {
	for _, id := range c.mp.pathIDs {
		path := c.mp.paths[id]
		if !path.usable() {
			continue
		}
		d := c.pathMTUDiscoverer(path)
		if d == nil || !d.ShouldSendProbe(now) || c.sentPacketHandler.SendModeForPath(id, now) != ackhandler.SendAny {
			continue
		}
		ping, size := d.GetPing(now)
		p, buf, err := c.packer.PackMTUProbePacket(ping, size, c.version, id)
		if err != nil {
			return false, err
		}
		ecn := c.pathECN(path)
		c.logShortHeaderPacket(p, ecn, buf.Len())
		c.registerPackedShortHeaderPacket(p, ecn, now)
		c.sendOnPath(path, buf, 0, ecn)
		return true, nil
	}
	return false, nil
}

// sendMultipathPackets sends packets on the active paths.
// Generic Segmentation Offload is only used if a single path can be used for sending.
func (c *Conn) sendMultipathPackets(now monotime.Time) error {
	usable := c.mp.usablePaths[:0]
	for _, id := range c.mp.pathIDs {
		if path := c.mp.paths[id]; path.usable() {
			usable = append(usable, path)
		}
	}
	c.mp.usablePaths = usable
	c.handlePendingReinjections(now)
	if len(usable) == 1 && c.pathSendConn(usable[0]).capabilities().GSO {
		// There's no other path to send lost frames on.
		c.reinjectionPathQueue = c.reinjectionPathQueue[:0]
		clear(c.reinjectionQueueCounts)
		return c.sendMultipathPacketsWithGSO(usable[0], now)
	}
	dataPaths := c.multipathDataPaths(usable)
	for {
		path := c.selectMultipathSendPath(dataPaths, now)
		if path == nil {
			return c.handleMultipathSendBlocked(dataPaths, usable, now)
		}
		buf := getPacketBuffer()
		ecn := c.pathECN(path)
		_, p, err := c.appendOneShortHeaderPacket(buf, c.pathMaxPacketSize(path), ecn, now, path.id)
		if err != nil {
			buf.Release()
			if err == errNothingToPack {
				return nil
			}
			return err
		}
		c.sendOnPath(path, buf, 0, ecn)
		c.maybeDuplicateFrames(&p, path, now)
		if c.sendQueue.WouldBlock() {
			return nil
		}
		// Prioritize receiving of packets over sending out more packets.
		if c.hasReceivedPackets() {
			c.pacingDeadline = deadlineSendImmediately
			return nil
		}
	}
}

// sendMultipathPacketsWithGSO sends packets on a single path, using Generic Segmentation Offload.
func (c *Conn) sendMultipathPacketsWithGSO(path *mpPath, now monotime.Time) error {
	if c.sentPacketHandler.SendModeForPath(path.id, now) != ackhandler.SendAny {
		return c.handleMultipathSendBlocked(c.mp.usablePaths, c.mp.usablePaths, now)
	}
	buf := getLargePacketBuffer()
	maxSize := c.pathMaxPacketSize(path)
	ecn := c.pathECN(path)
	for {
		var nothingToPack, dontSendMore bool
		size, _, err := c.appendOneShortHeaderPacket(buf, maxSize, ecn, now, path.id)
		if err != nil {
			if err != errNothingToPack {
				return err
			}
			if buf.Len() == 0 {
				buf.Release()
				return nil
			}
			nothingToPack = true
			dontSendMore = true
		}
		if !dontSendMore && c.sentPacketHandler.SendModeForPath(path.id, now) != ackhandler.SendAny {
			dontSendMore = true
		}

		// Don't send more packets in this batch if they require a different ECN marking than the previous ones.
		nextECN := c.pathECN(path)

		// Append another packet if
		// 1. The congestion controller and pacer allow sending more
		// 2. The last packet appended was a full-size packet
		// 3. The next packet will have the same ECN marking
		// 4. We still have enough space for another full-size packet in the buffer
		if !dontSendMore && size == maxSize && nextECN == ecn && buf.Len()+maxSize <= buf.Cap() {
			continue
		}

		c.sendOnPath(path, buf, uint16(maxSize), ecn)

		if nothingToPack {
			return nil
		}
		if dontSendMore {
			return c.handleMultipathSendBlocked(c.mp.usablePaths, c.mp.usablePaths, now)
		}
		if c.sendQueue.WouldBlock() {
			return nil
		}
		// Prioritize receiving of packets over sending out more packets.
		if c.hasReceivedPackets() {
			c.pacingDeadline = deadlineSendImmediately
			return nil
		}
		ecn = nextECN
		buf = getLargePacketBuffer()
	}
}

// multipathDataPaths returns the paths that data is sent on (section 3.3 of draft-ietf-quic-multipath-21):
// the usable paths that are neither backup paths nor potentially failed, if there are any.
// Otherwise, the backup paths that didn't potentially fail, if there are any, and otherwise all usable paths.
// A path is a backup path if the peer or the application marked it as such.
// If the application switched to a path (see Path.Switch), only that path is used, as long as it is usable and didn't
// potentially fail.
// Packets that are bound to a path, PTO probes, MTU probes and ACK-only packets are not affected by this.
func (c *Conn) multipathDataPaths(usable []*mpPath) []*mpPath {
	paths := c.appendMultipathDataPaths(c.mp.dataPaths[:0], usable)
	c.mp.dataPaths = paths
	return paths
}

func (c *Conn) appendMultipathDataPaths(paths, usable []*mpPath) []*mpPath {
	if c.mp.hasPreferredPath {
		if path, ok := c.mp.paths[c.mp.preferredPathID]; ok && path.usable() && !c.mp.failures.potentiallyFailed(path.id) {
			return append(paths, path)
		}
	}
	return c.appendMultipathDataPathsWithoutPreference(paths, usable)
}

func (c *Conn) appendMultipathDataPathsWithoutPreference(paths, usable []*mpPath) []*mpPath {
	start := len(paths)
	for _, path := range usable {
		if !path.isBackup() && !c.mp.failures.potentiallyFailed(path.id) {
			paths = append(paths, path)
		}
	}
	if len(paths) == start {
		for _, path := range usable {
			if !c.mp.failures.potentiallyFailed(path.id) {
				paths = append(paths, path)
			}
		}
	}
	if len(paths) == start {
		paths = append(paths, usable...)
	}
	return paths
}

// selectMultipathSendPath selects the path that the next packet is sent on,
// among the paths that data is sent on whose congestion controller and pacer allow sending.
// Lost frames that the reinjection policy assigned to a path are sent on that path.
// Otherwise, the multipath controller selects the path. If it doesn't select one of these paths,
// packets are sent on these paths in round-robin order. Since a path is only selected when its congestion controller
// and pacer allow sending, paths that can send at a higher rate are selected more often.
func (c *Conn) selectMultipathSendPath(dataPaths []*mpPath, now monotime.Time) *mpPath {
	candidates := c.mp.candidatePaths[:0]
	for _, path := range dataPaths {
		if c.sentPacketHandler.SendModeForPath(path.id, now) == ackhandler.SendAny {
			candidates = append(candidates, path)
		}
	}
	c.mp.candidatePaths = candidates
	if len(candidates) == 0 {
		return nil
	}
	selected := c.reinjectionTargetPath(candidates)
	if selected == nil {
		selected = c.controllerSelectPath(candidates, now)
	}
	if selected == nil {
		for _, path := range candidates {
			if path.id > c.mp.lastSendPathID {
				selected = path
				break
			}
		}
		if selected == nil {
			selected = candidates[0]
		}
	}
	c.mp.lastSendPathID = selected.id
	return selected
}

// reinjectionTargetPath returns the path that the reinjection policy selected for the lost frames that are queued for
// retransmission, if it is one of the candidate paths (see handlePendingReinjections).
func (c *Conn) reinjectionTargetPath(candidates []*mpPath) *mpPath {
	if len(c.reinjectionPathQueue) == 0 {
		return nil
	}
	// The lost frames were already sent.
	if !c.retransmissionQueue.HasData(protocol.Encryption1RTT) {
		c.reinjectionPathQueue = c.reinjectionPathQueue[:0]
		clear(c.reinjectionQueueCounts)
		return nil
	}
	for len(c.reinjectionPathQueue) > 0 {
		id := c.reinjectionPathQueue[0]
		c.reinjectionPathQueue = c.reinjectionPathQueue[1:]
		if count := c.reinjectionQueueCounts[id]; count <= 1 {
			delete(c.reinjectionQueueCounts, id)
		} else {
			c.reinjectionQueueCounts[id] = count - 1
		}
		for _, path := range candidates {
			if path.id == id {
				return path
			}
		}
	}
	return nil
}

// controllerSelectPath asks the multipath controller to select one of the candidate paths.
// It returns nil if there's no controller, or if the controller didn't select one of the candidates.
func (c *Conn) controllerSelectPath(candidates []*mpPath, now monotime.Time) *mpPath {
	if c.multipathController == nil {
		return nil
	}
	infos := c.mp.candidateInfos[:0]
	for _, path := range candidates {
		infos = append(infos, c.mpPathInfo(path))
	}
	c.mp.candidateInfos = infos
	info, ok := c.multipathController.SelectPath(PathSelectionContext{
		Now:               now.ToTime(),
		HasRetransmission: c.retransmissionQueue.HasData(protocol.Encryption1RTT),
		BytesInFlight:     c.sentPacketHandler.BytesInFlight(),
		PathCongestion:    c.pathCongestionFunc,
		Paths:             infos,
	})
	if !ok {
		return nil
	}
	for _, path := range candidates {
		if path.id == info.ID {
			return path
		}
	}
	return nil
}

// handleMultipathSendBlocked is called when no packet can be sent on any of the paths that data is sent on.
// It sets the pacing deadline and the block mode, and sends an ACK-only packet if an ACK is due:
// packets that only contain ACK frames are not congestion controlled (section 5.5 of draft-ietf-quic-multipath-21).
// ACK-only packets can be sent on all usable paths.
func (c *Conn) handleMultipathSendBlocked(dataPaths, usable []*mpPath, now monotime.Time) error {
	var pacingDeadline monotime.Time
	var canSendAck bool
	for _, path := range dataPaths {
		//nolint:exhaustive // PTO probes were sent before, and no packets can be sent with SendNone.
		switch c.sentPacketHandler.SendModeForPath(path.id, now) {
		case ackhandler.SendPacingLimited:
			canSendAck = true
			deadline := c.sentPacketHandler.TimeUntilSendForPath(path.id)
			if deadline.IsZero() {
				deadline = deadlineSendImmediately
			}
			if pacingDeadline.IsZero() || deadline.Before(pacingDeadline) {
				pacingDeadline = deadline
			}
		case ackhandler.SendAck, ackhandler.SendAny:
			canSendAck = true
		}
	}
	switch {
	case !pacingDeadline.IsZero():
		c.pacingDeadline = pacingDeadline
	case canSendAck:
		c.blocked = blockModeCongestionLimited
	default:
		c.blocked = blockModeHardBlocked
		return nil
	}
	return c.maybeSendMultipathAckOnlyPacket(usable, now)
}

// maybeSendMultipathAckOnlyPacket sends a packet containing the ACK frames that are due.
// It is sent on the path with the lowest path ID that an ACK is due for, if it can be used,
// and on the path with the lowest path ID that can send otherwise.
// The packet contains the ACK frames of all paths that an ACK is due for.
func (c *Conn) maybeSendMultipathAckOnlyPacket(paths []*mpPath, now monotime.Time) error {
	if c.sendQueue.WouldBlock() {
		return nil
	}
	canSendAck := func(path *mpPath) bool {
		return path.usable() && c.sentPacketHandler.SendModeForPath(path.id, now) != ackhandler.SendNone
	}
	var target *mpPath
	for _, id := range c.receivedPacketHandler.AckDuePaths(now) {
		if path, ok := c.mp.paths[id]; ok && canSendAck(path) {
			target = path
			break
		}
	}
	if target == nil {
		for _, path := range paths {
			if canSendAck(path) {
				target = path
				break
			}
		}
	}
	if target == nil {
		return nil
	}
	ecn := c.pathECN(target)
	p, buf, err := c.packer.PackAckOnlyPacket(c.pathMaxPacketSize(target), now, c.version, target.id)
	if err != nil {
		if err == errNothingToPack {
			return nil
		}
		return err
	}
	c.logShortHeaderPacket(p, ecn, buf.Len())
	c.registerPackedShortHeaderPacket(p, ecn, now)
	c.sendOnPath(target, buf, 0, ecn)
	return nil
}

// sendMultipathConnectionClose sends a packet containing a CONNECTION_CLOSE frame on a path.
// The packet is written to the path's sendConn right away, the send queue is not used.
// Every path performs its own ECN validation, so a 1-RTT packet uses the ECN marking of the path it is sent on
// (section 13.4.2 of RFC 9000).
func (c *Conn) sendMultipathConnectionClose(path *mpPath, packet *coalescedPacket) error {
	ecn := c.sentPacketHandler.ECNMode(false)
	if packet.IsOnlyShortHeaderPacket() {
		ecn = c.pathECN(path)
	}
	c.logCoalescedPacket(packet, ecn)
	conn := c.pathSendConn(path)
	if path.conn != nil && !path.conn.capabilities().ECN {
		ecn = protocol.ECNUnsupported
	}
	return conn.Write(packet.buffer.Data, 0, ecn)
}

// multipathConnectionClosePackets returns the packets containing a CONNECTION_CLOSE frame that are sent in the closing
// state, in response to packets received on a path (section 10.2.1 of RFC 9000), by path.
// A packet sent in response to a packet received on a path uses a connection ID of that path (section 3.1 of
// draft-ietf-quic-multipath-21), so a packet is packed for every path that can be used for sending. sent is the packet
// that was sent on the path chosen by sendConnectionClose. No packet is sent on the other paths, e.g. abandoned paths.
func (c *Conn) multipathConnectionClosePackets(e error, sent []byte) map[protocol.PathID][]byte {
	packets := make(map[protocol.PathID][]byte)
	closePathID, ok := c.mp.closePathID()
	if !ok {
		return packets
	}
	if sent != nil {
		packets[closePathID] = sent
	}
	for _, id := range c.mp.pathIDs {
		path := c.mp.paths[id]
		if id == closePathID || !path.usable() {
			continue
		}
		packet, err := c.packConnectionClose(e, c.pathMaxPacketSize(path), id)
		if err != nil {
			c.logger.Debugf("Error packing CONNECTION_CLOSE for path %d: %s", id, err)
			continue
		}
		packets[id] = packet.buffer.Data
	}
	return packets
}

// sendOnPath sends a packet on a path.
// If the path's sendConn doesn't support ECN, the packet is sent without ECN marking.
func (c *Conn) sendOnPath(path *mpPath, buf *packetBuffer, gsoSize uint16, ecn protocol.ECN) {
	if path.conn == nil {
		c.sendQueue.Send(buf, gsoSize, ecn)
		return
	}
	if !path.conn.capabilities().ECN {
		ecn = protocol.ECNUnsupported
	}
	c.sendQueue.SendOnConn(buf, gsoSize, ecn, path.conn)
}

// pathECN returns the ECN marking of a 1-RTT packet sent on a validated path.
// Every path performs its own ECN validation (section 13.4.2 of RFC 9000).
func (c *Conn) pathECN(path *mpPath) protocol.ECN {
	ecn := c.sentPacketHandler.ECNModeForPath(path.id)
	if path.conn != nil && !path.conn.capabilities().ECN && ecn != protocol.ECNUnsupported {
		// The packet will be sent without ECN marking.
		return protocol.ECNNon
	}
	return ecn
}

// pathMTUDiscoverer returns the MTU discoverer of a path.
func (c *Conn) pathMTUDiscoverer(path *mpPath) *mtuFinder {
	if path.id == 0 {
		if !c.handshakeConfirmed {
			return nil
		}
		return c.mtuDiscoverer
	}
	return path.mtuDiscoverer
}

// pathMaxPacketSize returns the maximum size of packets sent on a path.
func (c *Conn) pathMaxPacketSize(path *mpPath) protocol.ByteCount {
	if path.id == 0 {
		return c.maxPacketSize()
	}
	if path.mtuDiscoverer != nil {
		return path.mtuDiscoverer.CurrentSize()
	}
	return protocol.ByteCount(c.config.InitialPacketSize)
}

// maybeUpdatePathMTU is called when an ACK or PATH_ACK frame for a path was received.
// If one of the acknowledged packets was an MTU probe packet, this might have increased the path's MTU.
func (c *Conn) maybeUpdatePathMTU(path *mpPath) {
	d := c.pathMTUDiscoverer(path)
	if d == nil {
		return
	}
	mtu := d.CurrentSize()
	if mtu <= path.maxDatagramSize {
		return
	}
	path.maxDatagramSize = mtu
	c.sentPacketHandler.SetMaxDatagramSizeForPath(path.id, mtu)
	c.updateMaxPayloadSizeEstimate()
}

// updateMaxPayloadSizeEstimate updates the estimate of the maximum payload size of a packet.
// DATAGRAM frames can be sent on any path, so the smallest MTU of all active paths is used
// (section 5.8 of draft-ietf-quic-multipath-21).
func (c *Conn) updateMaxPayloadSizeEstimate() {
	var mtu protocol.ByteCount
	for _, id := range c.mp.pathIDs {
		path := c.mp.paths[id]
		if !path.usable() {
			continue
		}
		if size := c.pathMaxPacketSize(path); mtu == 0 || size < mtu {
			mtu = size
		}
	}
	if mtu > 0 {
		c.maxPayloadSizeEstimate.Store(uint32(estimateMaxPayloadSize(mtu)))
	}
}

func (c *Conn) hasReceivedPackets() bool {
	c.receivedPacketMx.Lock()
	defer c.receivedPacketMx.Unlock()

	return !c.receivedPackets.Empty()
}
