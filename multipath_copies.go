package quic

import (
	"slices"

	"github.com/AeonDave/mp-quic-go/internal/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/wire"
)

// With IETF Multipath QUIC, frames can be sent on several paths:
//   - MultipathDuplicationPolicy: after a packet was sent on a path, copies of the selected frames
//     (STREAM frames of the selected streams, CRYPTO and RESET_STREAM frames) are sent on other paths,
//   - MultipathReinjectionPolicy.SetReinjectOnPTO: when the probe timeout of a path expires, copies of the frames of the
//     packets outstanding on that path are sent on another path (section 5.7 of draft-ietf-quic-multipath-21).
//
// Every path has its own packet number space, so the copies are sent in separate packets.
// These packets are congestion controlled on the path they are sent on, but the copies don't have handlers:
// they are never retransmitted. The original frames are retransmitted if the packets they were sent in are lost.
// The receiver discards the data it receives twice.
// Copies of STREAM and STREAM_DATA_BLOCKED frames are not sent after the stream was reset (section 3.3 of RFC 9000),
// except for the data below the reliable size of a RESET_STREAM_AT frame.

// A streamFrameResendLimiter is a handler of STREAM frames that knows how much of the data of a frame
// may still be sent (see sendStreamAckHandler).
type streamFrameResendLimiter interface {
	resendLimit(*wire.StreamFrame) (end protocol.ByteCount, ok bool)
}

// copyStreamFrame returns a copy of a STREAM frame that is sent on another path.
// It returns nil if the frame must not be sent anymore. The copy only contains the data that may still be sent.
func copyStreamFrame(f ackhandler.StreamFrame) *wire.StreamFrame {
	end := f.Frame.Offset + f.Frame.DataLen()
	if limiter, ok := f.Handler.(streamFrameResendLimiter); ok {
		limit, ok := limiter.resendLimit(f.Frame)
		if !ok {
			return nil
		}
		end = min(end, limit)
	}
	return &wire.StreamFrame{
		StreamID:       f.Frame.StreamID,
		Offset:         f.Frame.Offset,
		Data:           slices.Clone(f.Frame.Data[:end-f.Frame.Offset]),
		Fin:            f.Frame.Fin && end == f.Frame.Offset+f.Frame.DataLen(),
		DataLenPresent: true,
	}
}

// copyControlFrame returns a copy of a frame other than a STREAM frame that is sent on another path.
// It returns nil for frames that are not copied, and for frames that must not be sent anymore.
func (c *Conn) copyControlFrame(f wire.Frame) wire.Frame {
	if f, ok := f.(*wire.StreamDataBlockedFrame); ok {
		if str := c.streamsMap.existingSendStream(f.StreamID); str == nil || !str.mayReportBlocked() {
			return nil
		}
	}
	return copyFrame(f)
}

// copyFrame returns a copy of a frame other than a STREAM frame that is sent on another path.
// It returns nil for frames that are not copied.
func copyFrame(f wire.Frame) wire.Frame {
	switch f := f.(type) {
	case *wire.CryptoFrame:
		return &wire.CryptoFrame{Offset: f.Offset, Data: slices.Clone(f.Data)}
	case *wire.ResetStreamFrame:
		c := *f
		return &c
	case *wire.MaxDataFrame:
		c := *f
		return &c
	case *wire.MaxStreamDataFrame:
		c := *f
		return &c
	case *wire.MaxStreamsFrame:
		c := *f
		return &c
	case *wire.DataBlockedFrame:
		c := *f
		return &c
	case *wire.StreamDataBlockedFrame:
		c := *f
		return &c
	case *wire.StreamsBlockedFrame:
		c := *f
		return &c
	default:
		return nil
	}
}

// duplicatedFrames returns copies of the frames of a packet that the duplication policy duplicates.
func duplicatedFrames(policy *MultipathDuplicationPolicy, p *shortHeaderPacket) []wire.Frame {
	var frames []wire.Frame
	for _, f := range p.Frames {
		switch f.Frame.(type) {
		case *wire.CryptoFrame:
			if !policy.ShouldDuplicateCrypto() {
				continue
			}
		case *wire.ResetStreamFrame:
			if !policy.ShouldDuplicateReset() {
				continue
			}
		default:
			continue
		}
		frames = append(frames, copyFrame(f.Frame))
	}
	for _, f := range p.StreamFrames {
		if f.Frame != nil && policy.ShouldDuplicateStream(f.Frame.StreamID) {
			if cf := copyStreamFrame(f); cf != nil {
				frames = append(frames, cf)
			}
		}
	}
	return frames
}

// maybeDuplicateFrames sends copies of the frames of a packet sent on a path on other paths,
// as selected by the duplication policy. The copies are sent on up to MultipathDuplicationPolicy.GetDuplicatePathCount
// minus 1 of the other paths that data is sent on, in ascending order of their path IDs,
// if their congestion controller allows sending.
func (c *Conn) maybeDuplicateFrames(p *shortHeaderPacket, sentOn *mpPath, now monotime.Time) {
	policy := c.multipathDuplicationPolicy
	if policy == nil || !policy.IsEnabled() || p.IsPathProbePacket || p.IsPathMTUProbePacket {
		return
	}
	n := policy.GetDuplicatePathCount() - 1
	if n <= 0 {
		return
	}
	frames := duplicatedFrames(policy, p)
	if len(frames) == 0 {
		return
	}
	for _, path := range c.multipathCopyTargets(sentOn) {
		if c.sentPacketHandler.SendModeForPath(path.id, now) != ackhandler.SendAny {
			continue
		}
		// Every path gets its own copies: sendFrameCopies might split STREAM frames.
		if frames == nil {
			frames = duplicatedFrames(policy, p)
		}
		c.sendFrameCopies(path, frames, now)
		frames = nil
		if n--; n == 0 {
			return
		}
	}
}

// multipathCopyTargets returns the paths that copies of frames sent on a path can be sent on:
// the other paths that data is sent on (section 3.3 of draft-ietf-quic-multipath-21).
// A preference set by Path.Switch is ignored.
func (c *Conn) multipathCopyTargets(sentOn *mpPath) []*mpPath {
	var usable []*mpPath
	for _, id := range c.mp.pathIDs {
		if path := c.mp.paths[id]; path.usable() {
			usable = append(usable, path)
		}
	}
	paths := c.appendMultipathDataPathsWithoutPreference(nil, usable)
	return slices.DeleteFunc(paths, func(p *mpPath) bool { return p == sentOn })
}

// maybeReinjectOnPTO is called when the probe timeout of a path expired.
// If the reinjection policy says so, copies of the frames of the packets outstanding on the path are sent on another
// path, if that path's congestion controller allows sending (section 5.7 of draft-ietf-quic-multipath-21).
// The other path is selected like the path for lost frames (see selectReinjectionTarget).
// Every packet is reinjected at most MultipathReinjectionPolicy.GetMaxReinjections times.
func (c *Conn) maybeReinjectOnPTO(path *mpPath, now monotime.Time) {
	m := c.multipathReinjectionManager
	if m == nil || !m.policy.ReinjectsOnPTO() {
		return
	}
	type outstandingPacket struct {
		pn     protocol.PacketNumber
		frames []wire.Frame
	}
	var packets []outstandingPacket
	var copies []ackhandler.Frame
	var outstanding []protocol.PacketNumber
	for ev := range c.sentPacketHandler.OutstandingPackets(path.id) {
		outstanding = append(outstanding, ev.PacketNumber)
		// Frames without a handler are copies themselves, they are not copied again.
		var frames []wire.Frame
		for _, f := range ev.Frames {
			if f.Frame != nil && f.Handler != nil && m.policy.ShouldReinjectFrame(f.Frame) {
				if cf := c.copyControlFrame(f.Frame); cf != nil {
					frames = append(frames, cf)
				}
			}
		}
		for _, f := range ev.StreamFrames {
			if f.Frame != nil && f.Handler != nil && m.policy.ShouldReinjectFrame(f.Frame) {
				if cf := copyStreamFrame(f); cf != nil {
					frames = append(frames, cf)
				}
			}
		}
		if len(frames) == 0 {
			continue
		}
		packets = append(packets, outstandingPacket{pn: ev.PacketNumber, frames: frames})
		for _, f := range frames {
			copies = append(copies, ackhandler.Frame{Frame: f})
		}
	}
	m.forgetPacketsExcept(path.id, outstanding)
	if len(packets) == 0 {
		return
	}
	target := c.selectReinjectionTarget(&PacketReinjectionInfo{
		OriginalPathID:  path.id,
		PacketNumber:    packets[0].pn,
		EncryptionLevel: protocol.Encryption1RTT,
		Frames:          copies,
		LostTime:        now.ToTime(),
		TargetPathID:    protocol.InvalidPathID,
	})
	targetPath, ok := c.mp.paths[target]
	if !ok || target == path.id || !targetPath.usable() || c.sentPacketHandler.SendModeForPath(target, now) != ackhandler.SendAny {
		return
	}
	if ok, _ := m.canReinjectOnPath(target, now.ToTime()); !ok {
		return
	}
	var frames []wire.Frame
	for _, p := range packets {
		if m.reinjectOnPTO(path.id, p.pn, target) {
			frames = append(frames, p.frames...)
		}
	}
	if len(frames) == 0 {
		return
	}
	if c.logger.Debug() {
		c.logger.Debugf("PTO expired on path %d. Reinjecting %d frames on path %d.", path.id, len(frames), target)
	}
	c.sendFrameCopies(targetPath, frames, now)
}

// sendFrameCopies sends copies of frames on a path, in as many packets as needed,
// as long as the path's congestion controller and pacer allow sending.
// STREAM frames are split if they don't fit into a packet, e.g. if the path's MTU is smaller than the MTU of the path
// the original frames were sent on. Other frames that don't fit into a packet are dropped, as are the frames that
// can't be sent because the path is congestion limited.
func (c *Conn) sendFrameCopies(path *mpPath, queue []wire.Frame, now monotime.Time) {
	connID, ok := c.pathDestConnID(path)
	if !ok {
		return
	}
	for len(queue) > 0 {
		if c.sentPacketHandler.SendModeForPath(path.id, now) != ackhandler.SendAny || c.sendQueue.WouldBlock() {
			return
		}
		maxSize := c.pathMaxPacketSize(path)
		maxPayloadLen := maxSize - c.shortHeaderPacketOverhead(path, connID)
		var frames []ackhandler.Frame
		var streamFrames []ackhandler.StreamFrame
		var length protocol.ByteCount
		for len(queue) > 0 {
			f := queue[0]
			l := f.Length(c.version)
			if length+l > maxPayloadLen {
				if sf, ok := f.(*wire.StreamFrame); ok && maxPayloadLen-length >= protocol.MinStreamFrameSize {
					// The remainder of the frame is sent in the next packet.
					if first, _ := sf.MaybeSplitOffFrame(maxPayloadLen-length, c.version); first != nil {
						first.DataLenPresent = true
						streamFrames = append(streamFrames, ackhandler.StreamFrame{Frame: first})
						length += first.Length(c.version)
						break
					}
				}
				if length == 0 {
					// The frame doesn't fit into a packet on this path.
					queue = queue[1:]
					continue
				}
				break
			}
			if sf, ok := f.(*wire.StreamFrame); ok {
				streamFrames = append(streamFrames, ackhandler.StreamFrame{Frame: sf})
			} else {
				frames = append(frames, ackhandler.Frame{Frame: f})
			}
			length += l
			queue = queue[1:]
		}
		if length == 0 {
			continue
		}
		p, buf, err := c.packer.PackPathPacket(path.id, frames, streamFrames, maxSize, c.version)
		if err != nil {
			c.logger.Debugf("Error packing copies of frames on path %d: %s", path.id, err)
			return
		}
		ecn := c.pathECN(path)
		c.logShortHeaderPacket(p, ecn, buf.Len())
		c.mp.sendingCopies = true
		c.registerPackedShortHeaderPacket(p, ecn, now)
		c.mp.sendingCopies = false
		c.sendOnPath(path, buf, 0, ecn)
	}
}
