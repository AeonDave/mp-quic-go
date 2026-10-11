# Loss recovery and congestion control in mp-quic-go

mp-quic-go detects losses and controls congestion as described in
[RFC 9002](https://datatracker.ietf.org/doc/html/rfc9002), using the code of quic-go. This document describes what
mp-quic-go adds to it. With IETF Multipath QUIC, every path runs its own loss recovery and congestion control (see
[MP_QUIC_README.md](MP_QUIC_README.md)).

## Persistent congestion

quic-go doesn't implement persistent congestion (section 7.6 of RFC 9002). mp-quic-go does: when persistent
congestion is established, the congestion window drops to the minimum window (2 maximum datagram sizes), and slow
start begins again.

Persistent congestion is established when an acknowledgment, or the loss timer it set, declares two ack-eliciting
packets lost, and

- no packet sent between them was acknowledged,
- the time between their send times exceeds the persistent congestion duration
  `(smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay) * 3`, which includes `max_ack_delay` in all packet
  number spaces, and
- both were sent after the first RTT sample.

Details:

- As in the pseudocode of Appendix B.8 of RFC 9002, the packets declared lost together are compared.
- Path MTU probe packets don't count: they are lost because of their size, and their loss doesn't reduce the
  congestion window either. A lost Path MTU probe packet sent between two lost packets doesn't prevent persistent
  congestion.
- Packets that probe a new path (PATH_CHALLENGE) are sent to another address. They are ignored: they neither count
  as lost packets nor as acknowledged packets.
- When a PTO expires, quic-go retransmits the frames of the oldest outstanding packet in the probe packet, and removes
  that packet from the bytes in flight. mp-quic-go keeps the packet in the sent packet history until it is
  acknowledged or declared lost, so that it counts for persistent congestion. The frames are not declared lost again,
  and the loss doesn't change the congestion window by itself.
- The first RTT sample is the first RTT measurement after the handshake started, or after a migration reset the RTT
  estimate. An RTT estimate derived from a Retry packet is not an RTT sample.
- The NewReno and Cubic controllers keep the slow start threshold and the recovery period of the congestion event
  caused by the same losses. The pseudocode of RFC 9002 ends the recovery period, so that another loss of a packet
  sent before persistent congestion was established starts a new recovery period, and sets the slow start threshold
  to the minimum window. Cubic also starts a new epoch, as after a retransmission timeout (section 4.8 of RFC 9438).
- The OLIA controller reacts in the same way, and the other paths of the connection see the new window.
- qlog: the event `recovery:congestion_state_updated` with the trigger `persistent_congestion` is logged
  (`qlog.CongestionStateTriggerPersistentCongestion`).

With IETF Multipath QUIC, persistent congestion is established for each path on its own: only the packets sent on
the path, and only the path's RTT estimate and first RTT sample, are taken into account, and only the path's
congestion controller reduces its window. Packets sent on the other paths, and their acknowledgments, travel on
other network paths and don't tell anything about the congestion of this one.

## Decisions for SHOULD and MAY statements

| Statement (RFC 9002) | Decision | Reason |
|---|---|---|
| kPersistentCongestionThreshold: the RECOMMENDED value is 3 (section 7.6.1) | Followed | |
| The persistent congestion period SHOULD NOT start until there is at least one RTT sample (section 7.6.2) | Followed, per path | |
| Persistent congestion SHOULD consider packets sent across packet number spaces (section 7.6.2) | Not followed: only the acknowledged packet number space is considered, as the RFC allows (MAY) | Loss detection works on one packet number space at a time. Considering only one space can establish persistent congestion when an acknowledged packet of another space was sent in between, but it never fails to establish it (section 7.6.2). Initial and Handshake packets are only sent at the start of a connection |
