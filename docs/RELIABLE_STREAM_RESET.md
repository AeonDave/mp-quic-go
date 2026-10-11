# Stream Resets with Partial Delivery in mp-quic-go

mp-quic-go implements QUIC Stream Resets with Partial Delivery
([draft-ietf-quic-reliable-stream-reset-11](https://datatracker.ietf.org/doc/html/draft-ietf-quic-reliable-stream-reset-11)),
which is in the RFC Editor queue. A stream can be reset with the RESET_STREAM_AT frame, which carries a reliable size:
the data up to this offset is still delivered to the peer.

The extension is enabled with `Config.EnableStreamResetPartialDelivery`. Connections without it are not affected: the
transport parameter isn't sent, RESET_STREAM_AT frames are a FRAME_ENCODING_ERROR, and streams are reset with
RESET_STREAM frames.

```go
str, err := conn.OpenStream()
// ...
str.Write(header)
str.SetReliableBoundary() // the header is delivered, even if the stream is canceled
str.Write(body)
str.CancelWrite(errorCode)
```

`ConnectionState().SupportsStreamResetPartialDelivery` says if the extension was enabled locally and by the peer.
`SetReliableBoundary` has no effect if the peer didn't enable it.

## Code points and negotiation

| | Draft | Value |
|---|---|---|
| `reset_stream_at` transport parameter | draft-09 to draft-11 (permanently registered by IANA) | `0x1d` |
| `reset_stream_at` transport parameter | draft-07 and draft-08 | `0x17f7586d2cb571` |
| `RESET_STREAM_AT` frame | all drafts (permanently registered by IANA) | `0x24` |

The format of the frame and the semantics didn't change between draft-07 and draft-11. An endpoint with the extension
enabled:

1. sends both transport parameters, `0x1d` first, so that peers implementing draft-07 or draft-08 (e.g. picoquic)
   enable the extension as well;
2. uses the extension if the peer sent either one, or both. A non-empty value of either one is a
   TRANSPORT_PARAMETER_ERROR;
3. saves the transport parameter in session tickets as `0x1d`, and accepts tickets saved with either value.

quic-go v0.63.0 negotiates the same way.

## Behavior

- The final size of a RESET_STREAM_AT frame is subject to flow control (section 4). The data below the reliable size
  that wasn't sent yet consumes flow control credit when the stream is canceled. If the peer's limits don't allow
  this, the RESET_STREAM_AT frame is sent after all data up to the reliable size was sent. quic-go v0.63.0 sends the
  frame immediately, which can exceed the peer's limits.
- The data up to the reliable size is retransmitted until it is acknowledged, and so is the RESET_STREAM_AT frame
  (section 5).
- A STOP_SENDING frame received after canceling the stream results in a RESET_STREAM frame with the same error code
  and the same final size as the RESET_STREAM_AT frame (sections 5.2 and 5.4).
- A received RESET_STREAM_AT frame with a reliable size larger than its final size is a FRAME_ENCODING_ERROR, and
  frames exceeding the flow control limits are a FLOW_CONTROL_ERROR (section 4). RESET_STREAM_AT frames in Initial or
  Handshake packets are a PROTOCOL_VIOLATION.
- Received increases of the reliable size are ignored (section 5.2). A change of the final size is a
  FINAL_SIZE_ERROR. A change of the error code in a RESET_STREAM or RESET_STREAM_AT frame after a RESET_STREAM_AT
  frame with a reliable size larger than 0 was received, or in such a frame, is a STREAM_STATE_ERROR (section 5.2).
  A RESET_STREAM_AT frame with a reliable size of 0 can't be told apart from a RESET_STREAM frame, for which RFC 9000
  doesn't require the error code to stay the same.
- With 0-RTT, the server rejects 0-RTT if it disabled the extension since it issued the session ticket, and the client
  closes the connection with a PROTOCOL_VIOLATION if the server accepted 0-RTT but disabled the extension (section 3).

## SHOULD and MAY statements

| Statement (draft-ietf-quic-reliable-stream-reset-11) | Decision | Reason |
|---|---|---|
| Data sent beyond the reliable size SHOULD NOT be retransmitted (section 5) | Followed | |
| An implementation might deliver data beyond the reliable size to the application (section 5) | Not done: `Read` returns the data up to the reliable size, then the stream error | Matches the behavior of RESET_STREAM, which stops the delivery of data |
| A sender resetting a stream without delivering data MAY use RESET_STREAM or RESET_STREAM_AT with a reliable size of 0 (section 5) | RESET_STREAM is sent | Also understood by peers without the extension |
| The initiator MAY send multiple RESET_STREAM_AT frames to reduce the reliable size (section 5.2) | Not supported by the API: `CancelWrite` only has an effect once. The reliable size is reduced to 0 when a STOP_SENDING frame is received | |
| If an endpoint sends RESET_STREAM_AT in response to STOP_SENDING, it SHOULD set the reliable size to 0 (section 5.4) | Followed: a RESET_STREAM frame is sent | |

## Tests and interoperability

- `send_stream_test.go`: sending, retransmissions, the flow control credit of the reliable data, a deferred
  RESET_STREAM_AT frame, and STOP_SENDING frames before and after canceling.
- `receive_stream_test.go`: delivery up to the reliable size, reordered frames, changes of the reliable size, the final
  size and the error code.
- `internal/wire`: the frame, both transport parameter code points, and session tickets.
- `integrationtests/self/reset_stream_at_test.go`: delivery of the reliable data between two endpoints, also when it
  exceeds the receiver's initial stream or connection flow control window.
- `integrationtests/upstream`: quic-go v0.63.0 (sending both code points) and mp-quic-go reset streams with
  RESET_STREAM_AT frames in both roles.
- `interop/multipath` (`TestPicoquic*GreaseQUICBitResetStreamAt`): picoquic only sends the draft-07 code point. The
  extension is negotiated with picoquic in both roles, and picoquic's server accepts a RESET_STREAM_AT frame.
