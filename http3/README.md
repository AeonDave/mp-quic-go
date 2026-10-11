# HTTP/3

[![Documentation](https://img.shields.io/badge/docs-quic--go.net-red?style=flat)](https://quic-go.net/docs/)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/qoke/mp-quic-go/http3)](https://pkg.go.dev/github.com/qoke/mp-quic-go/http3)

This package implements HTTP/3 ([RFC 9114](https://datatracker.ietf.org/doc/html/rfc9114)), including QPACK ([RFC 9204](https://datatracker.ietf.org/doc/html/rfc9204)) and HTTP Datagrams ([RFC 9297](https://datatracker.ietf.org/doc/html/rfc9297)).
It aims to provide feature parity with the standard library's HTTP/1.1 and HTTP/2 implementation.

Detailed documentation can be found on [quic-go.net](https://quic-go.net/docs/).

## Server push and the QPACK dynamic table

Server push is not implemented. A client never sends a MAX_PUSH_ID frame, so a server can't promise any push: a client
closes the connection with H3_ID_ERROR when it receives a PUSH_PROMISE or CANCEL_PUSH frame, and rejects push streams.
A server accepts MAX_PUSH_ID frames, as long as the maximum push ID doesn't decrease, and closes the connection with
H3_ID_ERROR when it receives a CANCEL_PUSH frame, since it never promised a push.

The QPACK dynamic table is not used. Both endpoints advertise a dynamic table capacity of 0, and their encoders only
use the static table. The peer's encoder and decoder streams are read: only Set Dynamic Table Capacity with a
capacity of 0 and Stream Cancellation instructions are accepted, every other instruction is a connection error
(sections 3.2.2, 4.3 and 4.4 of RFC 9204), and closing either stream is a connection error of type
H3_CLOSED_CRITICAL_STREAM (section 4.2).

## SHOULD and MAY statements

| Statement | Decision |
|---|---|
| RFC 9114, section 7.2.4: an endpoint MAY treat duplicate setting identifiers as H3_SETTINGS_ERROR. | Implemented. |
| RFC 9114, section 10.5: endpoints SHOULD limit the resources a peer can consume, and MAY treat suspicious activity as H3_EXCESSIVE_LOAD. | The payload of GOAWAY, CANCEL_PUSH and MAX_PUSH_ID frames is a single variable-length integer. A frame of one of these types with a Length of 0 or more than 8 is rejected right away with H3_FRAME_ERROR (section 7.1), without waiting for the payload. SETTINGS frames longer than 8 KiB and PRIORITY_UPDATE frames longer than 4 KiB are rejected the same way. H3_EXCESSIVE_LOAD is not used. |
| RFC 9114, section 7.2.8: reserved frame types MAY be sent on any stream where frames are allowed. | A frame of a reserved or unknown type on the control stream is ignored, also before the SETTINGS frame. Section 6.2.1 requires SETTINGS to be the first frame, but ignoring unknown frame types (section 9) takes precedence. |
