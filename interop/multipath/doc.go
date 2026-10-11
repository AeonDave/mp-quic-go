// Package multipath contains interoperability tests of IETF Multipath QUIC (draft-ietf-quic-multipath-21)
// with picoquic. The tests run picoquicdemo in a Docker container. They are only built with the picoquic build tag:
//
//	go test -tags picoquic -count=1 ./interop/multipath/...
//
// See README.md for details.
package multipath
