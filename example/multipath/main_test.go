package main

import (
	"context"
	"testing"
	"time"

	quic "github.com/AeonDave/mp-quic-go"

	"github.com/stretchr/testify/require"
)

// The client closes the connection before it closes the Transport of the second path.
// Closing that Transport destroys the connection without sending a CONNECTION_CLOSE frame,
// and the server's connection would only be closed by the idle timeout.
func TestClientClosesConnection(t *testing.T) {
	ln, err := quic.ListenAddr("127.0.0.1:0", generateTLSConfig(), &quic.Config{
		MultipathControllerFactory: func() quic.MultipathController {
			return quic.NewDefaultMultipathController(quic.NewRoundRobinScheduler())
		},
	})
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connChan := make(chan *quic.Conn, 1)
	go func() {
		conn, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		connChan <- conn
		serveConn(conn)
	}()
	require.NoError(t, runClient(ctx, ln.Addr(), 100<<10))

	var conn *quic.Conn
	select {
	case conn = <-connChan:
	case <-ctx.Done():
		t.Fatal("timeout")
	}
	select {
	case <-conn.Context().Done():
	case <-ctx.Done():
		t.Fatal("the server's connection wasn't closed")
	}
	var appErr *quic.ApplicationError
	require.ErrorAs(t, context.Cause(conn.Context()), &appErr)
	require.True(t, appErr.Remote)
	require.Zero(t, appErr.ErrorCode)
}
