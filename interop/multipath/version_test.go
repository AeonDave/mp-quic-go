//go:build picoquic

package multipath

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	quic "github.com/AeonDave/mp-quic-go"
	"github.com/AeonDave/mp-quic-go/qlog"
	"github.com/AeonDave/mp-quic-go/testutils/events"

	"github.com/stretchr/testify/require"
)

// negotiatedVersion returns the version of the last version_information event.
func negotiatedVersion(t *testing.T, r *events.Recorder) quic.Version {
	t.Helper()
	evs := r.Events(qlog.VersionInformation{})
	require.NotEmpty(t, evs)
	return evs[len(evs)-1].(qlog.VersionInformation).ChosenVersion
}

// testClientVersions runs our client, configured with the given versions, against picoquicdemo's server.
func testClientVersions(t *testing.T, versions []quic.Version, expected quic.Version) {
	setup(t)
	dir := testDir(t)
	server, addr := startServer(t, dir, false)
	tr := &tracer{dir: filepath.Join(dir, "qlog-mp-quic-go")}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn := dial(ctx, t, newTransport(t, net.IPv4(127, 0, 0, 1)), addr, tr, func(conf *quic.Config) {
		conf.Versions = versions
	})
	require.Equal(t, expected, conn.ConnectionState().Version)
	download(ctx, t, conn, downloadSize)
	require.NoError(t, conn.CloseWithError(0, ""))
	code, err := server.wait(ctx)
	require.NoError(t, err)
	require.Zero(t, code)
	stats := getPathStats(tr.all()[0])
	t.Logf("key updates: %d", stats.keyUpdates)
}

// Our client starts with QUIC version 1 and offers version 2. picoquicdemo's server keeps version 1.
func TestPicoquicServerVersion1OfferingVersion2(t *testing.T) {
	testClientVersions(t, []quic.Version{quic.Version1, quic.Version2}, quic.Version1)
}

// Our client uses QUIC version 2.
func TestPicoquicServerVersion2(t *testing.T) {
	testClientVersions(t, []quic.Version{quic.Version2, quic.Version1}, quic.Version2)
}

// picoquicdemo's client uses QUIC version 2. Our server updates the keys, using the key update label of version 2.
func TestPicoquicClientVersion2(t *testing.T) {
	r := testServer(t, false, "-v", "6b3343cf")
	require.Equal(t, quic.Version2, negotiatedVersion(t, r))
}

// Our server prefers QUIC version 2, but picoquicdemo's client (without -U) only offers version 1.
func TestPicoquicClientVersion1ServerPrefersVersion2(t *testing.T) {
	r := testServerWithConfig(t, false, func(conf *quic.Config) {
		conf.Versions = []quic.Version{quic.Version2, quic.Version1}
	})
	require.Equal(t, quic.Version1, negotiatedVersion(t, r))
}
