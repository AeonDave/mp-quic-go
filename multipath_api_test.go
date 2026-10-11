package quic

import (
	"bytes"
	"context"
	"errors"
	"io"
	"maps"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/wire"
	"github.com/AeonDave/mp-quic-go/qlog"
	"github.com/AeonDave/mp-quic-go/testutils/events"
	"github.com/AeonDave/mp-quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
)

// useTestController makes a Config use the controller (instead of a controller created by a factory).
func useTestController(ctrl MultipathController) func(*Config) {
	return func(c *Config) {
		c.MultipathControllerFactory = nil
		c.MultipathController = ctrl
	}
}

// A selectingTestController records the paths passed to SelectPath, and selects the path that selectPath returns.
type selectingTestController struct {
	mx         sync.Mutex
	selectPath func([]PathInfo) PathID
	contexts   [][]PathInfo
}

func (c *selectingTestController) SelectPath(ctx PathSelectionContext) (PathInfo, bool) {
	c.mx.Lock()
	defer c.mx.Unlock()

	c.contexts = append(c.contexts, slices.Clone(ctx.Paths))
	return PathInfo{ID: c.selectPath(ctx.Paths)}, true
}

func (c *selectingTestController) setSelectPath(f func([]PathInfo) PathID) {
	c.mx.Lock()
	defer c.mx.Unlock()

	c.selectPath = f
}

func (c *selectingTestController) getContexts() [][]PathInfo {
	c.mx.Lock()
	defer c.mx.Unlock()

	return slices.Clone(c.contexts)
}

// The multipath controller selects the path for packets carrying data among the paths in the PathSelectionContext:
// the active paths that can send. If it selects a path that is not one of them, the connection selects the path itself.
func TestMultipathControllerSelectsPath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
		c := tc.conn
		ctrl := &selectingTestController{selectPath: func([]PathInfo) PathID { return 1 }}
		c.multipathController = ctrl
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		pathConn := newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{})
		p := tc.newTestPath(pathConn)
		tc.openTestPath(t, p)

		numContexts := len(ctrl.getContexts())
		paths, _ := tc.sendTestDataPackets(t, 6)
		requireOnlyPath(t, paths, 1)
		contexts := ctrl.getContexts()[numContexts:]
		require.NotEmpty(t, contexts)
		for _, ctxPaths := range contexts {
			require.Len(t, ctxPaths, 2)
			require.Equal(t, PathID(0), ctxPaths[0].ID)
			require.Equal(t, PathID(1), ctxPaths[1].ID)
			for _, path := range ctxPaths {
				require.Equal(t, PathStateActive, path.State)
				require.Equal(t, tc.remoteAddr, path.RemoteAddr)
			}
		}

		// the controller selects a path that doesn't exist: the connection uses both paths
		ctrl.setSelectPath(func([]PathInfo) PathID { return 42 })
		paths, _ = tc.sendTestDataPackets(t, 6)
		require.Contains(t, paths, protocol.PathID(0))
		require.Contains(t, paths, protocol.PathID(1))

		// The peer marks path 1 as a backup path. It is not passed to the controller anymore.
		require.NoError(t, handleTestFrame(t, c, &wire.PathStatusFrame{PathID: 1, SequenceNumber: 0, Backup: true}, protocol.Encryption1RTT))
		ctrl.setSelectPath(func([]PathInfo) PathID { return 1 })
		numContexts = len(ctrl.getContexts())
		paths, _ = tc.sendTestDataPackets(t, 6)
		requireOnlyPath(t, paths, 0)
		for _, ctxPaths := range ctrl.getContexts()[numContexts:] {
			require.Len(t, ctxPaths, 1)
			require.Equal(t, PathID(0), ctxPaths[0].ID)
		}

		// The path is passed to the controller once path 0 can't be used anymore.
		require.NoError(t, handleTestFrame(t, c, &wire.PathAbandonFrame{PathID: 0}, protocol.Encryption1RTT))
		numContexts = len(ctrl.getContexts())
		paths, _ = tc.sendTestDataPackets(t, 6)
		requireOnlyPath(t, paths, 1)
		ctxPaths := ctrl.getContexts()[numContexts]
		require.Len(t, ctxPaths, 1)
		require.Equal(t, PathID(1), ctxPaths[0].ID)
		require.Equal(t, PathStatusBackup, ctxPaths[0].PeerStatus)
		require.Equal(t, PathStatusUnknown, ctxPaths[0].Status)
	})
}

// A notificationTestController records the notifications it receives about the paths.
type notificationTestController struct {
	mx         sync.Mutex
	enabled    int
	registered []PathInfo
	validated  []PathID
	removed    []PathID
	failed     map[PathID][]bool // the PotentiallyFailed updates
	rtt        map[PathID]time.Duration
	sent       map[PathID]int
	acked      map[PathID]int
	lost       map[PathID]int
}

func newNotificationTestController() *notificationTestController {
	return &notificationTestController{
		failed: make(map[PathID][]bool),
		rtt:    make(map[PathID]time.Duration),
		sent:   make(map[PathID]int),
		acked:  make(map[PathID]int),
		lost:   make(map[PathID]int),
	}
}

func (c *notificationTestController) SelectPath(PathSelectionContext) (PathInfo, bool) {
	return PathInfo{}, false
}

func (c *notificationTestController) EnableMultipath() {
	c.mx.Lock()
	defer c.mx.Unlock()
	c.enabled++
}

func (c *notificationTestController) RegisterPath(info PathInfo) {
	c.mx.Lock()
	defer c.mx.Unlock()
	c.registered = append(c.registered, info)
}

func (c *notificationTestController) ValidatePath(id PathID) {
	c.mx.Lock()
	defer c.mx.Unlock()
	c.validated = append(c.validated, id)
}

func (c *notificationTestController) RemovePath(id PathID) {
	c.mx.Lock()
	defer c.mx.Unlock()
	c.removed = append(c.removed, id)
}

func (c *notificationTestController) UpdatePathState(id PathID, update PathStateUpdate) {
	c.mx.Lock()
	defer c.mx.Unlock()
	if update.PotentiallyFailed != nil {
		c.failed[id] = append(c.failed[id], *update.PotentiallyFailed)
	}
	if update.SmoothedRTT != nil {
		c.rtt[id] = *update.SmoothedRTT
	}
}

func (c *notificationTestController) OnPacketSent(id PathID, _ ByteCount) {
	c.mx.Lock()
	defer c.mx.Unlock()
	c.sent[id]++
}

func (c *notificationTestController) OnPacketAcked(id PathID) {
	c.mx.Lock()
	defer c.mx.Unlock()
	c.acked[id]++
}

func (c *notificationTestController) OnPacketLost(id PathID) {
	c.mx.Lock()
	defer c.mx.Unlock()
	c.lost[id]++
}

func (c *notificationTestController) getFailed(id PathID) []bool {
	c.mx.Lock()
	defer c.mx.Unlock()
	return slices.Clone(c.failed[id])
}

// The connection informs the multipath controller about the paths: when IETF Multipath QUIC becomes active,
// when a path becomes active, when it is abandoned, and about the packets sent, acknowledged and lost.
func TestMultipathControllerNotifications(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctrl := newNotificationTestController()
		p := newMultipathPathTestPair(t, multipathPathTestOpts{clientConf: useTestController(ctrl)})
		ctrl.mx.Lock()
		require.Equal(t, 1, ctrl.enabled)
		require.Len(t, ctrl.registered, 1)
		require.Equal(t, PathID(0), ctrl.registered[0].ID)
		require.Equal(t, PathStateActive, ctrl.registered[0].State)
		require.Equal(t, multipathTestServerAddr.String(), ctrl.registered[0].RemoteAddr.String())
		require.Equal(t, []PathID{0}, ctrl.validated)
		ctrl.mx.Unlock()

		path := p.openPath(t)
		// every 5th packet sent on path 1 is lost
		var count int
		p.router.SetDrop(func(pkt simnet.Packet) bool {
			if !sameAddr(pkt.From, multipathTestClientAddr2) {
				return false
			}
			count++
			return count%5 == 0
		})
		p.transfer(t, randomData(1<<20))
		p.router.SetDrop(nil)
		require.NoError(t, path.Close())
		// the server receives the PATH_ABANDON frame
		time.Sleep(100 * time.Millisecond)
		p.close(t)

		ctrl.mx.Lock()
		defer ctrl.mx.Unlock()
		require.Equal(t, 1, ctrl.enabled)
		require.Len(t, ctrl.registered, 2)
		require.Equal(t, PathID(1), ctrl.registered[1].ID)
		require.Equal(t, PathStateActive, ctrl.registered[1].State)
		require.Equal(t, multipathTestClientAddr2.String(), ctrl.registered[1].LocalAddr.String())
		require.Equal(t, multipathTestServerAddr.String(), ctrl.registered[1].RemoteAddr.String())
		require.Equal(t, []PathID{0, 1}, ctrl.validated)
		require.Equal(t, []PathID{1}, ctrl.removed)
		for _, id := range []PathID{0, 1} {
			require.NotZero(t, ctrl.sent[id], "path %d", id)
			require.NotZero(t, ctrl.acked[id], "path %d", id)
			require.NotZero(t, ctrl.rtt[id], "path %d", id)
		}
		require.NotZero(t, ctrl.lost[1])
	})
}

// The connection detects paths that potentially failed, also when only STREAM frames are sent on them.
// The data in flight on a failed path is retransmitted on the other path, otherwise the transfer would stall:
// no acknowledgments are received for the failed path (section 5.7 of draft-ietf-quic-multipath-21).
// The controller is informed when the path potentially failed, and when it recovered.
func TestMultipathPotentiallyFailedPathEndToEnd(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctrl := newNotificationTestController()
		p := newMultipathPathTestPair(t, multipathPathTestOpts{clientConf: useTestController(ctrl)})
		p.openPath(t)
		p.transfer(t, randomData(100<<10))
		require.Empty(t, ctrl.getFailed(1))

		// all packets sent on path 1 are lost
		p.router.SetDrop(func(pkt simnet.Packet) bool { return sameAddr(pkt.From, multipathTestClientAddr2) })
		p.transfer(t, randomData(500<<10))
		time.Sleep(time.Second)
		synctest.Wait()
		require.Equal(t, []bool{true}, ctrl.getFailed(1))
		require.Empty(t, ctrl.getFailed(0))

		// path 1 works again: the PTO probe packets sent on path 1 are acknowledged
		p.router.SetDrop(nil)
		time.Sleep(5 * time.Second)
		synctest.Wait()
		require.Equal(t, []bool{true, false}, ctrl.getFailed(1))
		p.close(t)
	})
}

// The only path fails while data is in flight: its data can't be retransmitted on another path yet.
// When another path is validated afterwards, the data is retransmitted on that path, and the transfer completes.
func TestMultipathFailedPathDataMovesToNewPath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctrl := newNotificationTestController()
		p := newMultipathPathTestPair(t, multipathPathTestOpts{clientConf: useTestController(ctrl)})
		data := randomData(300 << 10)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		serverDone := make(chan error, 1)
		go func() {
			str, err := p.server.AcceptStream(ctx)
			if err != nil {
				serverDone <- err
				return
			}
			received, err := io.ReadAll(str)
			if err == nil && !bytes.Equal(data, received) {
				err = errors.New("received unexpected data")
			}
			serverDone <- err
		}()
		go func() {
			str, err := p.client.OpenStreamSync(ctx)
			if err != nil {
				return
			}
			if _, err := str.Write(data); err != nil {
				return
			}
			str.Close()
		}()

		// path 0 stops working while data is in flight
		time.Sleep(25 * time.Millisecond)
		p.router.SetDrop(func(pkt simnet.Packet) bool { return sameAddr(pkt.From, multipathTestClientAddr) })
		time.Sleep(2 * time.Second)
		synctest.Wait()
		require.Equal(t, []bool{true}, ctrl.getFailed(0))

		// a new path is opened
		path, err := p.client.AddPath(p.clientTr2)
		require.NoError(t, err)
		require.NoError(t, path.Probe(ctx))
		select {
		case err := <-serverDone:
			require.NoError(t, err)
		case <-ctx.Done():
			t.Fatal("transfer stalled")
		}
		require.Equal(t, []bool{true}, ctrl.getFailed(0))
		p.close(t)
	})
}

// A controller configured in the Config is used by one connection at a time.
// When it's in use, the built-in controllers are cloned for other connections.
// The connections use IETF Multipath QUIC, and every controller learns about the paths of its connection only.
func TestMultipathControllerClaimedAndCloned(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		serverCtrl := NewDefaultMultipathController(NewMinRTTScheduler(0.3))
		p := newMultipathPathTestPair(t, multipathPathTestOpts{serverConf: useTestController(serverCtrl)})
		require.Same(t, serverCtrl, p.server.MultipathController())

		// a second connection, from the client's other address
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var client2Events events.Recorder
		client2, err := p.clientTr2.Dial(ctx, multipathTestServerAddr, generateTLSConfigWithServerName("localhost"), multipathTestConfig(true, protocol.PerspectiveClient, &client2Events))
		require.NoError(t, err)
		defer client2.CloseWithError(0, "")
		server2, err := p.ln.Accept(ctx)
		require.NoError(t, err)
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()

		clone, ok := server2.MultipathController().(*DefaultMultipathController)
		require.True(t, ok)
		require.NotSame(t, serverCtrl, clone)
		require.Equal(t, 0.3, clone.scheduler.(*MinRTTScheduler).rttBias)
		require.NotNil(t, p.server.mp)
		require.NotNil(t, server2.mp)
		// each connection registered its path 0 with its own controller
		require.Contains(t, serverCtrl.GetStatistics(), PathID(0))
		require.Contains(t, clone.GetStatistics(), PathID(0))

		// both connections work, and only inform their own controller about the packets sent
		cloneSent := clone.GetStatistics()[0].PacketsSent
		serverSent := serverCtrl.GetStatistics()[0].PacketsSent
		p.transfer(t, randomData(10<<10))
		require.Greater(t, serverCtrl.GetStatistics()[0].PacketsSent, serverSent)
		require.Equal(t, cloneSent, clone.GetStatistics()[0].PacketsSent)
		p2 := &multipathTestConnPair{client: client2, server: server2}
		p2.transfer(t, randomData(10<<10))
		require.Greater(t, clone.GetStatistics()[0].PacketsSent, cloneSent)
		p2.close(t)
		p.close(t)
	})
}

// Conn.Paths returns the paths of IETF Multipath QUIC, Path.ID returns the path ID once the path was opened.
func TestMultipathConnPaths(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newMultipathPathTestPair(t, multipathPathTestOpts{
			clientConf: func(c *Config) { c.MaxPaths = 2 },
		})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		paths := p.client.Paths()
		require.Len(t, paths, 1)
		require.Equal(t, PathID(0), paths[0].ID)
		require.Equal(t, PathStateActive, paths[0].State)
		require.Equal(t, multipathTestServerAddr.String(), paths[0].RemoteAddr.String())
		require.Len(t, p.server.Paths(), 1)

		path, err := p.client.AddPath(p.clientTr2)
		require.NoError(t, err)
		_, ok := path.ID()
		require.False(t, ok)
		require.NoError(t, path.SetStatus(PathStatusBackup))
		require.NoError(t, path.Probe(ctx))
		id, ok := path.ID()
		require.True(t, ok)
		require.Equal(t, PathID(1), id)
		// the path is listed as active once Probe returned
		paths = p.client.Paths()
		require.Len(t, paths, 2)
		require.Equal(t, PathStateActive, paths[1].State)
		time.Sleep(time.Second)
		synctest.Wait()

		paths = p.client.Paths()
		require.Len(t, paths, 2)
		require.Equal(t, PathID(1), paths[1].ID)
		require.Equal(t, PathStateActive, paths[1].State)
		require.Equal(t, PathStatusBackup, paths[1].Status)
		require.Equal(t, PathStatusUnknown, paths[1].PeerStatus)
		require.Equal(t, multipathTestClientAddr2.String(), paths[1].LocalAddr.String())
		paths = p.server.Paths()
		require.Len(t, paths, 2)
		require.Equal(t, PathStateActive, paths[1].State)
		require.Equal(t, PathStatusUnknown, paths[1].Status)
		require.Equal(t, PathStatusBackup, paths[1].PeerStatus)
		require.Equal(t, multipathTestClientAddr2.String(), paths[1].RemoteAddr.String())

		// The client can only use 2 path IDs at the same time.
		path2, err := p.client.AddPathFromAddr(nil, nil)
		require.NoError(t, err)
		require.ErrorIs(t, path2.Probe(ctx), ErrTooManyPaths)
		_, ok = path2.ID()
		require.False(t, ok)

		require.NoError(t, path.Close())
		paths = p.client.Paths()
		require.Len(t, paths, 2)
		require.Equal(t, PathStateAbandoned, paths[1].State)
		// the path is closed 3 PTOs later
		time.Sleep(time.Second)
		synctest.Wait()
		require.Len(t, p.client.Paths(), 1)
		p.close(t)
	})
}

// Conn.SetPathStatus sets the status of paths that the application didn't open using AddPath, e.g. path 0.
// The server can set the status of the paths opened by the client.
func TestMultipathConnSetPathStatus(t *testing.T) {
	t.Run("without multipath", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			p := newMultipathTestConnPair(t, true, false)
			require.EqualError(t, p.client.SetPathStatus(0, PathStatusBackup), "IETF Multipath QUIC is not used")
			require.EqualError(t, p.server.SetPathStatus(0, PathStatusBackup), "IETF Multipath QUIC is not used")
			p.close(t)
		})
	})

	t.Run("path 0 and the server", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			p := newMultipathPathTestPair(t, multipathPathTestOpts{})
			require.EqualError(t, p.client.SetPathStatus(0, PathStatus(42)), "invalid path status: PathStatus(42)")
			require.ErrorIs(t, p.client.SetPathStatus(1, PathStatusBackup), ErrPathClosed)
			require.ErrorIs(t, p.server.SetPathStatus(1, PathStatusBackup), ErrPathClosed)
			p.openPath(t)
			time.Sleep(time.Second)
			synctest.Wait()

			require.NoError(t, p.client.SetPathStatus(0, PathStatusBackup))
			require.NoError(t, p.server.SetPathStatus(1, PathStatusBackup))
			time.Sleep(time.Second)
			synctest.Wait()
			clientPaths := p.client.Paths()
			require.Len(t, clientPaths, 2)
			require.Equal(t, PathStatusBackup, clientPaths[0].Status)
			require.Equal(t, PathStatusUnknown, clientPaths[0].PeerStatus)
			require.Equal(t, PathStatusBackup, clientPaths[1].PeerStatus)
			serverPaths := p.server.Paths()
			require.Len(t, serverPaths, 2)
			require.Equal(t, PathStatusBackup, serverPaths[0].PeerStatus)
			require.Equal(t, PathStatusBackup, serverPaths[1].Status)

			require.NoError(t, p.server.SetPathStatus(1, PathStatusAvailable))
			time.Sleep(time.Second)
			synctest.Wait()
			require.Equal(t, PathStatusAvailable, p.client.Paths()[1].PeerStatus)
			p.transfer(t, randomData(10<<10))
			p.close(t)

			statusFrames, _ := sentFrames[*qlog.PathStatusFrame](p.clientEvents)
			require.Equal(t, []*qlog.PathStatusFrame{{PathID: 0, SequenceNumber: 0, Backup: true}}, statusFrames)
			statusFrames, _ = sentFrames[*qlog.PathStatusFrame](p.serverEvents)
			require.Equal(t, []*qlog.PathStatusFrame{
				{PathID: 1, SequenceNumber: 0, Backup: true},
				{PathID: 1, SequenceNumber: 1},
			}, statusFrames)
		})
	})
}

// Without IETF Multipath QUIC, Conn.Paths returns nil.
func TestMultipathConnPathsWithoutMultipath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newMultipathTestConnPair(t, false, false)
		p.transfer(t, []byte("foobar"))
		require.Nil(t, p.client.Paths())
		require.Nil(t, p.server.Paths())
		path, err := p.client.AddPath(p.clientTr)
		require.NoError(t, err)
		_, ok := path.ID()
		require.False(t, ok)
		p.close(t)
	})
}

// Path.Switch makes a path the preferred path: data is only sent on this path, as long as it can be used.
// LocalAddr and RemoteAddr refer to this path.
func TestMultipathSwitchPath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newMultipathPathTestPair(t, multipathPathTestOpts{})
		path := p.openPath(t)
		require.NoError(t, path.Switch())
		start := len(p.clientEvents.Events(qlog.PacketSent{}))
		p.transfer(t, randomData(500<<10))
		require.Equal(t, multipathTestClientAddr2.String(), p.client.LocalAddr().String())
		require.Equal(t, multipathTestServerAddr.String(), p.client.RemoteAddr().String())
		for _, ev := range p.clientEvents.Events(qlog.PacketSent{})[start:] {
			ps := ev.(qlog.PacketSent)
			if hasFrame[*qlog.StreamFrame](ps) {
				require.Equal(t, protocol.PathID(1), ps.Header.PathID)
			}
		}

		// once the path is closed, data is sent on path 0
		require.NoError(t, path.Close())
		require.ErrorIs(t, path.Switch(), ErrPathClosed)
		start = len(p.clientEvents.Events(qlog.PacketSent{}))
		p.transfer(t, randomData(100<<10))
		require.Equal(t, multipathTestClientAddr.String(), p.client.LocalAddr().String())
		var onPath0 int
		for _, ev := range p.clientEvents.Events(qlog.PacketSent{})[start:] {
			ps := ev.(qlog.PacketSent)
			if hasFrame[*qlog.StreamFrame](ps) {
				require.Equal(t, protocol.PathID(0), ps.Header.PathID)
				onPath0++
			}
		}
		require.NotZero(t, onPath0)
		p.close(t)
	})
}

func registeredOLIAPaths(s *oliaSharedState) []protocol.PathID {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := slices.Collect(maps.Keys(s.paths))
	slices.Sort(ids)
	return ids
}

// With MultipathCongestionControlOLIA, every path has its own OLIA congestion controller,
// coupled to the controllers of the other paths of the connection.
// The controller of a path is removed from the shared state when the path is abandoned.
func TestMultipathOLIA(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newMultipathPathTestPair(t, multipathPathTestOpts{
			clientConf: func(c *Config) { c.MultipathCongestionControl = MultipathCongestionControlOLIA },
		})
		require.Nil(t, p.server.mp.olia)
		olia := p.client.mp.olia
		require.NotNil(t, olia)
		require.Equal(t, []protocol.PathID{0}, registeredOLIAPaths(olia))
		path := p.openPath(t)
		require.Equal(t, []protocol.PathID{0, 1}, registeredOLIAPaths(olia))
		p.transfer(t, randomData(500<<10))
		require.NoError(t, path.Close())
		require.Equal(t, []protocol.PathID{0}, registeredOLIAPaths(olia))
		p.transfer(t, randomData(100<<10))
		p.close(t)
	})
}
