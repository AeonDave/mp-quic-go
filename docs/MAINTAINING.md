# Maintaining mp-quic-go

This module is a fork of [quic-go](https://github.com/quic-go/quic-go) with the module path
`github.com/qoke/mp-quic-go`. It is maintained independently, and merges quic-go releases from time to time.
This document describes how to do that.

## Overview

The upstream history is merged as is: the quic-go commits keep the module path `github.com/quic-go/quic-go`.
A sync therefore consists of two commits:

1. A mechanical commit on top of the quic-go release, which rewrites the module path.
2. A merge of that commit into the development branch, which resolves the conflicts with the changes made
   by this module.

The merge base of a sync is always a quic-go commit with the original module path: the parent of the
mechanical commit of the previous sync. The mechanical commit of the previous sync is the same tree with the
new module path, and it is used as the merge base when resolving conflicts (see below).

| quic-go release | Merge base                              | Mechanical commit | Merge commit |
|-----------------|-----------------------------------------|-------------------|--------------|
| v0.63.0         | 29cb6ff5 (between v0.58.0 and v0.59.0)  | c7972e6a          | 9b74e614     |

Add a row for every sync.

## Files

The following files are maintained by this module, and conflicts are resolved in favor of this module's version
(taking over relevant upstream changes by hand):

- `README.md`, `SECURITY.md`, `CHANGELOG.md`, `docs/` and `FIPS140.md` (which describes the packet protection of
  multipath connections in addition to the text of quic-go)
- the multipath code (`multipath*.go`, `multi_socket_manager.go`, the frames of the multipath and address
  advertisement extensions in `internal/wire`, `example/multipath` and their tests)

The quic-go contribution policy and the quic-go issue and pull request templates describe the processes of the
quic-go project. They are not part of this module, and are removed in the merge when quic-go adds or changes them.
All other files, including `FUZZING.md`, the CI workflows and the fuzzing scripts, are taken from quic-go, with the
module path rewritten. Most of the core files (`connection.go`, `packet_packer.go`, `internal/ackhandler`,
`internal/handshake`, `internal/wire`, ...) are changed by this module; the sections below describe how.

## Multipath changes to the core files

The multipath code keeps the structure of quic-go, so that upstream changes can be applied to it. Without IETF
Multipath QUIC, path 0 is the only path, and the multipath branches are not taken.

### internal/ackhandler

The state that quic-go keeps for the application data packet number space moved into a `pathRecovery`, which exists
once per path. Path 0 is the inline field `appData` of the `sentPacketHandler`; other paths are in `paths` (with
their IDs in ascending order in `pathIDs`). An upstream change to the following fields applies to `appData`, and,
if it concerns 1-RTT packets, to the `pathRecovery` `r` of the path it is about:

| quic-go (`sentPacketHandler`) | mp-quic-go |
|---|---|
| `appDataPackets` | `appData.space`, `r.space` |
| `lostPackets` | `appData.lostPackets`, `r.lostPackets` |
| `congestion` | `appData.congestion`, `r.congestion` |
| `ecnTracker` | `appData.ecnTracker`, `r.ecnTracker` (nil without ECN) |
| `ptoCount`, `ptoMode`, `numProbesToSend` | `appData.ptoCount`, ... (also used for Initial and Handshake), `r.ptoCount`, ... |
| `rttStats` | `h.rttStats`, which is `appData.rttStats`; `r.rttStats` |
| `largestAckedTime` | `h.largestAckedTime` for Initial, Handshake and path 0; `r.largestAckedTime` for other paths |
| `bytesInFlight` | `h.bytesInFlight` is the total of all paths. Congestion controllers get `r.bytesInFlight` (for path 0, this includes Initial and Handshake packets) |
| `bytesSent`, `bytesReceived` | the anti-amplification limit of the handshake; `r.bytesSent` and `r.bytesReceived` for the other paths of a server |

Functions that work on one packet number space take the path:

| quic-go | mp-quic-go |
|---|---|
| `getPacketNumberSpace(encLevel)` | `getPacketNumberSpace(encLevel, pathID)` |
| `detectLostPackets(now, encLevel)` | `detectLostPackets(now, encLevel, pathID)` |
| `detectAndRemoveAckedPackets(ack, encLevel)` | `detectAndRemoveAckedPackets(ack, encLevel, pnSpace)` |
| `detectSpuriousLosses(ack, ackTime)` | `detectSpuriousLosses(ack, ackTime, r)` |
| `getLossTimeAndSpace()` | `getLossTimeAndSpace(r)`, which also returns the path ID |
| `getPTOTimeAndSpace(now)` | `getPTOTimeAndSpace(now, r)`, which also returns the path ID |
| `SentPacket(...)` | `SentPacket(..., pathID, pathAcks...)`: the path, and the PATH_ACK frames contained in the packet |
| `PeekPacketNumber(encLevel)`, `PopPacketNumber(encLevel)` | `PeekPacketNumber(pathID, encLevel)`, `PopPacketNumber(pathID, encLevel)` |

`ReceivedAck` has the signature of quic-go: the acknowledged path is the frame's `PathID` (0 for ACK frames).
Long header packets and single-path connections use path 0.

Additions that only run with IETF Multipath QUIC (`h.multipath`, set by `EnableMultipath`):

- the loss detection timer and send mode of all paths (`multipathLossDetectionTime`, `pathLossDetectionTime`,
  `multipathSendMode`, `pathSendMode`). `lossDetectionTime` and the rest of `SendMode` are quic-go's code for
  single-path connections, with the field mapping above.
- the methods for paths: `AddPath`, `AbandonPath`, `RemovePath`, `SetPathAddressValidated`, the `...ForPath`
  variants of existing methods, `NextProbePath`, `MaxPTO`, `AmplificationBudgetForPath`, `OutstandingPackets`,
  `DeclareOutstandingLost`, `PathCongestionState`, `GetPathRTTStats` and `ECNModeForPath`.
- the packet observer (`PacketObserver`, `PacketEvent`) and the congestion control factory, used by the multipath
  controllers and the OLIA congestion controller.

Other files:

- `packet.go`: `PathID`, the PATH_ACK frames contained in a packet (`AckPathID`, `extraAcks`), `PathAck`,
  `PacketEvent` and `PacketObserver`.
- `received_packet_handler.go`: `appDataPackets` is path 0, `paths` and `pathIDs` hold the trackers of the other
  paths, `closedPaths` the removed paths. `ReceivedPacket`, `GetAckFrame` and `IsPotentiallyDuplicate` take the path
  ID. Additions: `EnableMultipath`, `IgnorePacketsBelowForPath`, `AckDuePaths`, `AbandonPath` and `RemovePath`.
- `received_packet_tracker.go`: an abandoned path acknowledges every packet right away (`Abandon`, `abandoned`), and
  `ackDue`.
- `ecn.go`: `Restart` starts ECN validation again after a path migrated; only the testing packets of the current
  validation count.
- `ack_eliciting.go`: PATH_ACK frames are not ack-eliciting, and frames that implement `AckEliciting() bool` (the raw
  frames of `Conn.QueueRawFrame`) decide themselves.
- The other files (`received_packet_history.go`, `lost_packet_tracker.go`, `packet_number_generator.go`, ...) are
  those of quic-go, except for the changes for persistent congestion (see below).

The tests of quic-go stay, with the path ID 0 added where a signature changed. Most tests added by this module are in
`*_multipath_test.go`; the tests of the additions to `ecn.go` and `ack_eliciting.go`, and of the path probes in
`MigratedPath`, are next to the tests of quic-go.

### Connection migration

`path_manager.go`, the path manager of RFC 9000 connection migration, is quic-go's file, with these changes
(see [CONNECTION_MIGRATION.md](CONNECTION_MIGRATION.md)):

- A PATH_CHALLENGE received on a path that is already known is always answered (RFC 9000, section 8.2.2). quic-go
  applies the limit of `maxPaths` to these paths as well, so it doesn't answer the PATH_CHALLENGE when the limit is
  reached, or evicts another path first. Keep the condition `p == nil` of the limit until quic-go changes this.
- Paths are identified by the local address as well (`path.local`), for the server's preferred address (see below).
  `HandlePacket` and `SwitchToPath` are quic-go's methods, and call `HandlePacketOnLocalAddr` and
  `SwitchToPathOnLocalAddr` with the invalid address. Changes of quic-go to these methods go to the `...OnLocalAddr`
  variants. `HandlePacketOnLocalAddr` also takes the packet info, which is used to send to the path.
- The anti-amplification limit and the second path validation (section 8.2.1): `AddrValidated`,
  `ChallengeNotExpanded`, `PopDueChallenge` and the fields `addrValidated`, `challengeNotExpanded` and `challengeDue`.
  `HandlePathResponseFrame` only validates the path once a PATH_CHALLENGE in a datagram of 1200 bytes was answered.
- The validation of the previous path after a migration (section 9.3.3): `AddPreviousPath`.
- PATH_CHALLENGE retries (section 8.2.1): a path keeps all PATH_CHALLENGE frames sent on it (`pathChallenges`), and a
  packet received on a path that is not validated triggers another one after a PTO, with exponential backoff, up to
  `maxPathChallenges`. `newPathManager` takes a function that returns the PTO. The `tupleManager` (see below) uses
  the same type.

In `connection.go`, the server's part of `handleShortHeaderPacket` answers every PATH_CHALLENGE frame of a packet,
limits the probe packets by the anti-amplification limit (`sendPathProbe`), sends the due PATH_CHALLENGE frames
(`sendDuePathChallenges`, called by `triggerSending`), and switches to the connection ID of the new path
(`UseConnIDForPath`). `PackPathProbePacket` takes the maximum packet size. The packer expands 1-RTT packets with
PATH_CHALLENGE or PATH_RESPONSE frames to 1200 bytes (`pathValidationPadding`).

`path_manager_outgoing.go`, the client's path manager, is quic-go's file, with two additions: `InactivePathConnID`
returns the connection ID of the path that a PATH_CHALLENGE received on a `Transport` is answered on
(`respondOnProbedPath`; the `Transport` records itself in `receivedPacket.transport`), and `ShouldSwitchPath` also
returns the ID of the path, so that `switchToNewPath` uses the path's connection ID. `ShouldSwitchPath` delays the
switch until a connection ID is available for the path (`connIDManager.HasConnIDForPath`). `switchToNewPath` enables
or disables ECN for the new connection (`SetECNEnabled`).

With IETF Multipath QUIC, a server validates the 4-tuples of each path with a `tupleManager`
(`multipath_tuple_manager.go`), which is derived from the path manager. When quic-go changes the path manager, check
whether the change applies to the tuple manager as well.

### Server's preferred address

The server's preferred address (section 9.6 of RFC 9000, [PREFERRED_ADDRESS.md](PREFERRED_ADDRESS.md)) is
implemented in `preferred_address.go`. It changes these core files:

- `transport.go` and `server.go`: `Transport.PreferredAddress`, validated in `createServer`. `newServer`, the
  `newConn` function of the server and `newConnection` take the `*serverPreferredAddr` (nil without a preferred
  address) as an additional parameter. Calls added by quic-go need it.
- `send_conn.go`: the local address of a `sconn` is part of the `remoteAddrInfo`, and follows the packet info passed to
  `ChangeRemoteAddr`. A connection that sends from multiple sockets (`preferredAddrConn`) selects the local address
  (`localAddrSelector`).
- `conn_id_generator.go`: `IssuePreferredAddressConnID` issues the connection ID with sequence number 1.
- `conn_id_manager.go`: `AddFromPreferredAddressForPath` keeps that connection ID for the client's migration.
- `connection.go`: the server distinguishes the path from the preferred address in `handleShortHeaderPacket`, and drops
  packets received on the original address after the migration. The client's migration is driven by
  `handlePreferredAddrTimers` (run loop and `maybeResetTimer`), `handlePathResponseFrame` and
  `handleHandshakeConfirmed`. `addSinglePath` allows migration after the client migrated to the preferred address,
  even if the server sent `disable_active_migration`.

## Persistent congestion

Persistent congestion (section 7.6 of RFC 9002, [LOSS_RECOVERY.md](LOSS_RECOVERY.md)) applies to all connections:

- `internal/congestion`: `SendAlgorithm.OnPersistentCongestion`, implemented by the `cubicSender` (and by
  `OLIACongestionControl`).
- `sent_packet_history.go`: every packet records the largest acknowledged packet sent between the preceding packet
  in the history and itself (`packet.precedingAcked`), maintained by `Remove`, `DeclareLost` and `SentPacket`.
  `DeclareProbed` keeps a packet whose frames were retransmitted in a PTO probe packet in the history (`probed`),
  where quic-go declared it lost.
- `sent_packet_handler.go`: `pathRecovery.firstRTTSampleTime`, set in `ReceivedAck` and reset on migration;
  `detectLostPackets` establishes persistent congestion (`updatePersistentCongestion`); `queueProbePacket` calls
  `DeclareProbed`; `detectAndRemoveAckedPackets` removes acknowledged probed packets without processing them.

When quic-go changes the sent packet history, check that the `precedingAcked` value still reaches the next packet
whenever a packet leaves the history (acknowledged, declared lost or removed). If quic-go implements persistent
congestion, replace this code with quic-go's, and keep the per-path state.

## Changes for standards compliance

[COMPLIANCE.md](COMPLIANCE.md) maps every MUST statement of the implemented RFCs and drafts to the code. Where quic-go
didn't meet a requirement, this module changed quic-go's code. When merging a quic-go release, keep these changes, and
replace them with quic-go's code if quic-go fixes the same problem:

- `conn_id_generator.go`: `generateUnusedConnID` generates connection IDs until it finds one that the connection
  and the connection's Transports don't use (RFC 9000, sections 5.1 and 10.3.2). `server.go` (the server's connection
  ID) and `transport.go` (`doDial`, `AddWithConnID`) use it as well. `newConnIDGenerator` replaces the built-in
  generator by a `connIDPermutation` (`conn_id_permutation.go`) for every connection, so that a connection never
  issues a connection ID twice, and never issues its initial connection IDs (`initialConnIDs`).
- `internal/handshake`: session tickets contain an ID and the issue time (`sessionTicket`, revision 7);
  `handleSessionTicket` only accepts 0-RTT once per ticket, using the `ZeroRTTReplayCache` (`zero_rtt_replay.go`)
  passed to `NewCryptoSetupServer` (RFC 9001, section 9.2). `transport.go` (`createServer`) creates the default
  cache, `server.go` passes it on to the configs returned by `GetConfigForClient`.
- `internal/ackhandler/received_packet_tracker.go`: no ACK frame is generated when all packets were removed from the
  history (`GetAckFrame`, `IgnoreBelow`); quic-go v0.63.0 panics in `AckFrame.Length`.
- `internal/ackhandler/sent_packet_handler.go`: `MigratedPath` restarts ECN validation, `SetECNEnabled`.
- `closed_conn.go`: the CONNECTION_CLOSE packets of a closed connection are limited to 3 times the bytes received,
  per address (section 10.2.1). `ReplaceWithClosed` passes the packet size.
- `stateless_reset.go` and `transport.go`: the Transport stores the stateless reset tokens as HMAC values
  (`resetTokenMap`), and also checks long header packets (`maybeHandleStatelessReset`); `conn_id_manager.go`
  compares tokens in constant time; `connection.go` checks long header packets that couldn't be processed
  (`handleOnePacket`) (section 10.3).
- `connection.go`: a client drops Initial packets with a token (`handleLongHeaderPacket`, section 17.2.2); the run loop
  closes the connection without sending when the packer returns `errPacketNumbersExhausted` or
  `handshake.ErrConfidentialityLimitReached`.
- `packet_packer.go`: `errPacketNumbersExhausted` (section 12.3). `internal/handshake/updatable_aead.go`: the
  confidentiality limit (`ConfidentialityLimitReached`, RFC 9001, section 6.6), checked by `Get1RTTSealer`.
- `internal/ackhandler/received_packet_history.go`: packets below the oldest ACK range kept are duplicates
  (sections 12.3 and 13.2.3).
- `internal/handshake`: `checkPostHandshakeMessages` (post-handshake CertificateRequest and max_early_data_size,
  RFC 9001, sections 4.4 and 4.6.1); `negotiateVersionFromClientHello` reads the first ClientHello of every
  connection, and rejects a legacy_session_id (section 8.4).
- `internal/wire/frame_parser.go`: DATAGRAM frames without support are a PROTOCOL_VIOLATION (RFC 9221).
  `ResetStreamFrame.IsResetStreamAt` records the frame type for `receive_stream.go`.
- `http3`: truncated frames (`isTruncatedFrame`, `Stream.Read`, `RequestStream.ReadResponse`, `handleRequestStream`),
  `Stream.Close` resets a stream after a failed write, HEADERS frames on CONNECT streams (`Stream.isConnect`), the
  Content-Length check of short bodies (`body.Read`), `:scheme` (`requestFromHeaders`), `checkUniStreams`,
  `rawConn.sendDatagram` waits for the SETTINGS, and the client retries 0-RTT requests rejected with 425.
  `checkFieldSection` rewrites a non-zero Delta Base to 0 for the qpack decoder (RFC 9204, section 4.5.1.2).
  quic-go's `TestHTTPDeadlines` expects a truncated body after the server's write deadline; here the stream is
  reset.
- The HTTP/3 control stream, SETTINGS, push frame and QPACK stream rules of the earlier fixes (see the changelog).

Update COMPLIANCE.md when a change affects a requirement: the tables are maintained by hand. Keep the function
and test names in it valid; a renamed function is easy to miss.

## Rewriting the module path

The module path is rewritten everywhere, with these rules:

- Links to the quic-go repository (`https://github.com/quic-go/quic-go/...`) are kept, so that references to quic-go
  issues, pull requests and wiki pages keep working. Every other occurrence of `github.com/quic-go/quic-go` is
  rewritten: imports, `go.mod` files, mockgen directives and generated mocks, the lint configuration, package paths
  in `-ldflags`, the fuzzing scripts and the CI workflows.
- Imports of the root package are named `quic`, since the last element of the import path (`mp-quic-go`) differs
  from the package name. goimports requires the explicit name.
- `gofmt` sorts the imports again, since the import paths sort differently.

The following commands apply these rules to the checked out tree:

```sh
git grep -l -I -F 'github.com/quic-go/quic-go' |
  xargs perl -pi -e 's{(?<!://)github\.com/quic-go/quic-go(?![\w-])}{github.com/qoke/mp-quic-go}g'
git grep -l -E '^\s*(import\s+)?"github.com/qoke/mp-quic-go"$' -- '*.go' |
  xargs perl -pi -e 's{^(\s*(?:import\s+)?)"github\.com/qoke/mp-quic-go"$}{$1quic "github.com/qoke/mp-quic-go"}'
gofmt -w .
```

The same commands can be used to backport a single quic-go commit between syncs:

```sh
git format-patch -1 --stdout <commit> |
  perl -pe 's{(?<!://)github\.com/quic-go/quic-go(?![\w-])}{github.com/qoke/mp-quic-go}g' |
  git am -3
```

If the commit adds imports of the root package, name them `quic` and run `gofmt` afterwards.

Note backported fixes in `CHANGELOG.md` with the quic-go pull request number, so that the upstream version can be
used when the release containing the fix is merged.

## Syncing with a quic-go release

The following steps use quic-go vX.Y.Z and the development branch `next`.

1. Fetch the release into a temporary branch, without fetching the quic-go tags, and check the commit against the
   tag on GitHub:

   ```sh
   git fetch --no-tags https://github.com/quic-go/quic-go refs/tags/vX.Y.Z
   git branch upstream-sync-vX.Y.Z 'FETCH_HEAD^{commit}'
   git ls-remote https://github.com/quic-go/quic-go 'refs/tags/vX.Y.Z^{}'
   ```

2. In a separate worktree of the temporary branch, rewrite the module path (see above). Check that the result
   builds and passes the linters before committing it:

   ```sh
   go build ./... && go vet ./... && golangci-lint run ./...
   (cd integrationtests/fips && go vet ./...)
   git commit -a -m "change the module path of quic-go vX.Y.Z to github.com/qoke/mp-quic-go"
   ```

   This commit only contains the mechanical rewrite. Don't make any other changes in it.

3. Merge the temporary branch into the development branch:

   ```sh
   git switch next
   git -c merge.conflictStyle=zdiff3 merge --no-ff --no-commit upstream-sync-vX.Y.Z
   ```

4. Many conflicts are only caused by the rewrite: one side changed a line, and the other side rewrote the module
   path in it. Merge these files again, using the mechanical commit of the previous sync as the merge base.
   Check that its parent is the merge base reported by git first:

   ```sh
   R=$(git log --format=%H -1 --grep '^change the module path of quic-go' HEAD)
   test "$(git rev-parse "$R^")" = "$(git merge-base HEAD upstream-sync-vX.Y.Z)"

   tmp=$(mktemp -d)
   for f in $(git diff --name-only --diff-filter=U); do
     # only files that exist on both sides and in the merge base
     git cat-file -e ":2:$f" 2>/dev/null && git cat-file -e ":3:$f" 2>/dev/null &&
       git cat-file -e "$R:$f" 2>/dev/null || continue
     git show "$R:$f" > "$tmp/base"
     git show ":2:$f" > "$tmp/ours"
     git show ":3:$f" > "$tmp/theirs"
     if git merge-file --zdiff3 -L HEAD -L base -L upstream "$tmp/ours" "$tmp/base" "$tmp/theirs"; then
       cp "$tmp/ours" "$f" && git add "$f"
     else
       cp "$tmp/ours" "$f"
     fi
   done
   ```

   If the merge base is not the parent of a mechanical commit (as for the first sync), use the merge base with
   the module path rewritten instead.

5. Resolve the remaining conflicts by hand. Files deleted by quic-go and only changed by this module through the
   rewrite (or through changes that no longer apply) are deleted. For code:
   - Keep the multipath behavior, and adapt it to the upstream changes. Upstream changes that don't conflict can
     still break the multipath code, so read the quic-go release notes and the diff of the core files
     (`connection.go`, `packet_packer.go`, `framer.go`, `send_queue.go`, `send_conn.go`,
     `internal/ackhandler`, `internal/wire`).
   - Use the upstream version of fixes that were backported, and remove duplicate code that git merged twice.
     A useful check is to compare this module's changes to the merge base before and after the merge, file by
     file (`git diff <merge base, rewritten> HEAD` against `git diff upstream-sync-vX.Y.Z <merged tree>`).
   - Update `go.mod`: use the upstream Go version and dependency versions, unless this module needs a newer one.

6. Run the checks below, and fix the problems they find. Changes that are needed to make the merged tree build and
   pass the tests belong to the merge commit. Unrelated fixes are separate commits after the merge.

7. Commit the merge with the subject `Merge quic-go vX.Y.Z`, and describe how the conflicts were resolved in the
   commit message. Then delete the temporary branch and its worktree:

   ```sh
   git worktree remove <worktree>
   git branch -D upstream-sync-vX.Y.Z
   ```

8. Update the upstream base in `README.md` and `CHANGELOG.md`, and add a row to the table above.

## Checks

Before committing the merge:

```sh
go build ./...
go vet ./...
go test -count=1 ./...
go test -race -count=1 -skip '^TestFrameParserAllocs$' . ./internal/ackhandler ./internal/wire ./internal/handshake ./http3
golangci-lint run ./...
for os in windows darwin freebsd openbsd solaris; do GOOS=$os golangci-lint run ./...; done
(cd integrationtests/fips && go mod tidy -diff && go test ./...)
(cd integrationtests/upstream && go mod tidy -diff && go test ./...)
(cd integrationtests/gomodvendor && go mod tidy -diff)
go mod tidy -diff
go list ./... | grep -v '/internal/ackhandler$' | xargs go fix -diff
go fix -diff -slicesbackward=false ./internal/ackhandler
.github/workflows/go-generate.sh
go tool gcassert ./...
```

`TestFrameParserAllocs` fails under the race detector, since the race instrumentation allocates.

`integrationtests/upstream` runs mp-quic-go against the upstream release that it is based on. Update the
`github.com/quic-go/quic-go` version in its `go.mod` to vX.Y.Z.

The multipath tests of `integrationtests/self` (`multipath_test.go`, and `multipath_linux_test.go` using
127.0.0.2) transfer data over two paths with packet loss, key updates, path abandonment and NAT rebinding. Also run
the picoquic interop tests, which need Docker (see [interop/multipath/README.md](../interop/multipath/README.md)):

```sh
go test -tags picoquic -count=1 ./interop/multipath/...
```

## Conformance tests

Before a release, and after merging a quic-go release, run the conformance tests below, and update the results in
[COMPLIANCE.md](COMPLIANCE.md#conformance-tests). On shared hosts, run them through the host's CPU policy tool.

### QUIC interop runner

The [QUIC interop runner](https://github.com/quic-interop/quic-interop-runner) tests the endpoints in
`interop/client` and `interop/server` against other implementations. Build the image from the repository (the
Dockerfile reads the commit with `git`, so build from a checkout):

```sh
docker build -f interop/Dockerfile -t mp-quic-go-interop:latest .
```

Add the implementation to the runner's `implementations_quic.json`:

```json
"mp-quic-go": {"image": "mp-quic-go-interop:latest", "url": "https://github.com/qoke/mp-quic-go", "role": "both"}
```

Then run all test cases against the other implementations in both roles, and against upstream quic-go for
comparison:

```sh
python3 run.py -d -s mp-quic-go -c mp-quic-go,quic-go,ngtcp2,quiche,picoquic,msquic
python3 run.py -d -s quic-go,ngtcp2,quiche,picoquic,msquic -c mp-quic-go
```

The runner needs Docker with IPv6 and the ns-3 network simulator image. On hosts where the simulator can't forward
traffic between the Docker networks (for example with `br_netfilter` and the raw table rules of Docker 29), the
results in COMPLIANCE.md describe the single-bridge setup that was used instead. Compare failures with the public
results at https://interop.seemann.io: run the same pair with upstream quic-go in place of mp-quic-go.

### h3spec

[h3spec](https://github.com/kazu-yamamoto/h3spec) checks the HTTP/3 and QUIC error handling of a server:

```sh
go build -o server ./example
./server -bind 127.0.0.1:4433 -cert cert.pem -key key.pem &
h3spec 127.0.0.1 4433 -n
```

The 0-RTT test case only runs against a server that accepts 0-RTT (`http3.Server` with `quic.Config.Allow0RTT`).

### Multipath interoperability

The picoquic tests above cover IETF Multipath QUIC, QUIC version 2, the preferred address, address discovery,
greasing the QUIC Bit and RESET_STREAM_AT, in both roles. picoquic's public server (`test.privateoctopus.com:4433`)
negotiates multipath as well: open a second path from another local address or port, and check that data arrives on
both paths (`Conn.Paths`), that `PATH_STATUS_BACKUP` moves the data to the other path, and that `PATH_ABANDON`
is answered.

Mixed versions: run a transfer between a client and a server built from this version and from the previous release
(in both roles). Peers of v0.2.x don't negotiate multipath with this version, and the connection must work on a
single path.

### Fuzzing

The fuzz targets are native Go fuzz tests:

```sh
go test -run '^FuzzFrames$' -fuzz '^FuzzFrames$' -fuzztime=5m ./internal/wire
```

The targets are `FuzzFrames`, `FuzzHeaderParser` and `FuzzTransportParameters` (`internal/wire`), `FuzzHandshake`
and `FuzzClientHelloTransportParameters` (`internal/handshake`), `FuzzFrameParser`, `FuzzHeaderParsing`,
`FuzzCheckFieldSection` and `FuzzParsePriority` (`http3`), `FuzzFrameSorter` and `FuzzFindSNI` (root package), and
`FuzzEncoder` (`qlogwriter/jsontext`). Commit the inputs of crashes found as regression tests (`testdata/fuzz`).
[FUZZING.md](../FUZZING.md) describes the OSS-Fuzz setup of quic-go.
