package handshake

import (
	"crypto"
	"crypto/cipher"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/internal/utils"
	"github.com/AeonDave/mp-quic-go/qlog"
	"github.com/AeonDave/mp-quic-go/qlogwriter"
)

var keyUpdateInterval atomic.Uint64

func init() {
	keyUpdateInterval.Store(protocol.KeyUpdateInterval)
}

func SetKeyUpdateInterval(v uint64) (reset func()) {
	old := keyUpdateInterval.Swap(v)
	return func() { keyUpdateInterval.Store(old) }
}

// FirstKeyUpdateInterval is the maximum number of packets we send or receive before initiating the first key update.
// It's a package-level variable to allow modifying it for testing purposes.
var FirstKeyUpdateInterval uint64 = 100

// With the multipath extension, key updates are spaced by 3 times the largest PTO among all paths.
// Once this many packets were sent with the current keys, the next key update is initiated without waiting any longer,
// so that the keys are updated well before reaching the confidentiality limit of AES-GCM (2^23 packets,
// see RFC 9001, Section 6.6).
const maxPacketsDelayingKeyUpdate = 1 << 22

// pathKeys is the 1-RTT packet protection state of a path.
// Without the multipath extension, only path 0 is used.
type pathKeys struct {
	id protocol.PathID

	// With the multipath extension, the nonce depends on the path ID (draft-ietf-quic-multipath, Section 2.4).
	// Every path therefore uses its own AEADs, created with the IV returned by ivForPath.
	// The receive AEADs of path 0 are created when the keys are installed, those of the other paths when the first
	// packet is received on the path. They are rolled on every key update.
	// The send AEAD is created when the first packet is sent with the current keys.
	rcvAEAD     cipher.AEAD
	nextRcvAEAD cipher.AEAD
	prevRcvAEAD cipher.AEAD
	sendAEAD    cipher.AEAD

	highestRcvdPN           protocol.PacketNumber // highest packet number received (which could be successfully unprotected)
	firstRcvdWithCurrentKey protocol.PacketNumber
	firstSentWithCurrentKey protocol.PacketNumber
	// Largest packet number acknowledged by the most recent ACK frame.
	// It decreases if a reordered ACK frame acknowledges a lower packet number than an earlier ACK frame.
	largestAcked protocol.PacketNumber
	// Highest packet number received that was protected with keys older than the current keys.
	// Used to check that the peer doesn't use older keys for higher packet numbers (RFC 9001, Section 6.4).
	highestRcvdWithOldKeys protocol.PacketNumber
}

func newPathKeys(id protocol.PathID) pathKeys {
	return pathKeys{
		id:                      id,
		firstRcvdWithCurrentKey: protocol.InvalidPacketNumber,
		firstSentWithCurrentKey: protocol.InvalidPacketNumber,
		largestAcked:            protocol.InvalidPacketNumber,
		highestRcvdWithOldKeys:  protocol.InvalidPacketNumber,
	}
}

// receiveKey identifies the keys used to remove the protection of a 1-RTT packet.
type receiveKey uint8

const (
	receiveKeyCurrent receiveKey = iota
	receiveKeyPrevious
	receiveKeyNext
)

// selectReceiveKey selects the keys to remove the protection of a packet received on a path.
// Once the path has received a packet protected with the current keys, packets with a different key phase and
// a lower packet number use the previous keys, and packets with a higher packet number use the next keys
// (RFC 9001, Section 6.5). Before that, the key phase alone determines the keys (draft-ietf-quic-multipath,
// Section 2.5): the previous keys as long as they are retained, the next keys after that.
// Exactly one set of keys is selected, so that a packet is decrypted at most once (RFC 9001, Section 6.3).
func selectReceiveKey(
	kp, currentKeyPhase protocol.KeyPhaseBit,
	pn, firstRcvdWithCurrentKey protocol.PacketNumber,
	havePrevKeys bool,
) receiveKey {
	if kp == currentKeyPhase {
		return receiveKeyCurrent
	}
	if firstRcvdWithCurrentKey != protocol.InvalidPacketNumber {
		if pn < firstRcvdWithCurrentKey {
			return receiveKeyPrevious
		}
		return receiveKeyNext
	}
	if havePrevKeys {
		return receiveKeyPrevious
	}
	return receiveKeyNext
}

type updatableAEAD struct {
	suite cipherSuite

	keyPhase           protocol.KeyPhase
	firstPacketNumber  protocol.PacketNumber
	handshakeConfirmed bool

	invalidPacketLimit uint64
	// The number of packets that can be sent with one set of keys, 0 if there's no limit (section 6.6 of RFC 9001).
	confidentialityLimit uint64
	invalidPacketCount   uint64

	// Time when the keys should be dropped. Keys are dropped on the next call to Open().
	prevRcvAEADExpiry monotime.Time
	prevRcvKeys       aeadKeys // only set as long as the previous keys are retained

	// The packet counters and the following flags count the packets of all paths.
	numRcvdWithCurrentKey uint64
	numSentWithCurrentKey uint64
	// set when a packet protected with the current keys is received
	rcvdWithCurrentKey bool
	// With the multipath extension: set when a packet sent with the current keys is acknowledged,
	// and the time when this happened first.
	currentKeyAcked     bool
	currentKeyAckedTime monotime.Time

	rcvKeys               aeadKeys
	sendKeys              aeadKeys
	nextRcvKeys           aeadKeys
	nextSendKeys          aeadKeys
	nextRcvTrafficSecret  []byte
	nextSendTrafficSecret []byte
	// caches cipher.AEAD.Overhead(). This speeds up calls to Overhead().
	aeadOverhead int

	path0 pathKeys
	paths map[protocol.PathID]*pathKeys // all other paths

	multipath bool
	// returns the largest PTO among all paths, only set with the multipath extension
	maxPTO func() time.Duration

	headerDecrypter headerProtector
	headerEncrypter headerProtector

	rttStats *utils.RTTStats

	qlogger qlogwriter.Recorder
	logger  utils.Logger
	version protocol.Version

	// use a single slice to avoid allocations
	nonceBuf []byte
}

var (
	_ ShortHeaderOpener = &updatableAEAD{}
	_ ShortHeaderSealer = &updatableAEAD{}
)

func newUpdatableAEAD(rttStats *utils.RTTStats, qlogger qlogwriter.Recorder, logger utils.Logger, version protocol.Version) *updatableAEAD {
	return &updatableAEAD{
		firstPacketNumber: protocol.InvalidPacketNumber,
		path0:             newPathKeys(0),
		rttStats:          rttStats,
		qlogger:           qlogger,
		logger:            logger,
		version:           version,
	}
}

// EnableMultipath applies the rules of the multipath extension (draft-ietf-quic-multipath) to the 1-RTT keys.
// It is called when the transport parameters are received, before the handshake is confirmed,
// and therefore before the first key update.
// maxPTO returns the largest PTO among all paths.
// It is used for the key drop timer and for spacing key updates (Section 2.5).
func (a *updatableAEAD) EnableMultipath(maxPTO func() time.Duration) {
	a.multipath = true
	a.maxPTO = maxPTO
}

// pto is the PTO used for the key update timers:
// the largest PTO among all paths with the multipath extension, the PTO of the connection otherwise.
func (a *updatableAEAD) pto() time.Duration {
	if a.maxPTO != nil {
		return a.maxPTO()
	}
	return a.rttStats.PTO(true)
}

// getPath returns the state of a path, creating it if it doesn't exist yet.
func (a *updatableAEAD) getPath(id protocol.PathID) *pathKeys {
	if id == 0 {
		return &a.path0
	}
	if p, ok := a.paths[id]; ok {
		return p
	}
	if a.paths == nil {
		a.paths = make(map[protocol.PathID]*pathKeys)
	}
	p := newPathKeys(id)
	a.paths[id] = &p
	return &p
}

// lookupPath returns the state of a path, or nil if it doesn't exist.
func (a *updatableAEAD) lookupPath(id protocol.PathID) *pathKeys {
	if id == 0 {
		return &a.path0
	}
	return a.paths[id]
}

// DropPath drops the state of a path. The path ID must not be used afterwards.
// Path IDs are never reused (draft-ietf-quic-multipath, Section 7.3).
func (a *updatableAEAD) DropPath(pathID protocol.PathID) {
	if pathID == 0 {
		a.path0 = newPathKeys(0)
		return
	}
	delete(a.paths, pathID)
}

// newAEAD creates an AEAD for the packets of a path.
func (a *updatableAEAD) newAEAD(keys aeadKeys, pathID protocol.PathID) cipher.AEAD {
	return a.suite.AEAD(keys.key, ivForPath(keys.iv, pathID))
}

// initRcvAEADs creates the receive AEADs of a path.
// They are created at the same time, so that the time it takes to process a packet doesn't depend on its key phase
// (RFC 9001, Section 6.3).
func (a *updatableAEAD) initRcvAEADs(p *pathKeys) {
	if p.rcvAEAD != nil {
		return
	}
	p.rcvAEAD = a.newAEAD(a.rcvKeys, p.id)
	p.nextRcvAEAD = a.newAEAD(a.nextRcvKeys, p.id)
	if a.prevRcvKeys.key != nil {
		p.prevRcvAEAD = a.newAEAD(a.prevRcvKeys, p.id)
	}
}

func (a *updatableAEAD) rollKeys() {
	if a.prevRcvKeys.key != nil {
		a.logger.Debugf("Dropping key phase %d ahead of scheduled time. Drop time was: %s", a.keyPhase-1, a.prevRcvAEADExpiry)
		if a.qlogger != nil {
			a.qlogger.RecordEvent(qlog.KeyDiscarded{
				KeyType:  qlog.KeyTypeClient1RTT,
				KeyPhase: a.keyPhase - 1,
			})
			a.qlogger.RecordEvent(qlog.KeyDiscarded{
				KeyType:  qlog.KeyTypeServer1RTT,
				KeyPhase: a.keyPhase - 1,
			})
		}
		a.prevRcvAEADExpiry = 0
	}

	a.keyPhase++
	a.numRcvdWithCurrentKey = 0
	a.numSentWithCurrentKey = 0
	a.rcvdWithCurrentKey = false
	a.currentKeyAcked = false
	a.currentKeyAckedTime = 0
	a.prevRcvKeys = a.rcvKeys
	a.rcvKeys = a.nextRcvKeys
	a.sendKeys = a.nextSendKeys

	a.nextRcvTrafficSecret = a.getNextTrafficSecret(a.suite.Hash, a.nextRcvTrafficSecret)
	a.nextSendTrafficSecret = a.getNextTrafficSecret(a.suite.Hash, a.nextSendTrafficSecret)
	a.nextRcvKeys = deriveAEADKeys(a.suite, a.nextRcvTrafficSecret, a.version)
	a.nextSendKeys = deriveAEADKeys(a.suite, a.nextSendTrafficSecret, a.version)

	a.rollPathKeys(&a.path0)
	for _, p := range a.paths {
		a.rollPathKeys(p)
	}
}

func (a *updatableAEAD) rollPathKeys(p *pathKeys) {
	p.firstRcvdWithCurrentKey = protocol.InvalidPacketNumber
	p.firstSentWithCurrentKey = protocol.InvalidPacketNumber
	// all packets received so far were protected with keys older than the new keys
	p.highestRcvdWithOldKeys = p.highestRcvdPN
	if p.rcvAEAD != nil {
		p.prevRcvAEAD = p.rcvAEAD
		p.rcvAEAD = p.nextRcvAEAD
		p.nextRcvAEAD = a.newAEAD(a.nextRcvKeys, p.id)
	}
	p.sendAEAD = nil
}

func (a *updatableAEAD) dropPrevRcvKeys() {
	a.prevRcvKeys = aeadKeys{}
	a.prevRcvAEADExpiry = 0
	a.path0.prevRcvAEAD = nil
	for _, p := range a.paths {
		p.prevRcvAEAD = nil
	}
}

func (a *updatableAEAD) startKeyDropTimer(now monotime.Time) {
	d := 3 * a.pto()
	a.logger.Debugf("Starting key drop timer to drop key phase %d (in %s)", a.keyPhase-1, d)
	a.prevRcvAEADExpiry = now.Add(d)
}

// hkdfKeyUpdateLabel returns the label used to derive the next 1-RTT secret on a key update.
// QUIC version 2 uses a different label (section 3.3.2 of RFC 9369).
func hkdfKeyUpdateLabel(v protocol.Version) string {
	if v == protocol.Version2 {
		return "quicv2 ku"
	}
	return "quic ku"
}

func (a *updatableAEAD) getNextTrafficSecret(hash crypto.Hash, ts []byte) []byte {
	return hkdfExpandLabel(hash, ts, []byte{}, hkdfKeyUpdateLabel(a.version), hash.Size())
}

// SetReadKey sets the read key.
// For the client, this function is called before SetWriteKey.
// For the server, this function is called after SetWriteKey.
func (a *updatableAEAD) SetReadKey(suite cipherSuite, trafficSecret []byte) {
	a.rcvKeys = deriveAEADKeys(suite, trafficSecret, a.version)
	a.path0.rcvAEAD = suite.AEAD(a.rcvKeys.key, a.rcvKeys.iv)
	a.headerDecrypter = newHeaderProtector(suite, trafficSecret, false, a.version)
	if a.suite.ID == 0 { // suite is not set yet
		a.setAEADParameters(a.path0.rcvAEAD, suite)
	}

	a.nextRcvTrafficSecret = a.getNextTrafficSecret(suite.Hash, trafficSecret)
	a.nextRcvKeys = deriveAEADKeys(suite, a.nextRcvTrafficSecret, a.version)
	a.path0.nextRcvAEAD = suite.AEAD(a.nextRcvKeys.key, a.nextRcvKeys.iv)
}

// SetWriteKey sets the write key.
// For the client, this function is called after SetReadKey.
// For the server, this function is called before SetReadKey.
func (a *updatableAEAD) SetWriteKey(suite cipherSuite, trafficSecret []byte) {
	a.sendKeys = deriveAEADKeys(suite, trafficSecret, a.version)
	a.path0.sendAEAD = suite.AEAD(a.sendKeys.key, a.sendKeys.iv)
	a.headerEncrypter = newHeaderProtector(suite, trafficSecret, false, a.version)
	if a.suite.ID == 0 { // suite is not set yet
		a.setAEADParameters(a.path0.sendAEAD, suite)
	}

	a.nextSendTrafficSecret = a.getNextTrafficSecret(suite.Hash, trafficSecret)
	a.nextSendKeys = deriveAEADKeys(suite, a.nextSendTrafficSecret, a.version)
}

func (a *updatableAEAD) setAEADParameters(aead cipher.AEAD, suite cipherSuite) {
	a.nonceBuf = make([]byte, aead.NonceSize())
	a.aeadOverhead = aead.Overhead()
	a.suite = suite
	switch suite.ID {
	case tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384:
		a.invalidPacketLimit = protocol.InvalidPacketLimitAES
		a.confidentialityLimit = protocol.ConfidentialityLimitAES
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		a.invalidPacketLimit = protocol.InvalidPacketLimitChaCha
		// The confidentiality limit of ChaCha20-Poly1305 is larger than the number of packet numbers.
	default:
		panic(fmt.Sprintf("unknown cipher suite %d", suite.ID))
	}
}

func (a *updatableAEAD) DecodePacketNumber(wirePN protocol.PacketNumber, wirePNLen protocol.PacketNumberLen) protocol.PacketNumber {
	return protocol.DecodePacketNumber(wirePNLen, a.path0.highestRcvdPN, wirePN)
}

// DecodePacketNumberForPath decodes the packet number of a packet received on a path.
// With the multipath extension, every path has its own packet number space.
func (a *updatableAEAD) DecodePacketNumberForPath(pathID protocol.PathID, wirePN protocol.PacketNumber, wirePNLen protocol.PacketNumberLen) protocol.PacketNumber {
	var largest protocol.PacketNumber
	if p := a.lookupPath(pathID); p != nil {
		largest = p.highestRcvdPN
	}
	return protocol.DecodePacketNumber(wirePNLen, largest, wirePN)
}

func (a *updatableAEAD) Open(dst, src []byte, rcvTime monotime.Time, pn protocol.PacketNumber, kp protocol.KeyPhaseBit, ad []byte) ([]byte, error) {
	return a.openForPath(&a.path0, dst, src, rcvTime, pn, kp, ad)
}

// OpenForPath opens a packet received on a path.
// The state of the path is created when the first packet is received on it.
// If a packet on a path that has no state yet can't be opened, no state is kept for the path.
func (a *updatableAEAD) OpenForPath(dst, src []byte, rcvTime monotime.Time, pathID protocol.PathID, pn protocol.PacketNumber, kp protocol.KeyPhaseBit, ad []byte) ([]byte, error) {
	if p := a.lookupPath(pathID); p != nil {
		return a.openForPath(p, dst, src, rcvTime, pn, kp, ad)
	}
	dec, err := a.openForPath(a.getPath(pathID), dst, src, rcvTime, pn, kp, ad)
	if err != nil {
		delete(a.paths, pathID)
	}
	return dec, err
}

func (a *updatableAEAD) openForPath(p *pathKeys, dst, src []byte, rcvTime monotime.Time, pn protocol.PacketNumber, kp protocol.KeyPhaseBit, ad []byte) ([]byte, error) {
	dec, err := a.open(p, dst, src, rcvTime, pn, kp, ad)
	if err == ErrDecryptionFailed {
		// The integrity limit applies to the packets received on all paths
		// (draft-ietf-quic-multipath, Section 7.3).
		a.invalidPacketCount++
		if a.invalidPacketCount >= a.invalidPacketLimit {
			return nil, &qerr.TransportError{ErrorCode: qerr.AEADLimitReached}
		}
	}
	if err == nil {
		p.highestRcvdPN = max(p.highestRcvdPN, pn)
	}
	return dec, err
}

func (a *updatableAEAD) open(p *pathKeys, dst, src []byte, rcvTime monotime.Time, pn protocol.PacketNumber, kp protocol.KeyPhaseBit, ad []byte) ([]byte, error) {
	if a.prevRcvKeys.key != nil && !a.prevRcvAEADExpiry.IsZero() && rcvTime.After(a.prevRcvAEADExpiry) {
		a.dropPrevRcvKeys()
		a.logger.Debugf("Dropping key phase %d", a.keyPhase-1)
		if a.qlogger != nil {
			a.qlogger.RecordEvent(qlog.KeyDiscarded{
				KeyType:  qlog.KeyTypeClient1RTT,
				KeyPhase: a.keyPhase - 1,
			})
			a.qlogger.RecordEvent(qlog.KeyDiscarded{
				KeyType:  qlog.KeyTypeServer1RTT,
				KeyPhase: a.keyPhase - 1,
			})
		}
	}
	a.initRcvAEADs(p)
	binary.BigEndian.PutUint64(a.nonceBuf[len(a.nonceBuf)-8:], uint64(pn))
	key := selectReceiveKey(kp, a.keyPhase.Bit(), pn, p.firstRcvdWithCurrentKey, p.prevRcvAEAD != nil)
	if key == receiveKeyPrevious {
		if p.prevRcvAEAD == nil {
			return nil, ErrKeysDropped
		}
		// we updated the key, but the peer hasn't updated yet
		dec, err := p.prevRcvAEAD.Open(dst, a.nonceBuf, src, ad)
		if err != nil {
			return dec, ErrDecryptionFailed
		}
		p.highestRcvdWithOldKeys = max(p.highestRcvdWithOldKeys, pn)
		return dec, nil
	}
	if key == receiveKeyNext {
		// try opening the packet with the next key phase
		dec, err := p.nextRcvAEAD.Open(dst, a.nonceBuf, src, ad)
		if err != nil {
			return nil, ErrDecryptionFailed
		}
		// Opening succeeded. Check if the peer was allowed to update.
		if a.keyPhase > 0 && a.numSentWithCurrentKey == 0 {
			return nil, &qerr.TransportError{
				ErrorCode:    qerr.KeyUpdateError,
				ErrorMessage: "keys updated too quickly",
			}
		}
		// All packets received on this path so far were protected with older keys.
		if a.multipath && pn < p.highestRcvdPN {
			return nil, errOldKeysForHigherPacketNumber()
		}
		a.rollKeys()
		a.logger.Debugf("Peer updated keys to %d", a.keyPhase)
		// The peer initiated this key update. It's safe to drop the keys for the previous generation now.
		// Start a timer to drop the previous key generation.
		a.startKeyDropTimer(rcvTime)
		if a.qlogger != nil {
			a.qlogger.RecordEvent(qlog.KeyUpdated{
				Trigger:  qlog.KeyUpdateRemote,
				KeyType:  qlog.KeyTypeClient1RTT,
				KeyPhase: a.keyPhase,
			})
			a.qlogger.RecordEvent(qlog.KeyUpdated{
				Trigger:  qlog.KeyUpdateRemote,
				KeyType:  qlog.KeyTypeServer1RTT,
				KeyPhase: a.keyPhase,
			})
		}
		p.firstRcvdWithCurrentKey = pn
		a.rcvdWithCurrentKey = true
		return dec, err
	}
	// The AEAD we're using here will be the qtls.aeadAESGCM13.
	// It uses the nonce provided here and XOR it with the IV.
	dec, err := p.rcvAEAD.Open(dst, a.nonceBuf, src, ad)
	if err != nil {
		return dec, ErrDecryptionFailed
	}
	if a.multipath && pn < p.highestRcvdWithOldKeys {
		return nil, errOldKeysForHigherPacketNumber()
	}
	a.numRcvdWithCurrentKey++
	if !a.rcvdWithCurrentKey {
		// We initiated the key updated, and now we received the first packet protected with the new key phase.
		// Therefore, we are certain that the peer rolled its keys as well. Start a timer to drop the old keys.
		if a.keyPhase > 0 {
			a.logger.Debugf("Peer confirmed key update to phase %d", a.keyPhase)
			a.startKeyDropTimer(rcvTime)
		}
		a.rcvdWithCurrentKey = true
	}
	// With the multipath extension, track the lowest packet number received with the current keys:
	// only packets with a lower packet number are opened with the previous keys (RFC 9001, Section 6.5),
	// so the previous keys are never used for a higher packet number than the current keys (RFC 9001, Section 6.4).
	if p.firstRcvdWithCurrentKey == protocol.InvalidPacketNumber || (a.multipath && pn < p.firstRcvdWithCurrentKey) {
		p.firstRcvdWithCurrentKey = pn
	}
	return dec, err
}

// errOldKeysForHigherPacketNumber is returned when the peer protected a packet with older keys than a packet with a
// lower packet number (RFC 9001, Section 6.4).
func errOldKeysForHigherPacketNumber() error {
	return &qerr.TransportError{
		ErrorCode:    qerr.KeyUpdateError,
		ErrorMessage: "old keys used for a higher packet number",
	}
}

func (a *updatableAEAD) Seal(dst, src []byte, pn protocol.PacketNumber, ad []byte) []byte {
	return a.seal(&a.path0, dst, src, pn, ad)
}

// SealForPath seals a packet sent on a path.
func (a *updatableAEAD) SealForPath(dst, src []byte, pathID protocol.PathID, pn protocol.PacketNumber, ad []byte) []byte {
	return a.seal(a.getPath(pathID), dst, src, pn, ad)
}

func (a *updatableAEAD) seal(p *pathKeys, dst, src []byte, pn protocol.PacketNumber, ad []byte) []byte {
	if p.firstSentWithCurrentKey == protocol.InvalidPacketNumber {
		p.firstSentWithCurrentKey = pn
	}
	if a.firstPacketNumber == protocol.InvalidPacketNumber {
		a.firstPacketNumber = pn
	}
	// The confidentiality limit applies to the packets sent on all paths (draft-ietf-quic-multipath, Section 7.3).
	a.numSentWithCurrentKey++
	if p.sendAEAD == nil {
		p.sendAEAD = a.newAEAD(a.sendKeys, p.id)
	}
	binary.BigEndian.PutUint64(a.nonceBuf[len(a.nonceBuf)-8:], uint64(pn))
	// The AEAD we're using here will be the qtls.aeadAESGCM13.
	// It uses the nonce provided here and XOR it with the IV.
	return p.sendAEAD.Seal(dst, a.nonceBuf, src, ad)
}

func (a *updatableAEAD) SetLargestAcked(pn protocol.PacketNumber) error {
	return a.setLargestAcked(&a.path0, pn, 0)
}

// SetLargestAckedForPath is called when the peer acknowledges packets sent on a path.
func (a *updatableAEAD) SetLargestAckedForPath(pathID protocol.PathID, pn protocol.PacketNumber, now monotime.Time) error {
	p := a.lookupPath(pathID)
	if p == nil {
		return nil
	}
	return a.setLargestAcked(p, pn, now)
}

func (a *updatableAEAD) setLargestAcked(p *pathKeys, pn protocol.PacketNumber, now monotime.Time) error {
	if p.firstSentWithCurrentKey != protocol.InvalidPacketNumber && pn >= p.firstSentWithCurrentKey {
		// The ACK might have been sent on a different path,
		// so we can only be sure that it was sent with the old keys if we didn't receive any packet with the new keys.
		if a.numRcvdWithCurrentKey == 0 {
			return &qerr.TransportError{
				ErrorCode:    qerr.KeyUpdateError,
				ErrorMessage: fmt.Sprintf("received ACK for key phase %d, but peer didn't update keys", a.keyPhase),
			}
		}
		if a.multipath && !a.currentKeyAcked {
			a.currentKeyAcked = true
			if now.IsZero() {
				now = monotime.Now()
			}
			a.currentKeyAckedTime = now
		}
	}
	p.largestAcked = pn
	return nil
}

func (a *updatableAEAD) SetHandshakeConfirmed() {
	a.handshakeConfirmed = true
}

// ConfidentialityLimitReached says if the confidentiality limit of the AEAD was reached, and the keys can't be
// updated. The keys then can't be used anymore (section 6.6 of RFC 9001).
func (a *updatableAEAD) ConfidentialityLimitReached() bool {
	return a.confidentialityLimit > 0 && a.numSentWithCurrentKey >= a.confidentialityLimit && !a.updateAllowed()
}

func (a *updatableAEAD) updateAllowed() bool {
	if !a.handshakeConfirmed {
		return false
	}
	// the first key update is allowed as soon as the handshake is confirmed
	if a.keyPhase == 0 {
		return true
	}
	// subsequent key updates as soon as a packet sent with that key phase has been acknowledged
	if a.multipath {
		// With the multipath extension, packets sent on a path can be acknowledged on any path,
		// so ACK frames are frequently received out of order.
		// An ACK frame that was delayed doesn't withdraw the permission given by an earlier ACK frame.
		return a.currentKeyAcked
	}
	return a.path0.firstSentWithCurrentKey != protocol.InvalidPacketNumber &&
		a.path0.largestAcked != protocol.InvalidPacketNumber &&
		a.path0.largestAcked >= a.path0.firstSentWithCurrentKey
}

func (a *updatableAEAD) shouldInitiateKeyUpdate() bool {
	if !a.updateAllowed() {
		return false
	}
	// The keys are updated before reaching the confidentiality limit (section 6.6 of RFC 9001).
	if a.confidentialityLimit > 0 && a.numSentWithCurrentKey >= a.confidentialityLimit {
		return true
	}
	// Initiate the first key update shortly after the handshake, in order to exercise the key update mechanism.
	if a.keyPhase == 0 {
		if a.numRcvdWithCurrentKey >= FirstKeyUpdateInterval || a.numSentWithCurrentKey >= FirstKeyUpdateInterval {
			return true
		}
	}
	interval := keyUpdateInterval.Load()
	if a.numRcvdWithCurrentKey < interval && a.numSentWithCurrentKey < interval {
		return false
	}
	if a.keyPhase > 0 && !a.keyUpdateSpacingElapsed() {
		return false
	}
	if a.numRcvdWithCurrentKey >= interval {
		a.logger.Debugf("Received %d packets with current key phase. Initiating key update to the next key phase: %d", a.numRcvdWithCurrentKey, a.keyPhase+1)
		return true
	}
	a.logger.Debugf("Sent %d packets with current key phase. Initiating key update to the next key phase: %d", a.numSentWithCurrentKey, a.keyPhase+1)
	return true
}

// keyUpdateSpacingElapsed says if the next key update can be initiated.
// With the multipath extension, it is initiated 3 times the largest PTO among all paths after the previous key update
// was acknowledged (draft-ietf-quic-multipath, Section 2.5).
func (a *updatableAEAD) keyUpdateSpacingElapsed() bool {
	if !a.multipath || a.numSentWithCurrentKey >= maxPacketsDelayingKeyUpdate {
		return true
	}
	return !monotime.Now().Before(a.currentKeyAckedTime.Add(3 * a.pto()))
}

func (a *updatableAEAD) KeyPhase() protocol.KeyPhaseBit {
	if a.shouldInitiateKeyUpdate() {
		a.rollKeys()
		if a.qlogger != nil {
			a.qlogger.RecordEvent(qlog.KeyUpdated{
				Trigger:  qlog.KeyUpdateLocal,
				KeyType:  qlog.KeyTypeClient1RTT,
				KeyPhase: a.keyPhase,
			})
			a.qlogger.RecordEvent(qlog.KeyUpdated{
				Trigger:  qlog.KeyUpdateLocal,
				KeyType:  qlog.KeyTypeServer1RTT,
				KeyPhase: a.keyPhase,
			})
		}
	}
	return a.keyPhase.Bit()
}

func (a *updatableAEAD) Overhead() int {
	return a.aeadOverhead
}

func (a *updatableAEAD) EncryptHeader(sample []byte, firstByte *byte, hdrBytes []byte) {
	a.headerEncrypter.EncryptHeader(sample, firstByte, hdrBytes)
}

func (a *updatableAEAD) DecryptHeader(sample []byte, firstByte *byte, hdrBytes []byte) {
	a.headerDecrypter.DecryptHeader(sample, firstByte, hdrBytes)
}

func (a *updatableAEAD) FirstPacketNumber() protocol.PacketNumber {
	return a.firstPacketNumber
}
