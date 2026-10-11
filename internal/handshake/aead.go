package handshake

import (
	"crypto/cipher"
	"encoding/binary"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
)

// aeadKeys are the packet protection key and IV derived from a traffic secret (RFC 9001, Section 5.1).
type aeadKeys struct {
	key []byte
	iv  []byte
}

func deriveAEADKeys(suite cipherSuite, trafficSecret []byte, v protocol.Version) aeadKeys {
	keyLabel := hkdfLabelKeyV1
	ivLabel := hkdfLabelIVV1
	if v == protocol.Version2 {
		keyLabel = hkdfLabelKeyV2
		ivLabel = hkdfLabelIVV2
	}
	return aeadKeys{
		key: hkdfExpandLabel(suite.Hash, trafficSecret, []byte{}, keyLabel, suite.KeyLen),
		iv:  hkdfExpandLabel(suite.Hash, trafficSecret, []byte{}, ivLabel, suite.IVLen()),
	}
}

func createAEAD(suite cipherSuite, trafficSecret []byte, v protocol.Version) cipher.AEAD {
	keys := deriveAEADKeys(suite, trafficSecret, v)
	return suite.AEAD(keys.key, keys.iv)
}

type longHeaderSealer struct {
	aead            cipher.AEAD
	headerProtector headerProtector
	nonceBuf        [8]byte
}

var _ LongHeaderSealer = &longHeaderSealer{}

func newLongHeaderSealer(aead cipher.AEAD, headerProtector headerProtector) LongHeaderSealer {
	if aead.NonceSize() != 8 {
		panic("unexpected nonce size")
	}
	return &longHeaderSealer{
		aead:            aead,
		headerProtector: headerProtector,
	}
}

func (s *longHeaderSealer) Seal(dst, src []byte, pn protocol.PacketNumber, ad []byte) []byte {
	binary.BigEndian.PutUint64(s.nonceBuf[:], uint64(pn))
	return s.aead.Seal(dst, s.nonceBuf[:], src, ad)
}

func (s *longHeaderSealer) EncryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	s.headerProtector.EncryptHeader(sample, firstByte, pnBytes)
}

func (s *longHeaderSealer) Overhead() int {
	return s.aead.Overhead()
}

type longHeaderOpener struct {
	aead            cipher.AEAD
	headerProtector headerProtector
	highestRcvdPN   protocol.PacketNumber // highest packet number received (which could be successfully unprotected)

	// use a single array to avoid allocations
	nonceBuf [8]byte
}

var _ LongHeaderOpener = &longHeaderOpener{}

func newLongHeaderOpener(aead cipher.AEAD, headerProtector headerProtector) LongHeaderOpener {
	if aead.NonceSize() != 8 {
		panic("unexpected nonce size")
	}
	return &longHeaderOpener{
		aead:            aead,
		headerProtector: headerProtector,
	}
}

// continuePacketNumberSpace is used when the Initial keys change during compatible version negotiation (RFC 9368).
// The packet number space of the Initial packets continues, so the packet numbers received with the new keys are
// decoded relative to the largest packet number received with the previous keys (section 17.1 of RFC 9000):
// a peer might use large packet numbers, and encode them in fewer bytes.
func continuePacketNumberSpace(opener LongHeaderOpener, prev ...LongHeaderOpener) {
	o, ok := opener.(*longHeaderOpener)
	if !ok {
		return
	}
	for _, p := range prev {
		if p, ok := p.(*longHeaderOpener); ok && p != nil {
			o.highestRcvdPN = max(o.highestRcvdPN, p.highestRcvdPN)
		}
	}
}

func (o *longHeaderOpener) DecodePacketNumber(wirePN protocol.PacketNumber, wirePNLen protocol.PacketNumberLen) protocol.PacketNumber {
	return protocol.DecodePacketNumber(wirePNLen, o.highestRcvdPN, wirePN)
}

func (o *longHeaderOpener) Open(dst, src []byte, pn protocol.PacketNumber, ad []byte) ([]byte, error) {
	binary.BigEndian.PutUint64(o.nonceBuf[:], uint64(pn))
	dec, err := o.aead.Open(dst, o.nonceBuf[:], src, ad)
	if err == nil {
		o.highestRcvdPN = max(o.highestRcvdPN, pn)
	} else {
		err = ErrDecryptionFailed
	}
	return dec, err
}

func (o *longHeaderOpener) DecryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	o.headerProtector.DecryptHeader(sample, firstByte, pnBytes)
}
