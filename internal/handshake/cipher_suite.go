package handshake

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/fips140"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
)

// These cipher suite implementations are copied from the standard library crypto/tls package.

const aeadNonceLength = 12

// minMultipathNonceLength is the minimum nonce length of an AEAD used with the multipath extension,
// see Section 2.4 of draft-ietf-quic-multipath.
const minMultipathNonceLength = 12

type cipherSuite struct {
	ID       uint16
	Hash     crypto.Hash
	KeyLen   int
	NonceLen int
	AEAD     func(key, nonceMask []byte) cipher.AEAD
}

// IVLen returns the length of the packet protection IV, which is the length of the AEAD nonce.
func (s cipherSuite) IVLen() int { return s.NonceLen }

func getCipherSuite(id uint16) cipherSuite {
	switch id {
	case tls.TLS_AES_128_GCM_SHA256:
		return cipherSuite{ID: tls.TLS_AES_128_GCM_SHA256, Hash: crypto.SHA256, KeyLen: 16, NonceLen: aeadNonceLength, AEAD: aeadAESGCMTLS13}
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		// The usual convention is to only panic on fips140.Enforced (and not on fips140.Enabled),
		// but this function panics in the default case anyway, so we might as well panic here.
		if fips140.Enabled() {
			panic("tls: TLS_CHACHA20_POLY1305_SHA256 is not allowed in FIPS 140-3 mode")
		}
		return cipherSuite{ID: tls.TLS_CHACHA20_POLY1305_SHA256, Hash: crypto.SHA256, KeyLen: 32, NonceLen: aeadNonceLength, AEAD: aeadChaCha20Poly1305}
	case tls.TLS_AES_256_GCM_SHA384:
		return cipherSuite{ID: tls.TLS_AES_256_GCM_SHA384, Hash: crypto.SHA384, KeyLen: 32, NonceLen: aeadNonceLength, AEAD: aeadAESGCMTLS13}
	default:
		panic(fmt.Sprintf("unknown cypher suite: %d", id))
	}
}

// ivForPath returns the IV used to protect the 1-RTT packets sent on a path when the multipath extension is used.
//
// Section 2.4 of draft-ietf-quic-multipath defines the nonce as the IV XORed with the path-and-packet-number:
// the 32-bit path ID, two zero bits and the 62-bit packet number, left-padded with zeros to the length of the IV.
// XORing the path ID into the IV once, and then the packet number into the result for every packet, gives the
// same nonce. The AEADs created with this IV can therefore keep using the packet number as the 8-byte nonce.
// The IV of path 0 is unchanged: its nonce is the nonce defined in RFC 9001.
func ivForPath(iv []byte, pathID protocol.PathID) []byte {
	if pathID == 0 {
		return iv
	}
	if pathID > protocol.MaxPathID {
		panic(fmt.Sprintf("invalid path ID: %d", pathID))
	}
	if len(iv) < minMultipathNonceLength {
		panic(fmt.Sprintf("IV too short for multipath: %d bytes", len(iv)))
	}
	pathIV := make([]byte, len(iv))
	copy(pathIV, iv)
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(pathID))
	pos := len(pathIV) - minMultipathNonceLength
	subtle.XORBytes(pathIV[pos:pos+4], pathIV[pos:pos+4], b[:])
	return pathIV
}

func aeadAESGCMTLS13(key, nonceMask []byte) cipher.AEAD {
	if fips140.Enabled() {
		return aeadAESGCMTLS13FIPS140(key, nonceMask)
	}

	if len(nonceMask) != aeadNonceLength {
		panic("tls: internal error: wrong nonce length")
	}
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	ret := &xorNonceAEAD{aead: aead}
	copy(ret.nonceMask[:], nonceMask)
	return ret
}

func aeadChaCha20Poly1305(key, nonceMask []byte) cipher.AEAD {
	if len(nonceMask) != aeadNonceLength {
		panic("tls: internal error: wrong nonce length")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}

	ret := &xorNonceAEAD{aead: aead}
	copy(ret.nonceMask[:], nonceMask)
	return ret
}

// xorNonceAEAD wraps an AEAD by XORing in a fixed pattern to the nonce
// before each call.
type xorNonceAEAD struct {
	nonceMask [aeadNonceLength]byte
	aead      cipher.AEAD
}

func (f *xorNonceAEAD) NonceSize() int        { return 8 } // 64-bit sequence number
func (f *xorNonceAEAD) Overhead() int         { return f.aead.Overhead() }
func (f *xorNonceAEAD) explicitNonceLen() int { return 0 }

func (f *xorNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	result := f.aead.Seal(out, f.nonceMask[:], plaintext, additionalData)
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}

	return result
}

func (f *xorNonceAEAD) Open(out, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	result, err := f.aead.Open(out, f.nonceMask[:], ciphertext, additionalData)
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}

	return result, err
}
