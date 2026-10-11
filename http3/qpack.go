package http3

import "fmt"

// qpackStaticTableSize is the number of entries in the QPACK static table,
// see Appendix A of RFC 9204.
const qpackStaticTableSize = 99

// A qpackConnectionError is a QPACK decoding error that RFC 9204 requires
// to be treated as a connection error of type QPACK_DECOMPRESSION_FAILED.
type qpackConnectionError struct{ msg string }

func (e *qpackConnectionError) Error() string { return "qpack: " + e.msg }

// checkFieldSection checks an encoded field section for errors that must be treated as
// a connection error of type QPACK_DECOMPRESSION_FAILED. We never send
// SETTINGS_QPACK_MAX_TABLE_CAPACITY, so the peer's encoder can't use the dynamic table.
// This makes the following errors:
//   - a non-zero Encoded Required Insert Count (section 4.5.1.1 of RFC 9204),
//   - a Sign bit of 1, which would result in a negative Base (section 4.5.1.2 of RFC 9204),
//   - any reference to the dynamic table (section 2.2.3 of RFC 9204),
//   - an invalid static table index (section 3.1 of RFC 9204).
//
// Other decoding errors, e.g. a truncated field section or a value that is too large to decode,
// are detected by the qpack decoder, and are treated as stream errors (see section 7.4 of RFC 9204).
//
// It returns the field section to pass to the qpack decoder.
// A field section that doesn't reference the dynamic table can use any value for the Base
// (section 4.5.1.2 of RFC 9204), but the decoder only accepts a zero Delta Base.
// If the Delta Base is non-zero, a copy of the field section with a zero Delta Base is returned.
func checkFieldSection(fieldSection []byte) ([]byte, error) {
	ric, b, ok := readQPACKVarInt(8, fieldSection)
	if !ok {
		return fieldSection, nil
	}
	if ric != 0 {
		return nil, &qpackConnectionError{msg: fmt.Sprintf("invalid Required Insert Count: %d", ric)}
	}
	if len(b) == 0 {
		return fieldSection, nil
	}
	if b[0]&0x80 > 0 {
		return nil, &qpackConnectionError{msg: "negative Base"}
	}
	deltaBase, b, ok := readQPACKVarInt(7, b)
	if !ok {
		return fieldSection, nil
	}
	fieldLines := b
	for len(b) > 0 {
		switch {
		case b[0]&0x80 > 0: // 1Txxxxxx: indexed field line
			if b[0]&0x40 == 0 {
				return nil, &qpackConnectionError{msg: "reference to the dynamic table"}
			}
			var index uint64
			index, b, ok = readQPACKVarInt(6, b)
			if !ok {
				return fieldSection, nil
			}
			if index >= qpackStaticTableSize {
				return nil, &qpackConnectionError{msg: fmt.Sprintf("invalid static table index: %d", index)}
			}
		case b[0]&0x40 > 0: // 01NTxxxx: literal field line with name reference
			if b[0]&0x10 == 0 {
				return nil, &qpackConnectionError{msg: "reference to the dynamic table"}
			}
			var index uint64
			index, b, ok = readQPACKVarInt(4, b)
			if !ok {
				return fieldSection, nil
			}
			if index >= qpackStaticTableSize {
				return nil, &qpackConnectionError{msg: fmt.Sprintf("invalid static table index: %d", index)}
			}
			if b, ok = skipQPACKString(7, b); !ok {
				return fieldSection, nil
			}
		case b[0]&0x20 > 0: // 001NHxxx: literal field line with literal name
			if b, ok = skipQPACKString(3, b); !ok {
				return fieldSection, nil
			}
			if b, ok = skipQPACKString(7, b); !ok {
				return fieldSection, nil
			}
		default:
			// 0001xxxx: indexed field line with post-Base index
			// 0000Nxxx: literal field line with post-Base name reference
			return nil, &qpackConnectionError{msg: "reference to the dynamic table"}
		}
	}
	if deltaBase != 0 {
		return append([]byte{0x00, 0x00}, fieldLines...), nil
	}
	return fieldSection, nil
}

// readQPACKVarInt reads an integer with an n-bit prefix, see section 4.1.1 of RFC 9204.
// It uses the same limit for the encoded length as the qpack decoder.
func readQPACKVarInt(n uint8, b []byte) (uint64, []byte, bool) {
	if len(b) == 0 {
		return 0, nil, false
	}
	mask := uint64(1)<<n - 1
	i := uint64(b[0]) & mask
	b = b[1:]
	if i < mask {
		return i, b, true
	}
	for m := 0; len(b) > 0; m += 7 {
		if m >= 63 {
			return 0, nil, false
		}
		c := b[0]
		b = b[1:]
		i += uint64(c&0x7f) << m
		if c&0x80 == 0 {
			return i, b, true
		}
	}
	return 0, nil, false
}

// skipQPACKString skips a string literal with an n-bit prefix, see section 4.1.2 of RFC 9204.
func skipQPACKString(n uint8, b []byte) ([]byte, bool) {
	l, b, ok := readQPACKVarInt(n, b)
	if !ok || uint64(len(b)) < l {
		return nil, false
	}
	return b[l:], true
}
