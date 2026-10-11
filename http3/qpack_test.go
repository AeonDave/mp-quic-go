package http3

import (
	"bytes"
	"io"
	"testing"

	"github.com/quic-go/qpack"

	"github.com/stretchr/testify/require"
)

func encodeFieldSection(t testing.TB, fields ...qpack.HeaderField) []byte {
	t.Helper()

	var buf bytes.Buffer
	enc := qpack.NewEncoder(&buf)
	for _, f := range fields {
		require.NoError(t, enc.WriteField(f))
	}
	require.NoError(t, enc.Close())
	return buf.Bytes()
}

func decodeFieldSection(b []byte) error {
	decodeFn := qpack.NewDecoder().Decode(b)
	for {
		_, err := decodeFn()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func TestCheckFieldSection(t *testing.T) {
	valid := encodeFieldSection(t,
		qpack.HeaderField{Name: ":status", Value: "200"},                    // indexed field line
		qpack.HeaderField{Name: "content-type", Value: "foo/bar"},           // literal field line with name reference
		qpack.HeaderField{Name: "foo", Value: "bar"},                        // literal field line with literal name
		qpack.HeaderField{Name: "x-long", Value: string(make([]byte, 300))}, // multi-byte string length
	)
	// the trailing field line references the dynamic table
	validThenDynamic := append(append([]byte{}, valid...), 0x80)

	for _, tc := range []struct {
		name           string
		data           []byte
		connError      bool
		decoderAccepts bool   // the decoder ignores the Sign bit
		normalized     []byte // the field section passed to the decoder, if it differs from data
	}{
		{name: "valid", data: valid},
		{name: "empty field section", data: []byte{0x00, 0x00}},
		{name: "non-zero Base", data: []byte{0x00, 0x05, 0xd9}, normalized: []byte{0x00, 0x00, 0xd9}},
		{name: "multi-byte non-zero Base", data: []byte{0x00, 0x7f, 0x81, 0x01, 0xd9}, normalized: []byte{0x00, 0x00, 0xd9}},
		{name: "non-zero Base, empty field section", data: []byte{0x00, 0x01}, normalized: []byte{0x00, 0x00}},
		{name: "highest static table index", data: []byte{0x00, 0x00, 0xff, 0x23}}, // index 98
		{name: "empty input", data: []byte{}},
		{name: "truncated Required Insert Count", data: []byte{0xff}},
		{name: "missing Base", data: []byte{0x00}},
		{name: "truncated Base", data: []byte{0x00, 0x7f}},
		{name: "truncated field line", data: []byte{0x00, 0x00, 0x52}},
		{name: "truncated literal name", data: []byte{0x00, 0x00, 0x23, 'f', 'o'}},
		{name: "truncated literal value", data: []byte{0x00, 0x00, 0x23, 'f', 'o', 'o', 0x03, 'b'}},
		{name: "index too large to decode", data: []byte{0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}},
		{name: "non-zero Required Insert Count", data: []byte{0x01, 0x00, 0xd1}, connError: true},
		{name: "multi-byte Required Insert Count", data: []byte{0xff, 0x01, 0x00}, connError: true},
		{name: "negative Base", data: []byte{0x00, 0x80, 0xd1}, connError: true, decoderAccepts: true},
		{name: "negative Base, truncated", data: []byte{0x00, 0xff}, connError: true},
		{name: "indexed field line, dynamic table", data: []byte{0x00, 0x00, 0x80}, connError: true},
		{name: "indexed field line, post-Base index", data: []byte{0x00, 0x00, 0x10}, connError: true},
		{name: "literal field line, dynamic table name", data: []byte{0x00, 0x00, 0x40, 0x00}, connError: true},
		{name: "literal field line, post-Base name", data: []byte{0x00, 0x00, 0x00, 0x00}, connError: true},
		{name: "indexed field line, invalid static index", data: []byte{0x00, 0x00, 0xff, 0x24}, connError: true},       // index 99
		{name: "literal field line, invalid static index", data: []byte{0x00, 0x00, 0x5f, 0x54, 0x00}, connError: true}, // index 99
		{name: "dynamic table reference after valid field lines", data: validThenDynamic, connError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fieldSection, err := checkFieldSection(tc.data)
			if !tc.connError {
				require.NoError(t, err)
				if tc.normalized != nil {
					require.Equal(t, tc.normalized, fieldSection)
					// RFC 9204 allows any Base if the dynamic table isn't used, but the decoder doesn't
					require.Error(t, decodeFieldSection(tc.data))
					require.NoError(t, decodeFieldSection(fieldSection))
				} else {
					require.Equal(t, tc.data, fieldSection)
				}
				return
			}
			require.Error(t, err)
			require.Nil(t, fieldSection)
			require.ErrorAs(t, err, new(*qpackConnectionError))
			if tc.decoderAccepts {
				require.NoError(t, decodeFieldSection(tc.data))
			} else {
				require.Error(t, decodeFieldSection(tc.data))
			}
		})
	}

	require.NoError(t, decodeFieldSection(valid))
	require.NoError(t, decodeFieldSection([]byte{0x00, 0x00, 0xff, 0x23}))
}

func FuzzCheckFieldSection(f *testing.F) {
	f.Add(encodeFieldSection(f, qpack.HeaderField{Name: ":path", Value: "/"}, qpack.HeaderField{Name: "foo", Value: "bar"}))
	f.Add([]byte{0x01, 0x00, 0xd1})
	f.Add([]byte{0x00, 0x00, 0x80})
	f.Add([]byte{0x00, 0x00, 0x5f, 0x54, 0x00})
	f.Add([]byte{0x00, 0x80, 0xd1})
	f.Add([]byte{0x00, 0x05, 0xd9})
	f.Fuzz(func(t *testing.T, data []byte) {
		fieldSection, err := checkFieldSection(data)
		if err == nil {
			// A field section that the decoder accepts must still be accepted after rewriting the Base.
			if decodeFieldSection(data) == nil {
				require.NoError(t, decodeFieldSection(fieldSection))
			}
			return
		}
		if decodeFieldSection(data) != nil {
			return
		}
		// Apart from the negative Base, which the decoder doesn't detect since it ignores the Sign bit,
		// a field section that the decoder accepts must never cause the connection to be closed.
		require.Equal(t, "qpack: negative Base", err.Error())
	})
}
