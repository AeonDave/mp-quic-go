package qerr

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"runtime"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTransportErrorCodeStringer(t *testing.T) {
	_, thisfile, _, ok := runtime.Caller(0)
	require.True(t, ok, "Failed to get current frame")

	filename := path.Join(path.Dir(thisfile), "error_codes.go")
	fileAst, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
	require.NoError(t, err)

	constSpecs := fileAst.Decls[2].(*ast.GenDecl).Specs
	require.Greater(t, len(constSpecs), 4, "Expected more than 4 constants")

	for _, c := range constSpecs {
		valString := c.(*ast.ValueSpec).Values[0].(*ast.BasicLit).Value
		val, err := strconv.ParseInt(valString, 0, 64)
		require.NoError(t, err)
		require.NotEqual(t, "unknown error code", TransportErrorCode(val).String())
	}

	// test that there's a string representation for unknown error codes
	require.Equal(t, "unknown error code: 0x1337", TransportErrorCode(0x1337).String())
}

func TestMultipathTransportErrorCodes(t *testing.T) {
	for _, tc := range []struct {
		code TransportErrorCode
		val  uint64
		str  string
	}{
		{ApplicationAbandonPath, 0x3e, "APPLICATION_ABANDON_PATH"},
		{PathResourceLimitReached, 0x3e75, "PATH_RESOURCE_LIMIT_REACHED"},
		{PathUnstableOrPoor, 0x3e76, "PATH_UNSTABLE_OR_POOR"},
		{NoCIDAvailableForPath, 0x3e77, "NO_CID_AVAILABLE_FOR_PATH"},
	} {
		require.Equal(t, tc.val, uint64(tc.code))
		require.Equal(t, tc.str, tc.code.String())
		require.False(t, tc.code.IsCryptoError())
		require.Equal(t, tc.str+" (local)", (&TransportError{ErrorCode: tc.code}).Error())
	}
}

func TestIsCryptoError(t *testing.T) {
	for i := range 0x100 {
		require.False(t, TransportErrorCode(i).IsCryptoError())
	}
	for i := 0x100; i < 0x200; i++ {
		require.True(t, TransportErrorCode(i).IsCryptoError())
	}
	for i := 0x200; i < 0x300; i++ {
		require.False(t, TransportErrorCode(i).IsCryptoError())
	}
}

func TestVersionNegotiationErrorCode(t *testing.T) {
	// section 10.2 of RFC 9368
	require.Equal(t, uint64(0x11), uint64(VersionNegotiationErrorCode))
	require.Equal(t, "VERSION_NEGOTIATION_ERROR", VersionNegotiationErrorCode.String())
	require.False(t, VersionNegotiationErrorCode.IsCryptoError())
}
