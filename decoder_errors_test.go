package qpack

import (
	"encoding/hex"
	"io"
	"testing"

	"golang.org/x/net/http2/hpack"

	"github.com/stretchr/testify/require"
)

// The payloads below are copied from the QIF error corpus
// (interop/qifs/encoded/errors/err1 ... err12), with the 12 byte test
// framework prefix (8 byte stream ID, 4 byte length) stripped off.
// They are inlined on purpose: the root package must not read the qifs
// submodule, which isn't part of the module zip.
//
// err9 and err10 are valid field sections, all other payloads are invalid.
func TestDecoderQIFErrorCorpus(t *testing.T) {
	tests := []struct {
		name     string
		payload  string // hex encoded
		expected string // empty if the payload is a valid field section
		kind     DecoderErrorKind
		fields   []HeaderField
	}{
		{
			name:     "err1: truncated indexed field",
			payload:  "ff",
			expected: "unexpected EOF",
			kind:     DecoderErrorMalformed,
		},
		{
			name:     "err2: no delta base",
			payload:  "00",
			expected: "unexpected EOF",
			kind:     DecoderErrorMalformed,
		},
		{
			name:     "err3: truncated delta base",
			payload:  "00ff",
			expected: "unexpected EOF",
			kind:     DecoderErrorMalformed,
		},
		{
			name:     "err4: delta base with sign bit set",
			payload:  "0081",
			expected: "invalid Base: sign bit set with a Required Insert Count of 0",
			kind:     DecoderErrorInvalidBase,
		},
		{
			name:     "err5: literal field referencing the dynamic table",
			payload:  "000041",
			expected: "no dynamic table",
			kind:     DecoderErrorInvalidReference,
		},
		{
			name:     "err6: truncated name length",
			payload:  "000027",
			expected: "unexpected EOF",
			kind:     DecoderErrorMalformed,
		},
		{
			name:     "err7: truncated value length",
			payload:  "000051ff",
			expected: "unexpected EOF",
			kind:     DecoderErrorMalformed,
		},
		{
			name:     "err8: indexed field referencing the dynamic table",
			payload:  "0000bf",
			expected: "no dynamic table",
			kind:     DecoderErrorInvalidReference,
		},
		{
			name:    "err9: valid indexed field",
			payload: "0000c0",
			fields:  []HeaderField{{Name: ":authority"}},
		},
		{
			name:    "err10: valid indexed field",
			payload: "0000fe",
			fields:  []HeaderField{{Name: "x-xss-protection", Value: "1; mode=block"}},
		},
		{
			name:     "err11: non-zero required insert count",
			payload:  "01",
			expected: "expected Required Insert Count to be zero",
			kind:     DecoderErrorInvalidRequiredInsertCount,
		},
		{
			name:     "err12: oversized required insert count",
			payload:  "ff80ffffffff01",
			expected: "expected Required Insert Count to be zero",
			kind:     DecoderErrorInvalidRequiredInsertCount,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := hex.DecodeString(tt.payload)
			require.NoError(t, err)

			dec := NewDecoder()
			decode := dec.Decode(payload)
			var fields []HeaderField
			for {
				hf, err := decode()
				if err != nil {
					if tt.expected == "" {
						require.ErrorIs(t, err, io.EOF)
					} else {
						require.EqualError(t, err, tt.expected)
						var decoderErr *DecoderError
						require.ErrorAs(t, err, &decoderErr)
						require.Equal(t, tt.kind, decoderErr.Kind)
					}
					break
				}
				fields = append(fields, hf)
			}
			require.Equal(t, tt.fields, fields)
		})
	}
}

// TestDecoderTruncatedStringIsMalformed locks in the classification of a
// truncated string literal: it is reported as Malformed, i.e. a connection
// error at the HTTP/3 layer. See the documentation of readString.
func TestDecoderTruncatedStringIsMalformed(t *testing.T) {
	// literal field without name reference: name "a", value length 5, but only
	// one byte of the value is present
	data := []byte{0x00, 0x00, 0x21, 'a', 0x05, 'b'}
	dec := NewDecoder()
	_, err := dec.Decode(data)()
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	var decoderErr *DecoderError
	require.ErrorAs(t, err, &decoderErr)
	require.Equal(t, DecoderErrorMalformed, decoderErr.Kind)
}

// TestDecoderOversizedStringLengthIsValueTooLarge locks in the classification
// of a string literal length that overflows the varint encoding: it is reported
// as ValueTooLarge, the only error kind that's exempt from being a connection
// error at the HTTP/3 layer.
func TestDecoderOversizedStringLengthIsValueTooLarge(t *testing.T) {
	// literal field without name reference: name "a", followed by a value
	// length that overflows the 7 bit prefix varint encoding
	data := make([]byte, 0, 15)
	data = append(data, 0x00, 0x00, 0x21, 'a', 0x7f)
	for range 10 {
		data = append(data, 0x80)
	}
	dec := NewDecoder()
	_, err := dec.Decode(data)()
	require.ErrorIs(t, err, errVarintOverflow)
	var decoderErr *DecoderError
	require.ErrorAs(t, err, &decoderErr)
	require.Equal(t, DecoderErrorValueTooLarge, decoderErr.Kind)
}

// TestDecoderInvalidHuffmanEncoding verifies that invalid Huffman-encoded data
// is reported as Malformed, i.e. a connection error at the HTTP/3 layer.
func TestDecoderInvalidHuffmanEncoding(t *testing.T) {
	// literal field without name reference: name "a" (not Huffman encoded), and
	// a Huffman encoded value consisting of the invalid EOS symbol
	data := appendVarInt(nil, 3, 1)
	data[0] ^= 0x20 ^ 0x8
	data = append(data, 'a')
	data = appendVarInt(data, 7, 4)
	data[len(data)-1] ^= 0x80
	data = append(data, 0xff, 0xff, 0xff, 0xff)

	dec := NewDecoder()
	_, err := dec.Decode(insertPrefix(data))()
	require.ErrorIs(t, err, hpack.ErrInvalidHuffman)
	var decoderErr *DecoderError
	require.ErrorAs(t, err, &decoderErr)
	require.Equal(t, DecoderErrorMalformed, decoderErr.Kind)
}

// TestDecoderInvalidNameReferenceIndex verifies that a literal field
// referencing a non-existent static table entry (name reference) is reported
// as InvalidReference, i.e. a connection error at the HTTP/3 layer.
func TestDecoderInvalidNameReferenceIndex(t *testing.T) {
	// 01NTxxxx, with N = 0, T = 1 (static table) and index 99,
	// one past the end of the static table
	data := appendVarInt(nil, 4, uint64(len(staticTableEntries)))
	data[0] ^= 0x40 | 0x10

	dec := NewDecoder()
	_, err := dec.Decode(insertPrefix(data))()
	require.EqualError(t, err, "invalid indexed representation index 99")
	var decoderErr *DecoderError
	require.ErrorAs(t, err, &decoderErr)
	require.Equal(t, DecoderErrorInvalidReference, decoderErr.Kind)
}
