package qpack

import (
	"bytes"
	"io"
	"testing"

	"golang.org/x/net/http2/hpack"

	"github.com/stretchr/testify/require"
)

// errWriter wraps bytes.Buffer and optionally fails on every write
// useful for testing misbehaving writers
type errWriter struct {
	bytes.Buffer
	fail bool
}

func (ew *errWriter) Write(b []byte) (int, error) {
	if ew.fail {
		return 0, io.ErrClosedPipe
	}
	return ew.Buffer.Write(b)
}

// partialErrWriter wraps bytes.Buffer, writes half of the data and then fails.
// Network writers commonly fail after a partial write.
type partialErrWriter struct {
	bytes.Buffer
	fail bool
}

func (ew *partialErrWriter) Write(b []byte) (int, error) {
	if ew.fail {
		n := len(b) / 2
		ew.Buffer.Write(b[:n])
		return n, io.ErrClosedPipe
	}
	return ew.Buffer.Write(b)
}

func readPrefix(t *testing.T, data []byte) (rest []byte, requiredInsertCount uint64, deltaBase uint64) {
	var err error
	requiredInsertCount, rest, err = readVarInt(8, data)
	require.NoError(t, err)
	deltaBase, rest, err = readVarInt(7, rest)
	require.NoError(t, err)
	return
}

func checkHeaderField(t *testing.T, data []byte, hf HeaderField) []byte {
	require.Equal(t, uint8(0x20), data[0]&(0x80^0x40^0x20)) // 001xxxxx
	require.NotZero(t, data[0]&0x8)                         // Huffman encoding
	nameLen, data, err := readVarInt(3, data)
	require.NoError(t, err)
	l := hpack.HuffmanEncodeLength(hf.Name)
	require.Equal(t, l, nameLen)
	decodedName, err := hpack.HuffmanDecodeToString(data[:l])
	require.NoError(t, err)
	require.Equal(t, hf.Name, decodedName)
	valueLen, data, err := readVarInt(7, data[l:])
	require.NoError(t, err)
	l = hpack.HuffmanEncodeLength(hf.Value)
	require.Equal(t, l, valueLen)
	decodedValue, err := hpack.HuffmanDecodeToString(data[:l])
	require.NoError(t, err)
	require.Equal(t, hf.Value, decodedValue)
	return data[l:]
}

// Reads one indexed field line representation from data and verifies it matches hf.
// Returns the leftover bytes from data.
func checkIndexedHeaderField(t *testing.T, data []byte, hf HeaderField) []byte {
	require.Equal(t, uint8(1), data[0]>>7) // 1Txxxxxx
	index, data, err := readVarInt(6, data)
	require.NoError(t, err)
	require.Equal(t, hf, staticTableEntries[index])
	return data
}

func checkHeaderFieldWithNameRef(t *testing.T, data []byte, hf HeaderField) []byte {
	// read name reference
	require.Equal(t, uint8(1), data[0]>>6) // 01NTxxxx
	index, data, err := readVarInt(4, data)
	require.NoError(t, err)
	require.Equal(t, hf.Name, staticTableEntries[index].Name)
	// read literal value
	valueLen, data, err := readVarInt(7, data)
	require.NoError(t, err)
	l := hpack.HuffmanEncodeLength(hf.Value)
	require.Equal(t, l, valueLen)
	decodedValue, err := hpack.HuffmanDecodeToString(data[:l])
	require.NoError(t, err)
	require.Equal(t, hf.Value, decodedValue)
	return data[l:]
}

func TestEncoderEncodesSingleField(t *testing.T) {
	output := &errWriter{}
	encoder := NewEncoder(output)

	hf := HeaderField{Name: "foobar", Value: "lorem ipsum"}
	require.NoError(t, encoder.WriteField(hf))

	data, requiredInsertCount, deltaBase := readPrefix(t, output.Bytes())
	require.Zero(t, requiredInsertCount)
	require.Zero(t, deltaBase)

	data = checkHeaderField(t, data, hf)
	require.Empty(t, data)
}

func TestEncoderFailsToEncodeWhenWriterErrs(t *testing.T) {
	output := &errWriter{fail: true}
	encoder := NewEncoder(output)

	hf := HeaderField{Name: "foobar", Value: "lorem ipsum"}
	err := encoder.WriteField(hf)
	require.EqualError(t, err, "io: read/write on closed pipe")
}

// TestEncoderStickyWriteError verifies that a failed write poisons the Encoder:
// subsequent calls return the same error instead of writing a field section
// that's missing its Header Block Prefix. Close resets the Encoder.
func TestEncoderStickyWriteError(t *testing.T) {
	output := &errWriter{fail: true}
	encoder := NewEncoder(output)

	hf := HeaderField{Name: "foobar", Value: "lorem ipsum"}
	require.EqualError(t, encoder.WriteField(hf), "io: read/write on closed pipe")

	output.fail = false
	for i := range 3 {
		err := encoder.WriteField(HeaderField{Name: "raboof", Value: "dolor sit amet"})
		require.EqualError(t, err, "io: read/write on closed pipe", "call %d", i)
	}
	require.Empty(t, output.Bytes())

	require.NoError(t, encoder.Close())
	require.NoError(t, encoder.WriteField(hf))
	data, requiredInsertCount, deltaBase := readPrefix(t, output.Bytes())
	require.Zero(t, requiredInsertCount)
	require.Zero(t, deltaBase)
	require.Empty(t, checkHeaderField(t, data, hf))
}

// TestEncoderStickyWriteErrorAfterPartialWrite verifies that the Encoder also
// stays poisoned after a partial write, where the Writer wrote some bytes
// before returning an error.
func TestEncoderStickyWriteErrorAfterPartialWrite(t *testing.T) {
	output := &partialErrWriter{fail: true}
	encoder := NewEncoder(output)

	require.EqualError(t,
		encoder.WriteField(HeaderField{Name: "foobar", Value: "lorem ipsum"}),
		"io: read/write on closed pipe",
	)
	partialLen := output.Len()
	require.NotZero(t, partialLen)

	// It must not append to the partially written header block,
	// even though the underlying Writer works again.
	output.fail = false
	require.EqualError(t,
		encoder.WriteField(HeaderField{Name: "raboof", Value: "dolor sit amet"}),
		"io: read/write on closed pipe",
	)
	require.Len(t, output.Bytes(), partialLen)

	// After Close, a new header block (including the prefix) is written.
	require.NoError(t, encoder.Close())
	hf := HeaderField{Name: "foobar", Value: "lorem ipsum"}
	require.NoError(t, encoder.WriteField(hf))
	data, requiredInsertCount, deltaBase := readPrefix(t, output.Bytes()[partialLen:])
	require.Zero(t, requiredInsertCount)
	require.Zero(t, deltaBase)
	require.Empty(t, checkHeaderField(t, data, hf))
}

func TestEncoderEncodesMultipleFields(t *testing.T) {
	output := &errWriter{}
	encoder := NewEncoder(output)

	hf1 := HeaderField{Name: "foobar", Value: "lorem ipsum"}
	hf2 := HeaderField{Name: "raboof", Value: "dolor sit amet"}
	require.NoError(t, encoder.WriteField(hf1))
	require.NoError(t, encoder.WriteField(hf2))

	data, requiredInsertCount, deltaBase := readPrefix(t, output.Bytes())
	require.Zero(t, requiredInsertCount)
	require.Zero(t, deltaBase)

	data = checkHeaderField(t, data, hf1)
	data = checkHeaderField(t, data, hf2)
	require.Empty(t, data)
}

func TestEncoderEncodesAllFieldsOfStaticTable(t *testing.T) {
	output := &errWriter{}
	encoder := NewEncoder(output)

	for _, hf := range staticTableEntries {
		require.NoError(t, encoder.WriteField(hf))
	}

	data, requiredInsertCount, deltaBase := readPrefix(t, output.Bytes())
	require.Zero(t, requiredInsertCount)
	require.Zero(t, deltaBase)

	for _, hf := range staticTableEntries {
		data = checkIndexedHeaderField(t, data, hf)
	}
	require.Empty(t, data)
}

func TestEncodeFieldsWithNameReferenceInStaticTable(t *testing.T) {
	output := &errWriter{}
	encoder := NewEncoder(output)

	hf1 := HeaderField{Name: ":status", Value: "666"}
	hf2 := HeaderField{Name: "server", Value: "lorem ipsum"}
	hf3 := HeaderField{Name: ":method", Value: ""}
	require.NoError(t, encoder.WriteField(hf1))
	require.NoError(t, encoder.WriteField(hf2))
	require.NoError(t, encoder.WriteField(hf3))

	data, requiredInsertCount, deltaBase := readPrefix(t, output.Bytes())
	require.Zero(t, requiredInsertCount)
	require.Zero(t, deltaBase)

	data = checkHeaderFieldWithNameRef(t, data, hf1)
	data = checkHeaderFieldWithNameRef(t, data, hf2)
	data = checkHeaderFieldWithNameRef(t, data, hf3)
	require.Empty(t, data)
}

func TestEncodeMultipleRequests(t *testing.T) {
	output := &errWriter{}
	encoder := NewEncoder(output)

	hf1 := HeaderField{Name: "foobar", Value: "lorem ipsum"}
	require.NoError(t, encoder.WriteField(hf1))
	data, requiredInsertCount, deltaBase := readPrefix(t, output.Bytes())
	require.Zero(t, requiredInsertCount)
	require.Zero(t, deltaBase)
	require.Empty(t, checkHeaderField(t, data, hf1))

	output.Reset()
	require.NoError(t, encoder.Close())
	hf2 := HeaderField{Name: "raboof", Value: "dolor sit amet"}
	require.NoError(t, encoder.WriteField(hf2))
	data, requiredInsertCount, deltaBase = readPrefix(t, output.Bytes())
	require.Zero(t, requiredInsertCount)
	require.Zero(t, deltaBase)
	require.Empty(t, checkHeaderField(t, data, hf2))
}
