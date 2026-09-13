package qpack

import (
	"bytes"
	"io"
	"testing"
)

// Fuzz target for the decoder (the repository only ships a go-fuzz entry point,
// which `go test -fuzz` cannot drive). Properties:
//   - decoding arbitrary bytes must never panic,
//   - errors must be terminal for that Decode call (no infinite loop),
//   - every decoded field list must survive a round trip through the encoder.
func FuzzDecoder(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0xd1})
	f.Add([]byte{0x00, 0x00, 0x50, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79})
	f.Add([]byte{0x02, 0x00, 0x80, 0x00})
	f.Add([]byte{0x3f, 0xe1, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0x00, 0x00, 0xc0, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	// A literal field with a name reference and a value (static table index 32,
	// value length 5): the seeded corpus above only decodes pseudo-fields, so
	// without this block the encoder round-trip oracle below is never reached.
	f.Add([]byte{0x00, 0x00, 0x20, 0x05, 'h', 'e', 'l', 'l', 'o'})
	// Two literal fields with indexed names, plus a literal without a name
	// reference, so both encoder paths are exercised by the seeds.
	f.Add([]byte{0x00, 0x00, 0x20, 0x03, 'o', 'n', 'e', 0x25, 0x06, 'a', 'c', 'c', 'e', 'p', 't', 0x00, 0x04, 'x', 'y', 'z', 'w'})
	// A non-empty dynamic-table block with a small capacity, so the
	// dynamic-table paths stay reachable from the seeds.
	f.Add([]byte{0x00, 0x00, 0x3f, 0xe1, 0x02, 0x20, 0x05, 'h', 'e', 'l', 'l', 'o'})
	f.Fuzz(func(t *testing.T, data []byte) {
		decoder := NewDecoder()
		decode := decoder.Decode(data)
		var fields []HeaderField
		for i := 0; ; i++ {
			if i > len(data)+64 {
				t.Fatalf("decoder did not terminate after %d fields for %d bytes", i, len(data))
			}
			hf, err := decode()
			if err == io.EOF {
				break
			}
			if err != nil {
				return
			}
			fields = append(fields, hf)
		}
		if len(fields) == 0 {
			return
		}
		var buf bytes.Buffer
		enc := NewEncoder(&buf)
		for _, hf := range fields {
			if hf.IsPseudo() {
				continue
			}
			if err := enc.WriteField(hf); err != nil {
				return
			}
		}
		reencoded, err := io.ReadAll(&buf)
		if err != nil {
			t.Fatal(err)
		}
		if len(reencoded) == 0 {
			return
		}
		redec := NewDecoder().Decode(reencoded)
		var again []HeaderField
		for {
			hf, err := redec()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("re-decoding our own encoding failed: %v (fields=%v)", err, fields)
			}
			again = append(again, hf)
		}
		var want []HeaderField
		for _, hf := range fields {
			if !hf.IsPseudo() {
				want = append(want, hf)
			}
		}
		if len(again) != len(want) {
			t.Fatalf("round trip changed field count: %d -> %d (fields=%v)", len(want), len(again), fields)
		}
		for i := range want {
			if again[i] != want[i] {
				t.Fatalf("round trip changed field %d: %v -> %v", i, want[i], again[i])
			}
		}
	})
}
