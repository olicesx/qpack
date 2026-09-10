package interop

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/olicesx/qpack"

	"github.com/stretchr/testify/require"
)

type request struct {
	headers []qpack.HeaderField
}

type qif struct {
	requests []request
}

var qifs map[string]qif

func init() {
	qifs = make(map[string]qif)
	readQIFs()
}

func readQIFs() {
	qifDir := currentDir() + "/qifs/qifs"
	if err := filepath.Walk(qifDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		_, filename := filepath.Split(path)
		name := filename[:len(filename)-len(filepath.Ext(filename))]
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		requests := parseRequests(file)
		qifs[name] = qif{requests: requests}
		return nil
	}); err != nil {
		log.Fatal(err)
	}
}

func parseRequests(r io.Reader) []request {
	lr := bufio.NewReader(r)
	var reqs []request
	for {
		headers, done := parseRequest(lr)
		if done {
			break
		}
		reqs = append(reqs, request{headers})
	}
	return reqs
}

func parseRequest(lr *bufio.Reader) (headers []qpack.HeaderField, done bool) {
	for {
		line, isPrefix, err := lr.ReadLine()
		if err == io.EOF {
			return headers, true
		}
		if err != nil {
			return nil, true
		}
		if isPrefix {
			return nil, true
		}
		if len(line) == 0 {
			break
		}
		split := strings.Split(string(line), "\t")
		if len(split) != 1 && len(split) != 2 {
			return nil, true
		}
		name := split[0]
		var val string
		if len(split) == 2 {
			val = split[1]
		}
		headers = append(headers, qpack.HeaderField{Name: name, Value: val})
	}
	return headers, false
}

func currentDir() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("Failed to get current frame")
	}
	return path.Dir(filename)
}

func findFiles() []string {
	var files []string
	encodedDir := currentDir() + "/qifs/encoded/qpack-06/"
	filepath.Walk(encodedDir, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		_, file := filepath.Split(path)
		if file == "draft-examples.out" {
			return nil
		}
		split := strings.Split(file, ".")
		tableSize := split[len(split)-3]
		if tableSize == "0" {
			files = append(files, path)
		}
		return nil
	})
	return files
}

// errorCorpusKinds is the golden classification of the QIF error corpus
// (interop/qifs/encoded/errors). A zero kind means that the payload is a valid
// field section, which is the case for err9 and err10.
var errorCorpusKinds = map[string]qpack.DecoderErrorKind{
	"err1":  qpack.DecoderErrorMalformed,        // truncated indexed field
	"err2":  qpack.DecoderErrorMalformed,        // missing delta base
	"err3":  qpack.DecoderErrorMalformed,        // truncated delta base
	"err4":  qpack.DecoderErrorInvalidBase,      // delta base with sign bit set
	"err5":  qpack.DecoderErrorInvalidReference, // literal field referencing the dynamic table
	"err6":  qpack.DecoderErrorMalformed,        // truncated name length
	"err7":  qpack.DecoderErrorMalformed,        // truncated value length
	"err8":  qpack.DecoderErrorInvalidReference, // indexed field referencing the dynamic table
	"err9":  0,                                  // valid field section
	"err10": 0,                                  // valid field section
	"err11": qpack.DecoderErrorInvalidRequiredInsertCount,
	"err12": qpack.DecoderErrorInvalidRequiredInsertCount,
}

func TestInteropErrorCorpus(t *testing.T) {
	dir := currentDir() + "/qifs/encoded/errors"
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, len(errorCorpusKinds))

	seen := make(map[string]bool)
	for _, entry := range entries {
		name := entry.Name()
		kind, ok := errorCorpusKinds[name]
		require.True(t, ok, "unexpected file in the error corpus: %s", name)
		seen[name] = true

		t.Run(name, func(t *testing.T) {
			require.False(t, entry.IsDir())
			raw, err := os.ReadFile(filepath.Join(dir, name))
			require.NoError(t, err)

			// test framework invariants: 8 byte stream ID, 4 byte payload length
			require.GreaterOrEqual(t, len(raw), 12)
			streamID := binary.BigEndian.Uint64(raw[:8])
			length := binary.BigEndian.Uint32(raw[8:12])
			require.LessOrEqual(t, length, uint32(1<<15))
			require.NotZero(t, length)
			require.Equal(t, 12+int(length), len(raw))
			t.Logf("stream ID %d, payload length %d", streamID, length)

			decoder := qpack.NewDecoder()
			decode := decoder.Decode(raw[12:])
			var headers []qpack.HeaderField
			var decodeErr error
			for {
				hf, err := decode()
				if err != nil {
					decodeErr = err
					break
				}
				headers = append(headers, hf)
			}

			if kind == 0 {
				require.ErrorIs(t, decodeErr, io.EOF)
				require.NotEmpty(t, headers)
				return
			}
			require.Error(t, decodeErr)
			var decoderErr *qpack.DecoderError
			require.ErrorAs(t, decodeErr, &decoderErr)
			require.Equal(t, kind, decoderErr.Kind)
		})
	}
	for name := range errorCorpusKinds {
		require.True(t, seen[name], "missing file in the error corpus: %s", name)
	}
}

func parseInput(r io.Reader) (uint64, []byte) {
	prefix := make([]byte, 12)
	if _, err := io.ReadFull(r, prefix); err != nil {
		return 0, nil
	}
	streamID := binary.BigEndian.Uint64(prefix[:8])
	length := binary.BigEndian.Uint32(prefix[8:12])
	if length > 1<<15 {
		return 0, nil
	}
	data := make([]byte, int(length))
	if _, err := io.ReadFull(r, data); err != nil {
		return 0, nil
	}
	return streamID, data
}

func TestInteropDecodingEncodedFiles(t *testing.T) {
	filenames := findFiles()
	for _, path := range filenames {
		fpath, filename := filepath.Split(path)
		prettyPath := path[len(filepath.Dir(filepath.Dir(filepath.Dir(fpath))))+1:]

		t.Run(fmt.Sprintf("Decoding_%s", prettyPath), func(t *testing.T) {
			qif, ok := qifs[strings.Split(filename, ".")[0]]
			require.True(t, ok)

			file, err := os.Open(path)
			require.NoError(t, err)
			defer file.Close()

			var numRequests, numHeaderFields int
			require.NotEmpty(t, qif.requests)

			decoder := qpack.NewDecoder()

			for _, req := range qif.requests {
				_, data := parseInput(file)
				require.NotNil(t, data)

				var headers []qpack.HeaderField
				decode := decoder.Decode(data)
				for {
					hf, err := decode()
					if err == io.EOF {
						break
					}
					require.NoError(t, err)
					headers = append(headers, hf)
				}

				require.Equal(t, req.headers, headers)

				numRequests++
				numHeaderFields += len(headers)
			}

			t.Logf("Decoded %d requests containing %d header fields.", len(qif.requests), numHeaderFields)
		})
	}
}
