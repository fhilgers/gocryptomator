package stream_test

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fhilgers/gocryptomator/internal/constants"
	"github.com/fhilgers/gocryptomator/internal/stream"
)

const cs = constants.ChunkPayloadSize

type encryptedFile struct {
	ContentKey []byte
	Nonce      []byte
	MacKey     []byte
	Ciphertext []byte
}

func TestDecryptReference(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("testdata", "*.input"))
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range paths {
		filename := filepath.Base(path)
		testname := strings.TrimSuffix(filename, filepath.Ext(filename))

		input, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}

		golden, err := os.ReadFile(filepath.Join("testdata", testname+".golden"))
		if err != nil {
			t.Fatal(err)
		}

		var encFiles map[string]encryptedFile
		json.Unmarshal(input, &encFiles)

		var plainTexts map[string][]byte
		json.Unmarshal(golden, &plainTexts)

		for name, encFile := range encFiles {
			t.Run(fmt.Sprintf("%s:%s", testname, name), func(t *testing.T) {
				buf := bytes.NewBuffer(encFile.Ciphertext)

				r, err := stream.NewReader(buf, encFile.ContentKey, encFile.Nonce, encFile.MacKey)
				if err != nil {
					t.Fatal(err)
				}

				output, err := io.ReadAll(r)
				if err != nil {
					t.Fatal(err)
				}

				if !bytes.Equal(output, plainTexts[name]) {
					t.Errorf("\n==== got:\n%s\n==== want:\n%s\n", output, plainTexts[name])
				}
			})
		}
	}
}

func TestRoundTrip(t *testing.T) {
	for _, stepSize := range []int{512, 600, 1000, cs} {
		for _, length := range []int{0, 1000, cs, cs + 100} {
			t.Run(fmt.Sprintf("len=%d,step=%d", length, stepSize),
				func(t *testing.T) { testRoundTrip(t, stepSize, length) })
		}
	}
}

func testRoundTrip(t *testing.T, stepSize, length int) {
	src := make([]byte, length)
	if _, err := rand.Read(src); err != nil {
		t.Fatal(err)
	}
	buf := &bytes.Buffer{}
	contentKey := make([]byte, constants.HeaderContentKeySize)
	if _, err := rand.Read(contentKey); err != nil {
		t.Fatal(err)
	}
	macKey := make([]byte, constants.MasterMacKeySize)
	if _, err := rand.Read(macKey); err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, constants.HeaderNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	w, err := stream.NewWriter(buf, contentKey, nonce, macKey)
	if err != nil {
		t.Fatal(err)
	}

	var n int
	for n < length {
		b := length - n
		if b > stepSize {
			b = stepSize
		}
		nn, err := w.Write(src[n : n+b])
		if err != nil {
			t.Fatal(err)
		}
		if nn != b {
			t.Errorf("Write returned %d, expected %d", nn, b)
		}
		n += nn

		nn, err = w.Write(src[n:n])
		if err != nil {
			t.Fatal(err)
		}
		if nn != 0 {
			t.Errorf("Write returned %d, expected 0", nn)
		}
	}

	if err := w.Close(); err != nil {
		t.Error("Close returned an error:", err)
	}

	t.Logf("buffer size: %d", buf.Len())

	r, err := stream.NewReader(buf, contentKey, nonce, macKey)
	if err != nil {
		t.Fatal(err)
	}

	n = 0
	readBuf := make([]byte, stepSize)
	for n < length {
		nn, err := r.Read(readBuf)
		if err != nil {
			t.Fatalf("Read error at index %d: %v", n, err)
		}

		if !bytes.Equal(readBuf[:nn], src[n:n+nn]) {
			t.Errorf("wrong data at indexes %d - %d", n, n+nn)
		}

		n += nn
	}
}
