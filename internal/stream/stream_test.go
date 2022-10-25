package stream_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fhilgers/gocryptomator/internal/constants"
	"github.com/fhilgers/gocryptomator/internal/stream"
	"github.com/fhilgers/gocryptomator/internal/testutils"
	"github.com/stretchr/testify/assert"
	"pgregory.net/rapid"
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
	assert.NoError(t, err)

	for _, path := range paths {
		filename := filepath.Base(path)
		testname := strings.TrimSuffix(filename, filepath.Ext(filename))

		input, err := os.ReadFile(path)
		assert.NoError(t, err)

		golden, err := os.ReadFile(filepath.Join("testdata", testname+".golden"))
		assert.NoError(t, err)

		var encFiles map[string]encryptedFile
		json.Unmarshal(input, &encFiles)

		var plainTexts map[string][]byte
		json.Unmarshal(golden, &plainTexts)

		for name, encFile := range encFiles {
			t.Run(fmt.Sprintf("%s:%s", testname, name), func(t *testing.T) {
				buf := bytes.NewBuffer(encFile.Ciphertext)

				r, err := stream.NewReader(buf, encFile.ContentKey, encFile.Nonce, encFile.MacKey)
				assert.NoError(t, err)

				output, err := io.ReadAll(r)
				assert.NoError(t, err)

				assert.Equal(t, plainTexts[name], output)
			})
		}
	}
}



func TestRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		stepSize := rapid.SampledFrom([]int{512, 600, 1000, cs}).Draw(t, "stepSize")
		// Maxlength due to memory problems when using math.MaxInt
		maxLength := 1000000
		length := rapid.IntRange(0, maxLength).Draw(t, "length")

		src := testutils.FixedSizeByteArray(length).Draw(t, "src")
		contentKey := testutils.FixedSizeByteArray(constants.HeaderContentKeySize).Draw(t, "contentKey")
		macKey := testutils.FixedSizeByteArray(constants.MasterMacKeySize).Draw(t, "macKey")
		nonce := testutils.FixedSizeByteArray(constants.HeaderNonceSize).Draw(t, "nonce")

		buf := &bytes.Buffer{}

		w, err := stream.NewWriter(buf, contentKey, nonce, macKey)
		assert.NoError(t, err)

		n := 0
		for n < length {
			b := length - n
			if b > stepSize {
				b = stepSize
			}

			nn, err := w.Write(src[n : n+b])
			assert.NoError(t, err)
			assert.Equal(t, b, nn, "wrong number of bytes written")

			n += nn

			nn, err = w.Write(src[n:n])
			assert.NoError(t, err)
			assert.Zero(t, nn, "more than 0 bytes written")
		}

		err = w.Close()
		assert.NoError(t, err, "close returned an error")

		t.Logf("buffer size: %d", buf.Len())

		r, err := stream.NewReader(buf, contentKey, nonce, macKey)
		assert.NoError(t, err)

		n = 0
		readBuf := make([]byte, stepSize)
		for n < length {
			nn, err := r.Read(readBuf)
			assert.NoErrorf(t, err, "read error at index %d", n)

			assert.Equalf(t, readBuf[:nn], src[n:n+nn], "wrong data at indexes %d - %d", n, n+nn)

			n += nn
		}
	})
}

