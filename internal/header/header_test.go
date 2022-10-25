package header_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fhilgers/gocryptomator/internal/constants"
	"github.com/fhilgers/gocryptomator/internal/header"
	"github.com/fhilgers/gocryptomator/internal/testutils"
	"github.com/stretchr/testify/assert"
	"pgregory.net/rapid"
)

func TestNew(t *testing.T) {
	h, err := header.New()
	assert.NoError(t, err)

	assert.Len(t, h.Nonce, constants.HeaderNonceSize)
	assert.Len(t, h.ContentKey, constants.HeaderContentKeySize)
	assert.Len(t, h.Reserved, constants.HeaderReservedSize)

	assert.Equal(t, constants.HeaderReservedValue, binary.BigEndian.Uint64(h.Reserved))
}

func TestRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		buf := &bytes.Buffer{}

		encKey := testutils.FixedSizeByteArray(constants.MasterEncryptKeySize).Draw(t, "encKey")
		macKey := testutils.FixedSizeByteArray(constants.MasterMacKeySize).Draw(t, "macKey")

		h1, err := header.New()
		assert.NoError(t, err)

		err = h1.Marshal(buf, encKey, macKey)
		assert.NoError(t, err)

		h2, err := header.Unmarshal(buf, encKey, macKey)
		assert.NoError(t, err)

		assert.Equal(t, h1, h2)
	})
}

type encHeader struct {
	Header []byte
	EncKey []byte
	MacKey []byte
}

func TestUnmarshalReference(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("testdata", "*.input"))
	assert.NoError(t, err)

	for _, path := range paths {
		filename := filepath.Base(path)
		testname := strings.TrimSuffix(filename, filepath.Ext(filename))

		input, err := os.ReadFile(path)
		assert.NoError(t, err)

		golden, err := os.ReadFile(filepath.Join("testdata", testname+".golden"))
		assert.NoError(t, err)

		var encHeaders map[string]encHeader
		err = json.Unmarshal(input, &encHeaders)
		assert.NoError(t, err)

		var headers map[string]header.FileHeader
		err = json.Unmarshal(golden, &headers)
		assert.NoError(t, err)

		for name, encHeader := range encHeaders {
			t.Run(fmt.Sprintf("%s:%s", testname, name), func(t *testing.T) {
				buf := bytes.NewBuffer(encHeader.Header)

				h, err := header.Unmarshal(buf, encHeader.EncKey, encHeader.MacKey)
				assert.NoError(t, err)

				assert.Equal(t, headers[name], h)
			})
		}
	}
}
