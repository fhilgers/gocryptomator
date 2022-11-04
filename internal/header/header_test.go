package header_test

import (
	"bytes"
	"encoding/binary"
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
	testutils.WithTestdata(t, func(t *testing.T, input encHeader, golden header.FileHeader) {
		buf := bytes.NewBuffer(input.Header)

		h, err := header.Unmarshal(buf, input.EncKey, input.MacKey)
		assert.NoError(t, err)

		assert.Equal(t, golden, h)
	})
}
