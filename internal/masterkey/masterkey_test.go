package masterkey_test

import (
	"bytes"
	"testing"

	"github.com/fhilgers/gocryptomator/internal/constants"
	"github.com/fhilgers/gocryptomator/internal/masterkey"
	"github.com/fhilgers/gocryptomator/internal/testutils"
	"github.com/stretchr/testify/assert"
	"pgregory.net/rapid"
)

func TestNew(t *testing.T) {
	k, err := masterkey.New()
	assert.NoError(t, err, "got an error while creating the master key")

	assert.Len(t, k.EncryptKey, constants.MasterEncryptKeySize, "invalid encryption key size")
	assert.Len(t, k.MacKey, constants.MasterMacKeySize, "invalid mac key size")
}

func TestRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		passphrase := rapid.String().Draw(t, "passphrase")

		k1, err := masterkey.New()
		assert.NoError(t, err, "got an error while creating the master key")

		buf := &bytes.Buffer{}

		err = k1.Marshal(buf, passphrase)
		assert.NoError(t, err, "got an error while marshalling")

		assert.NotEmpty(t, buf.Bytes(), "buffer is empty after marshalling")

		k2, err := masterkey.Unmarshal(buf, passphrase)
		assert.NoError(t, err, "got an error while unmarshalling")

		assert.Empty(t, buf.Bytes(), "buffer is not empty after unmarshalling")

		assert.Equal(t, k1, k2)
	})
}

type encKey struct {
	EncryptedMasterKey []byte
	Passphrase         string
}

func TestUnmarshalReference(t *testing.T) {
	testutils.WithTestdata(t, func(t *testing.T, input encKey, golden masterkey.MasterKey) {
		buf := bytes.NewBuffer(input.EncryptedMasterKey)

		h, err := masterkey.Unmarshal(buf, input.Passphrase)
		assert.NoError(t, err)

		assert.Empty(t, buf.Bytes())

		assert.Equal(t, golden, h)
	})
}
