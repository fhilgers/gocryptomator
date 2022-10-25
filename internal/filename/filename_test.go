package filename

import (
	"testing"

	"github.com/fhilgers/gocryptomator/internal/constants"
	"github.com/fhilgers/gocryptomator/internal/testutils"
	"github.com/stretchr/testify/assert"
	"pgregory.net/rapid"
)

func TestEncryptDecrypt(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		name := rapid.String().Draw(t, "name")
		dirID := rapid.String().Draw(t, "dirID")

		encKey := testutils.FixedSizeByteArray(constants.MasterEncryptKeySize).Draw(t, "encKey")
		macKey := testutils.FixedSizeByteArray(constants.MasterMacKeySize).Draw(t, "macKey")

		encName, err := Encrypt(name, dirID, encKey, macKey)
		assert.NoError(t, err, "encryption error")

		decName, err := Decrypt(encName, dirID, encKey, macKey)
		assert.NoError(t, err, "decryption error")

		assert.Equal(t, name, decName)
	})
}
