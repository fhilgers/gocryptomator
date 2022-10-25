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

		encypted_name, err := Encrypt(name, dirID, encKey, macKey)
		assert.NoError(t, err, "encryption error")

		decrypted_name, err := Decrypt(encypted_name, dirID, encKey, macKey)
		assert.NoError(t, err, "decryption error")

		assert.Equal(t, name, decrypted_name)
	})
}
