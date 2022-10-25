package config_test

import (
	"bytes"
	"testing"

	"github.com/fhilgers/gocryptomator/internal/config"
	"github.com/fhilgers/gocryptomator/internal/constants"
	"github.com/fhilgers/gocryptomator/internal/testutils"
	"github.com/stretchr/testify/assert"
	"pgregory.net/rapid"
)

func TestRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		buf := &bytes.Buffer{}

		encKey := testutils.FixedSizeByteArray(constants.MasterEncryptKeySize).Draw(t, "encKey")
		macKey := testutils.FixedSizeByteArray(constants.MasterMacKeySize).Draw(t, "macKey")

		c1, err := config.New(encKey, macKey)
		assert.NoError(t, err)

		err = c1.Marshal(buf, encKey, macKey)
		assert.NoError(t, err)

		c2, err := config.UnmarshalUnverified(buf)
		assert.NoError(t, err)

		assert.Empty(t, buf.Bytes())
		assert.Equal(t, c1, c2)

		err = c2.Verify(encKey, macKey)
		assert.NoError(t, err)
	})
}
