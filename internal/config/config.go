package config

import (
	"fmt"
	"io"
	"strings"

	"github.com/fhilgers/gocryptomator/internal/constants"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

type keyID string

func (kid keyID) Scheme() string {
	return strings.Split(string(kid), ":")[0]
}

func (kid keyID) URI() string {
	return strings.Split(string(kid), ":")[1]
}

type Config struct {
	Format              int    `json:"format"`
	ShorteningThreshold int    `json:"shorteningThreshold"`
	Jti                 string `json:"jti"`
	CipherCombo         string `json:"cipherCombo"`

	KeyID    keyID  `json:"-"`
	rawToken string `json:"-"`
}

func New(encKey, macKey []byte) (c Config, err error) {
	c = Config{
		Format:              constants.ConfigVaultFormat,
		ShorteningThreshold: constants.ConfigShorteningThreshold,
		Jti:                 uuid.NewString(),
		CipherCombo:         constants.ConfigCipherCombo,
		KeyID:               constants.ConfigKeyID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &c)
	token.Header[constants.ConfigKeyIDTag] = string(c.KeyID)

	c.rawToken, err = token.SignedString(append(encKey, macKey...))

	return
}

func (c *Config) Valid() error {
	if c.Format != constants.ConfigVaultFormat {
		return fmt.Errorf("unsupported vault format: %d, wanted: %d", c.Format, constants.ConfigVaultFormat)
	}

	if c.ShorteningThreshold != constants.ConfigShorteningThreshold {
		return fmt.Errorf("unsupported shortening threshold: %d, wanted: %d", c.ShorteningThreshold, constants.ConfigShorteningThreshold)
	}

	if c.CipherCombo != constants.ConfigCipherCombo {
		return fmt.Errorf("unsupported cipher combo: %s, wanted: %s", c.CipherCombo, constants.ConfigCipherCombo)
	}

	return nil
}

func (c Config) Marshal(w io.Writer, encKey, macKey []byte) error {
	_, err := w.Write([]byte(c.rawToken))

	return err
}

func (c Config) Verify(encKey, macKey []byte) error {
	_, err := jwt.Parse(c.rawToken, func(t *jwt.Token) (interface{}, error) {
		return append(encKey, macKey...), nil
	})

	return err
}

func UnmarshalUnverified(r io.Reader) (c Config, err error) {
	tokenBytes, err := io.ReadAll(r)
	if err != nil {
		return
	}

	token, _, err := jwt.NewParser().ParseUnverified(string(tokenBytes), &c)

	if err = token.Claims.Valid(); err != nil {
		return
	}

	c.KeyID = keyID(token.Header[constants.ConfigKeyIDTag].(string))
	c.rawToken = token.Raw

	return
}
