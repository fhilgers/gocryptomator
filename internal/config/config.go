package config

import "io"

type Config struct {
	Format              int    `json:"format"`
	ShorteningThreshold int    `json:"shorteningThreshold"`
	Jti                 string `json:"jti"`
	CipherCombo         string `json:"cipherCombo"`
}

func New() Config

func (c Config) Marshal(w io.Writer, encKey, macKey []byte) error

func Unmarshal(r io.Reader, encKey, macKey []byte) (Config, error)
func UnmarshalUnverified(r io.Reader) (Config, error)
