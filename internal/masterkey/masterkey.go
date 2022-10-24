package masterkey

import "io"

type MasterKey struct {
	EncryptKey []byte
	MacKey     []byte
}

func New() (MasterKey, error)
func (m MasterKey) Marshal(w io.Writer, passphrase string) error
func Unmarshal(r io.Reader, passphrase string) (MasterKey, error)
