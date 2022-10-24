package header

import (
	"io"
)

type FileHeader struct {
	Nonce      []byte
	Reserved   []byte
	ContentKey []byte
}

func New() (FileHeader, error)
func Unmarshal(r io.Reader, encKey, macKey []byte) (FileHeader, error)
func (h FileHeader) Marshal(w io.Writer, encKey, macKey []byte) error
