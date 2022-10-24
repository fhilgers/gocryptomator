package vault

import (
	"io"
	"io/fs"

	"github.com/fhilgers/gocryptomator/internal/config"
	"github.com/fhilgers/gocryptomator/internal/filename"
	"github.com/fhilgers/gocryptomator/internal/header"
	"github.com/fhilgers/gocryptomator/internal/masterkey"
	"github.com/fhilgers/gocryptomator/internal/path"
	"github.com/fhilgers/gocryptomator/internal/stream"
)

type Vault struct {
	config.Config
	masterkey.MasterKey

	fs fs.FS
}

func (v Vault) EncryptFileName(name, dirID string) (string, error) {
	return filename.Encrypt(name, dirID, v.EncryptKey, v.MacKey)
}

func (v Vault) DecryptFileName(name, dirID string) (string, error) {
	return filename.Decrypt(name, dirID, v.EncryptKey, v.MacKey)
}

func (v Vault) PathFromDirID(dirID string) (string, error) {
	return path.FromDirID(dirID, v.EncryptKey, v.MacKey)
}

func (v Vault) ResolveFilePath(filepath string) (string, error) {
	return path.Resolve(v.fs, filepath, v.EncryptKey, v.MacKey)
}

func (v Vault) NewReader(r io.Reader) (io.Reader, error) {
	h, err := header.Unmarshal(r, v.EncryptKey, v.MacKey)
	if err != nil {
		return nil, err
	}

	return stream.NewReader(r, h.ContentKey, h.Nonce)
}

func (v Vault) NewWriter(w io.Writer) (io.Writer, error) {
	h, err := header.New()
	if err != nil {
		return nil, err
	}

	if err := h.Marshal(w, v.EncryptKey, v.MacKey); err != nil {
		return nil, err
	}

	return stream.NewWriter(w, h.ContentKey, h.Nonce)
}
