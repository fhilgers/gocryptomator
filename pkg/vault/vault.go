package vault

import (
	"io"
	"path/filepath"

	"github.com/fhilgers/gocryptomator/internal/config"
	"github.com/fhilgers/gocryptomator/internal/constants"
	"github.com/fhilgers/gocryptomator/internal/filename"
	"github.com/fhilgers/gocryptomator/internal/header"
	"github.com/fhilgers/gocryptomator/internal/masterkey"
	"github.com/fhilgers/gocryptomator/internal/path"
	"github.com/fhilgers/gocryptomator/internal/stream"
	"github.com/fhilgers/gocryptomator/pkg/fs"
)

type Vault struct {
	config.Config
	masterkey.MasterKey


  basePath string
	fs fs.Fs
}


func Unlock(f fs.Fs, path, passphrase string) (vault Vault, err error) {

    vault = Vault{
        fs: f,
        basePath: filepath.Join(path, "d"),
    }

    configFile, err := f.Open(filepath.Join(path, constants.ConfigFileName))
    if err != nil {
        return
    }

    vault.Config, err = config.UnmarshalUnverified(configFile)
    if err != nil {
        return
    }

    masterkeyFile, err := f.Open(filepath.Join(path, constants.ConfigMasterkeyFileName))
    if err != nil {
        return
    }

    vault.MasterKey, err = masterkey.Unmarshal(masterkeyFile, passphrase)
    if err != nil {
        return
    }

    if err = vault.Config.Verify(vault.EncryptKey, vault.MacKey); err != nil {
        return 
    }

    return
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

func (v Vault) ResolveDirPath(dirPath, dirID string) (string, string, error) {
    return path.ResolveDirPath(v.fs, v.basePath, dirPath, dirID, v.EncryptKey, v.MacKey)
}

func (v Vault) ResolveFilePath(filepath, dirID string) (string, string, error) {
	return path.ResolveFilePath(v.fs, v.basePath, filepath, dirID, v.EncryptKey, v.MacKey)
}

func (v Vault) NewReader(r io.Reader) (io.Reader, error) {
	h, err := header.Unmarshal(r, v.EncryptKey, v.MacKey)
	if err != nil {
		return nil, err
	}

	return stream.NewReader(r, h.ContentKey, h.Nonce, v.MacKey)
}

func (v Vault) NewWriter(w io.Writer) (io.Writer, error) {
	h, err := header.New()
	if err != nil {
		return nil, err
	}

	if err := h.Marshal(w, v.EncryptKey, v.MacKey); err != nil {
		return nil, err
	}

	return stream.NewWriter(w, h.ContentKey, h.Nonce, v.MacKey)
}
