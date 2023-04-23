package vault

import (
	"bytes"
	"fmt"
	"io"
	gopath "path"
	"strings"
	"sync"

	"github.com/fhilgers/gocryptomator/internal/config"
	"github.com/fhilgers/gocryptomator/internal/constants"
	"github.com/fhilgers/gocryptomator/internal/filename"
	"github.com/fhilgers/gocryptomator/internal/header"
	"github.com/fhilgers/gocryptomator/internal/masterkey"
	"github.com/fhilgers/gocryptomator/internal/path"
	"github.com/fhilgers/gocryptomator/internal/stream"
	"github.com/google/uuid"

	"github.com/orcaman/concurrent-map/v2"
)

const (
	PathSeparator = "/"
	RootDirID     = ""
	DataDir       = "d"
)

type Fs interface {
	// Open file for reading
	Open(name string) (io.ReadCloser, error)

	// Create a new file and write the content to it, fail if already exists
	WriteString(name, content string) error

	// Remove dir, error if not exists, error if not empty
	RemoveDir(name string) error

	// Remove a file, error if not exists
	RemoveFile(name string) error

	// Make a dir with all parents, dont error if exists
	MkdirAll(name string) error
}

type cacheEntry struct {
	DirID string
}

type Vault struct {
	config.Config
	masterkey.MasterKey

	fs Fs

	mkDirLock cmap.ConcurrentMap[string, *sync.Mutex]
	cache     cmap.ConcurrentMap[string, cacheEntry]
}

func Open(fs Fs, passphrase string) (vault *Vault, err error) {
	vault = &Vault{
		fs:        fs,
		cache:     cmap.New[cacheEntry](),
		mkDirLock: cmap.New[*sync.Mutex](),
	}

	configReader, err := fs.Open(constants.ConfigFileName)
	if err != nil {
		return
	}
	defer configReader.Close()

	if vault.Config, err = config.UnmarshalUnverified(configReader); err != nil {
		return
	}

	masterKeyReader, err := fs.Open(constants.ConfigMasterkeyFileName)
	if err != nil {
		return
	}
	defer masterKeyReader.Close()

	if vault.MasterKey, err = masterkey.Unmarshal(masterKeyReader, passphrase); err != nil {
		return
	}

	if err = vault.Config.Verify(vault.EncryptKey, vault.MacKey); err != nil {
		return
	}

	return
}

func Create(fs Fs, passphrase string) (vault *Vault, err error) {
	vault = &Vault{
		fs:        fs,
		cache:     cmap.New[cacheEntry](),
		mkDirLock: cmap.New[*sync.Mutex](),
	}

	if vault.MasterKey, err = masterkey.New(); err != nil {
		return
	}

	masterKeyWriter := new(bytes.Buffer)
	if err = vault.MasterKey.Marshal(masterKeyWriter, passphrase); err != nil {
		return
	}

	if err = vault.fs.WriteString(constants.ConfigMasterkeyFileName, masterKeyWriter.String()); err != nil {
		return
	}

	if vault.Config, err = config.New(vault.EncryptKey, vault.MacKey); err != nil {
		return
	}

	configWriter := new(bytes.Buffer)
	if err = vault.Config.Marshal(configWriter, vault.EncryptKey, vault.MacKey); err != nil {
		return
	}

	if err = vault.fs.WriteString(constants.ConfigFileName, configWriter.String()); err != nil {
		return
	}

	if err = vault.Config.Verify(vault.EncryptKey, vault.MacKey); err != nil {
		return
	}

	return
}

func (v *Vault) MkRootDir() (err error) {
	dirPath, err := path.FromDirID(RootDirID, v.EncryptKey, v.MacKey)
	if err != nil {
		return
	}

	return v.fs.MkdirAll(gopath.Join(DataDir, dirPath))
}

func (v *Vault) Mkdir(name string) (err error) {
	cleanName := cleanPath(name)

	mu, ok := v.mkDirLock.Get(cleanName)
	if !ok {
		mu = new(sync.Mutex)
		v.mkDirLock.Set(cleanName, mu)
	}
	mu.Lock()
	defer mu.Unlock()

	if _, err = v.GetDirID(cleanName); err == nil {
		return nil
	}

	parent, dir := gopath.Split(cleanName)

	if dir == "" {
		return nil
	}

	if err = v.MkRootDir(); err != nil {
		return
	}

	parentID, err := v.GetDirID(parent)
	if err != nil {
		return
	}

	parentPath, err := path.FromDirID(parentID, v.EncryptKey, v.MacKey)
	if err != nil {
		return
	}

	encDirName, err := filename.Encrypt(dir, parentID, v.EncryptKey, v.MacKey)
	if err != nil {
		return
	}

	if err = v.fs.MkdirAll(gopath.Join(DataDir, parentPath, encDirName)); err != nil {
		return
	}

	dirID := uuid.NewString()
	err = v.writeDirIDToPath(gopath.Join(DataDir, parentPath, encDirName, constants.DirFile), dirID)
	if err != nil {
		return
	}

	v.cache.Set(cleanName, cacheEntry{
		DirID: dirID,
	})

	dirPath, err := path.FromDirID(dirID, v.EncryptKey, v.MacKey)
	if err != nil {
		return
	}

	if err = v.fs.MkdirAll(gopath.Join(DataDir, dirPath)); err != nil {
		return
	}

	if err = v.writeDirIDToPathEncrypted(gopath.Join(DataDir, dirPath, "dirid.c9r"), dirID); err != nil {
		return err
	}

	return nil
}

func (v *Vault) Rmdir(name string) (err error) {
	cleanName := cleanPath(name)

	parent, dir := gopath.Split(cleanName)

	if dir == "" {
		return nil
	}

	parentID, err := v.GetDirID(parent)
	if err != nil {
		return
	}

	dirID, _, err := v.getDirSegmentID(dir, parentID)
	if err != nil {
		return
	}

	v.cache.Remove(cleanName)

	parentPath, err := path.FromDirID(parentID, v.EncryptKey, v.MacKey)
	if err != nil {
		return
	}

	dirPath, err := path.FromDirID(dirID, v.EncryptKey, v.MacKey)
	if err != nil {
		return
	}

	encDirName, err := filename.Encrypt(dir, parentID, v.EncryptKey, v.MacKey)
	if err != nil {
		return
	}

	if err = v.fs.RemoveFile(gopath.Join(DataDir, dirPath, "dirid.c9r")); err != nil {
		// TODO handle dirid.c9r correctly
	}

	if err = v.fs.RemoveDir(gopath.Join(DataDir, dirPath)); err != nil {
		return
	}

	if err = v.fs.RemoveDir(gopath.Join(DataDir, gopath.Dir(dirPath))); err != nil {
		// TODO
	}

	if err = v.fs.RemoveFile(gopath.Join(DataDir, parentPath, encDirName, constants.DirFile)); err != nil {
		// TODO handle dir.c9r correctly
	}

	if err = v.fs.RemoveDir(gopath.Join(DataDir, parentPath, encDirName)); err != nil {
		return
	}

	return
}

func (v *Vault) GetDirPath(name string) (dirPath, dirID string, err error) {
	dirID, err = v.GetDirID(name)
	if err != nil {
		return
	}

	dir, err := path.FromDirID(dirID, v.EncryptKey, v.MacKey)
	if err != nil {
		return
	}

	return gopath.Join(DataDir, dir), dirID, nil
}

func (v *Vault) InvalidateCache(name string) {
	v.cache.Remove(cleanPath(name))
}

func (v *Vault) FullyInvalidate() {
	v.cache.Clear()
}

func (v *Vault) GetDirID(name string) (dirID string, err error) {
	segments := splitPath(name)

	dirID = RootDirID

	if entry, ok := v.cache.Get(cleanPath(name)); ok {
		return entry.DirID, nil
	}

	// var dirIDFile string
	for i, segment := range segments {

		entry, ok := v.cache.Get(strings.Join(segments[:i+1], PathSeparator))
		if ok {
			dirID = entry.DirID
			continue
		}

		if dirID, _, err = v.getDirSegmentID(segment, dirID); err != nil {
			return
		}

		v.cache.Set(strings.Join(segments[:i+1], PathSeparator), cacheEntry{
			DirID: dirID,
		})
	}

	return
}

func (v *Vault) GetFilePath(name string) (filePath, dirID string, err error) {
	cleanName := cleanPath(name)

	dir, file := gopath.Split(cleanName)

	if file == "" {
		return "", "", fmt.Errorf("not a valid filepath: %s", name)
	}

	dirID, err = v.GetDirID(dir)
	if err != nil {
		return
	}

	parentPath, err := path.FromDirID(dirID, v.EncryptKey, v.MacKey)
	if err != nil {
		return
	}

	encName, err := filename.Encrypt(file, dirID, v.EncryptKey, v.MacKey)
	if err != nil {
		return
	}

	return gopath.Join(DataDir, parentPath, encName), dirID, nil
}

// TODO change API

func (v *Vault) PathFromDirID(dirId string) (string, error) {
	path, err := path.FromDirID(dirId, v.EncryptKey, v.MacKey)
	if err != nil {
		return "", err
	}

	return gopath.Join(DataDir, path), nil
}

func (v *Vault) DecryptFileName(name, dirID string) (string, error) {
	return filename.Decrypt(name, dirID, v.EncryptKey, v.MacKey)
}

func (v *Vault) EncryptFileName(name, dirID string) (string, error) {
	return filename.Encrypt(name, dirID, v.EncryptKey, v.MacKey)
}

func CalculateEncryptedFileSize(size int64) int64 {
	nFullChunks := (size / constants.ChunkPayloadSize)
	fullChunksSize := nFullChunks * constants.ChunkEncryptedSize

	rest := size - (nFullChunks * constants.ChunkPayloadSize)

	var restSize int64 = 0
	if rest > 0 {
		restSize = rest + constants.ChunkMacSize + constants.ChunkNonceSize
	}

	return fullChunksSize + restSize + constants.HeaderEncryptedSize
}

func CalculateRawFileSize(size int64) int64 {
	size = size - constants.HeaderEncryptedSize

	nFullChunks := (size / constants.ChunkEncryptedSize)
	fullChunksSize := nFullChunks * constants.ChunkPayloadSize

	rest := size - (nFullChunks * constants.ChunkEncryptedSize)

	var restSize int64 = 0
	if rest > 0 {
		restSize = rest - constants.ChunkMacSize - constants.ChunkNonceSize
	}

	return fullChunksSize + restSize
}

func (v *Vault) NewEncryptReader(r io.Reader) (io.ReadCloser, error) {
	pipeReader, pipeWriter := io.Pipe()

	go func() {
		encWriter, err := v.NewEncryptWriter(pipeWriter)
		if err != nil {
			pipeWriter.CloseWithError(err)
			return
		}

		if _, err = io.Copy(encWriter, r); err != nil {
			pipeWriter.CloseWithError(err)
			return
		}

		pipeWriter.CloseWithError(encWriter.Close())
	}()

	return pipeReader, nil
}

func (v Vault) NewDecryptReader(r io.ReadCloser) (*stream.Reader, error) {
	h, err := header.Unmarshal(r, v.EncryptKey, v.MacKey)
	if err != nil {
		return nil, err
	}

	return stream.NewReader(r, h.ContentKey, h.Nonce, v.MacKey)
}

func (v Vault) NewEncryptWriter(w io.WriteCloser) (*stream.Writer, error) {
	h, err := header.New()
	if err != nil {
		return nil, err
	}

	if err := h.Marshal(w, v.EncryptKey, v.MacKey); err != nil {
		return nil, err
	}

	return stream.NewWriter(w, h.ContentKey, h.Nonce, v.MacKey)
}

// ENDTODO

func (v *Vault) getDirSegmentID(segment, parentID string) (dirID, dirIDFile string, err error) {
	if strings.Contains(segment, PathSeparator) {
		return "", "", fmt.Errorf("segment must not have any slashes: %s", segment)
	}

	parentPath, err := path.FromDirID(parentID, v.EncryptKey, v.MacKey)
	if err != nil {
		return
	}

	encSegment, err := filename.Encrypt(segment, parentID, v.EncryptKey, v.MacKey)
	if err != nil {
		return
	}

	dirID, err = v.getDirIDFromPath(gopath.Join(DataDir, parentPath, encSegment, constants.DirFile))
	if err != nil {
		return
	}

	return dirID, gopath.Join(DataDir, parentPath, encSegment, constants.DirFile), nil
}

func (v *Vault) getDirIDFromPath(path string) (dirID string, err error) {
	dirIDReader, err := v.fs.Open(path)
	if err != nil {
		return
	}
	defer dirIDReader.Close()

	dirIDBytes, err := io.ReadAll(dirIDReader)
	if err != nil {
		return
	}

	return string(dirIDBytes), nil
}

func (v *Vault) writeDirIDToPath(path, dirID string) (err error) {
	return v.fs.WriteString(path, dirID)
}

func (v *Vault) writeDirIDToPathEncrypted(path, dirID string) (err error) {
	encReader, err := v.NewEncryptReader(strings.NewReader(dirID))
	if err != nil {
		return err
	}
	defer encReader.Close()

	encryptedDirID, err := io.ReadAll(encReader)
	if err != nil {
		return err
	}

	return v.fs.WriteString(path, string(encryptedDirID))
}

func cleanPath(name string) string {
	name = gopath.Clean(name)

	if name == "." {
		return ""
	}

	return strings.TrimLeft(name, PathSeparator)
}

func splitPath(name string) []string {
	name = cleanPath(name)

	if name == "" {
		return []string{}
	} else {
		return strings.Split(name, PathSeparator)
	}
}
