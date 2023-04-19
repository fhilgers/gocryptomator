package vault

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fhilgers/gocryptomator/internal/config"
	"github.com/fhilgers/gocryptomator/internal/constants"
	"github.com/fhilgers/gocryptomator/internal/filename"
	"github.com/fhilgers/gocryptomator/internal/header"
	"github.com/fhilgers/gocryptomator/internal/masterkey"
	"github.com/fhilgers/gocryptomator/internal/path"
	"github.com/fhilgers/gocryptomator/internal/stream"
	"github.com/fhilgers/gocryptomator/pkg/fs"
	"github.com/google/uuid"
	"github.com/spf13/afero"
)

type Directory path.Directory
type Entry path.Entry
type File path.File

type Vault struct {
	config.Config
	masterkey.MasterKey


  basePath string
	fs fs.Fs

  cache map[string]string
}

var (
  ErrVaultNotFound = errors.New("vault not found")
)

func New(f fs.Fs, path, passphrase string) (vault Vault, err error) {
    vault = Vault{
        fs: f,
        basePath: filepath.Join(path, "d"),
        cache: make(map[string]string, 0),
    }

    if vault.MasterKey, err = masterkey.New(); err != nil {
      return
    }

    masterkeyFile, err := f.Create(filepath.Join(path, constants.ConfigMasterkeyFileName))
    if err != nil {
        return
    }
    defer masterkeyFile.Close()

    if err = vault.MasterKey.Marshal(masterkeyFile, passphrase); err != nil {
      return
    }

    configFile, err := f.Create(filepath.Join(path, constants.ConfigFileName))
    if err != nil {
        return
    }
    defer configFile.Close()

    if vault.Config, err = config.New(vault.EncryptKey, vault.MacKey); err != nil {
      return
    }

   if err = vault.Config.Marshal(configFile, vault.EncryptKey, vault.MacKey); err != nil {
     return
   }

    if err = vault.Config.Verify(vault.EncryptKey, vault.MacKey); err != nil {
        return 
    }

    if err = vault.MkRoot(); err != nil {
      return
    }

    return
}


func Unlock(f fs.Fs, path, passphrase string) (vault Vault, err error) {

    vault = Vault{
        fs: f,
        basePath: filepath.Join(path, "d"),
        cache: make(map[string]string, 0),
    }

    configFile, err := f.Open(filepath.Join(path, constants.ConfigFileName))
    if err != nil {
        err = ErrVaultNotFound
        return
    }
    defer configFile.Close()

    vault.Config, err = config.UnmarshalUnverified(configFile)
    if err != nil {
        return
    }

    masterkeyFile, err := f.Open(filepath.Join(path, constants.ConfigMasterkeyFileName))
    if err != nil {
        return
    }
    defer masterkeyFile.Close()

    vault.MasterKey, err = masterkey.Unmarshal(masterkeyFile, passphrase)
    if err != nil {
        return
    }

    if err = vault.Config.Verify(vault.EncryptKey, vault.MacKey); err != nil {
        return 
    }

    if err = vault.MkRoot(); err != nil {
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

func (v Vault) ResolveDirPath(dirPath, dirID string) (Directory, error) {
    return path.ResolveDirPath(v.fs, v.basePath, dirPath, dirID, v.EncryptKey, v.MacKey)
}

func (v Vault) ResolveFilePath(filepath, dirID string) (File, error) {
	return path.ResolveFilePath(v.fs, v.basePath, filepath, dirID, v.EncryptKey, v.MacKey)
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



func (v Vault) NewReader(r io.ReadCloser) (*stream.Reader, error) {
	h, err := header.Unmarshal(r, v.EncryptKey, v.MacKey)
	if err != nil {
		return nil, err
	}

	return stream.NewReader(r, h.ContentKey, h.Nonce, v.MacKey)
}


func (v Vault) NewReverseReader(r io.Reader) (io.Reader, error) {

  pipeReader, pipeWriter := io.Pipe()

  go func() {
    encWriter, err := v.NewWriter(pipeWriter)
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

func (v Vault) NewWriter(w io.WriteCloser) (*stream.Writer, error) {
	h, err := header.New()
	if err != nil {
		return nil, err
	}

	if err := h.Marshal(w, v.EncryptKey, v.MacKey); err != nil {
		return nil, err
	}

	return stream.NewWriter(w, h.ContentKey, h.Nonce, v.MacKey)
}

type DirV2 struct {
  id string
  parentID *string
  path string
  dirIDPath *string
}

func (d *DirV2) ID() string {
  return d.id
}

func (d *DirV2) ParentID() *string {
  return d.parentID
}
 
func (d *DirV2) Path() string {
  return d.path
}

func (d *DirV2) DirIDPath() *string {
  return d.dirIDPath
}

type DirectoryV2 interface {
  ID() string
  ParentID() *string
  Path() string
  DirIDPath() *string
}

/*
func (v Vault) mkdirIn(name, parentID string) (dirID string, error) {
  encName, err := v.EncryptFileName(name, parentID)
  if err != nil {
    return "", err
  }


}
*/

func (v Vault) resolveDirIn(name, parentID string) (id string, dirIDPath string, err error) {
  encName, err := v.EncryptFileName(name, parentID)
  if err != nil {
    return "", "", err
  }

  dir, err := v.PathFromDirID(parentID)
  if err != nil {
    return "", "", err
  }

  reader, err := v.fs.Open(filepath.Join(v.basePath, dir, encName, constants.DirFile))
  if err != nil {
    return "", "", err
  }
  defer reader.Close()

  dirIDBytes, err := io.ReadAll(reader)
  if err != nil {
    return "", "", err
  }

  
  return string(dirIDBytes), filepath.Join(dir, encName), nil
}

func (v Vault) GetCache(path string) (string, string, error) {
  path = cleanPath(path)

  dirID, ok := v.cache[path]
  if !ok || (dirID == "" && path != "") {
    return "", "", fmt.Errorf("not found")
  }

  parentID, ok := v.cache[filepath.Dir(path)]
  if !ok || (dirID == "" && path != "") {
    return "", "", fmt.Errorf("not found")
  }

  encPathName, err := v.EncryptFileName(filepath.Base(path), parentID)
  if err != nil {
    return "", "", err
  }

  parentPath, err := v.PathFromDirID(parentID)
  if err != nil {
    return "", "", err
  }

  return dirID, filepath.Join(parentPath, encPathName), nil
}

func (v Vault) PutCache(path string, id string) {
  path = cleanPath(path)

  //v.cache[path] = id
}

func (v Vault) InvalidateCache(paths []string) {
  for _, path := range paths {
    v.cache[path] = ""
  }
}

func (v Vault) ResolveDirV2Cache(dir string) (DirectoryV2, []string, error) {
  dir = cleanPath(dir)

  paths := make([]string, 0)

  parentID := ""
  path, err := v.PathFromDirID(parentID)
  if err != nil {
    return nil, paths, fmt.Errorf("could not resolve dirID: %w", err)
  }
  if dir == "" {
    return &DirV2{
      id: parentID,
      parentID: nil,
      path: path,
      dirIDPath: nil,
    }, paths, nil
  }

  segments := strings.Split(dir, string(os.PathSeparator))
  dirID := parentID
  var dirIDPath string
  for i, segment := range segments {
    parentID = dirID

    dirID, dirIDPath, err = v.GetCache(filepath.Join(segments[:i+1]...))
    if err == nil {
      paths = append(paths, filepath.Join(segments[:i+1]...))
    } else {
      dirID, dirIDPath, err = v.resolveDirIn(segment, dirID)
      if err != nil {
        return nil, paths, fmt.Errorf("could not resolve %s in dir with id %s: %w", segment, dirID, err)
      }
      v.PutCache(filepath.Join(segments[:i+1]...), dirID)
    }
  }

  path, err = v.PathFromDirID(dirID)
  if err != nil {
    return nil, paths, fmt.Errorf("could not resolve dirID: %w", err)
  }

  return &DirV2{
    id: dirID,
    parentID: &parentID,
    path: path,
    dirIDPath: &dirIDPath,
  }, paths, nil
}

func (v Vault) ResolveDirV2(dir string) (DirectoryV2, error) {
  d, paths, err := v.ResolveDirV2Cache(dir)
  if err == nil {
    info, err := v.fs.Stat(filepath.Join(v.basePath, d.Path()))
    if err == nil && info.IsDir() {
      return d, nil
    }
  }

  v.InvalidateCache(paths)

  dir = cleanPath(dir)

  parentID := ""
  path, err := v.PathFromDirID(parentID)
  if err != nil {
    return nil, fmt.Errorf("could not resolve dirID: %w", err)
  }
  if dir == "" {
    return &DirV2{
      id: parentID,
      parentID: nil,
      path: path,
      dirIDPath: nil,
    }, nil
  }

  segments := strings.Split(dir, string(os.PathSeparator))
  dirID := parentID
  var dirIDPath string
  for i, segment := range segments {
    parentID = dirID

    dirID, dirIDPath, err = v.resolveDirIn(segment, dirID)
    if err != nil {
      return nil, fmt.Errorf("could not resolve %s in dir with id %s: %w", segment, dirID, err)
    }
    v.PutCache(filepath.Join(segments[:i+1]...), dirID)
  }

  path, err = v.PathFromDirID(dirID)
  if err != nil {
    return nil, fmt.Errorf("could not resolve dirID: %w", err)
  }

  return &DirV2{
    id: dirID,
    parentID: &parentID,
    path: path,
    dirIDPath: &dirIDPath,
  }, nil
}

func (v Vault) ResolveFileV2(path string) (string, string, error) {
  dir, file := filepath.Split(path)

  resolvedDir, err := v.ResolveDirV2(dir)
  if err != nil {
    return "", "", err
  }

  id := resolvedDir.ID()

  encFileName, err := v.EncryptFileName(cleanPath(file), id)
  if err != nil {
    return "", "", err
  }

  return filepath.Join(resolvedDir.Path(), encFileName), id, nil
}

func (v Vault) MkRoot() error {
  encDirName, err := v.PathFromDirID("")
  if err != nil {
    return err
  }

  v.PutCache("", "")


  return v.fs.MkdirAll(filepath.Join(v.basePath, encDirName), 0755)
}

func (v Vault) Mkdir(name string) error {
  name = cleanPath(name)
  if _, err := v.ResolveDirV2(name); err == nil {
    return nil
  }
  parent, dir := filepath.Split(name)

  resolvedParent, err := v.ResolveDirV2(parent)
  if err != nil {
    return fmt.Errorf("could not resolve parent directory: %w", err)
  }

  encDirName, err := v.EncryptFileName(dir, resolvedParent.ID())
  if err != nil {
    return fmt.Errorf("could not encrypt directory name %s: %w", dir, err)
  }

  dirIDPath := filepath.Join(v.basePath, resolvedParent.Path(), encDirName)

  if err := v.fs.MkdirAll(dirIDPath, 0755); err != nil {
    return fmt.Errorf("could not make dir for dirFile: %w", err)
  }

  writer, err := v.fs.Create(filepath.Join(dirIDPath, constants.DirFile))
  if err != nil {
    return fmt.Errorf("could not create dirFile: %w", err)
  }

  id := uuid.NewString()
  if _, err = writer.Write([]byte(id)); err != nil {
    return fmt.Errorf("could not write id to dirFile: %w", err)
  }
  if err = writer.Close(); err != nil {
    return fmt.Errorf("could not close writer: %w", err)
  }

  path, err := v.PathFromDirID(id)
  if err != nil {
    return fmt.Errorf("could not create path for id %s: %w", id, err)
  }

  return v.fs.MkdirAll(filepath.Join(v.basePath, path), 0755)
}

func (v Vault) MkdirAll(name string) error {
  name = cleanPath(name)

  segments := strings.Split(name, string(os.PathSeparator))
  for i := range segments {
    dir := filepath.Join(segments[:i + 1]...)
    if err := v.Mkdir(dir); err != nil {
      return fmt.Errorf("failed to create dir %s as part of %s: %w", dir, name, err)
    }
  }

  return nil
}

func (v Vault) Rmdir(name string) error {
  name = cleanPath(name)
  if name == "" {
    // dont delete root dir
    return nil
  }
 
  dir, err := v.ResolveDirV2(name)
  if err != nil {
    return err
  }

  // TODO handle error types
  _ = v.fs.RemoveFile(filepath.Join(v.basePath, dir.Path(), "dirid.c9r"))

  if err := v.fs.Rmdir(filepath.Join(v.basePath, dir.Path())); err != nil {
    return err
  }

  // remove the (XY)/AOIENSTORYUSTOAIERNSAROSIM part
  _ = v.fs.Rmdir(filepath.Join(v.basePath, filepath.Dir(dir.Path())))

  _ = v.fs.RemoveFile(filepath.Join(v.basePath, *dir.DirIDPath(), "dir.c9r"))

  return v.fs.Rmdir(filepath.Join(v.basePath, *dir.DirIDPath()))
}

func cleanPath(path string) string {
  clean := strings.TrimLeft(path, string(os.PathSeparator))
  clean = strings.TrimRight(path, string(os.PathSeparator))
  clean = filepath.Clean(clean)
  if clean == "." || clean == "/" {
    clean = ""
  }

  return clean
}


type encFileInfo struct {
  os.FileInfo
  name string
  size int64
}

func (i *encFileInfo) Name() string {
  return i.name
}

func (i *encFileInfo) Size() int64 {
  return i.size
}
 
func (v Vault) Stat(name string) (os.FileInfo, error) {
  name = cleanPath(name)
	encFilePath, _, err := v.ResolveFileV2(name)
	if err != nil {
    println("STAT ERR 1")
		return nil, err
	}

  info, err := v.fs.Stat(filepath.Join(v.basePath, encFilePath))
  if err != nil {
    println("STAT ERR: " + name)
    return nil, err
  }

  return &encFileInfo {
    // TODO manage '.'
    FileInfo: info,
    name: filepath.Base(name),
    size: CalculateRawFileSize(info.Size()),
  }, nil
}


type dirWrapper struct {
  afero.File
  dirID string
  name string
  v Vault
}

func (d *dirWrapper) Readdir(count int) ([]os.FileInfo, error) {
  entries, err := d.File.Readdir(count)
  if err != nil {
    return nil, err
  }
  var infos []os.FileInfo
  for _, entry := range entries {
    if entry.Name() == "dirid.c9r" {
      continue
    }
    name, err := d.v.DecryptFileName(entry.Name(), d.dirID)
    if err != nil {
      return nil, err
    }
    infos = append(infos, &encFileInfo{
      FileInfo: entry,
      name: name,
      size: CalculateRawFileSize(entry.Size()),
    })
  }
  return infos, nil
}

func (w *dirWrapper) Stat() (os.FileInfo, error) {
  info, err := w.File.Stat()
  if err != nil {
    return nil, err
  }

  return &encFileInfo{
    name: w.name,
    FileInfo: info,
  }, nil
}


type fileWrapper struct {
  io.Reader
  io.WriteCloser
  afero.File
  name string
}

func (w *fileWrapper) Close() error {
  if w.WriteCloser != nil {
    if err := w.WriteCloser.Close(); err != nil {
      return err
    }
  }

  return w.File.Close()
}

func (w *fileWrapper) Read(b []byte) (int, error) {
  return w.Reader.Read(b)
}

func (w *fileWrapper) Write(b []byte) (int, error) {
  return w.WriteCloser.Write(b)
}

func (w *fileWrapper) Stat() (os.FileInfo, error) {
  info, err := w.File.Stat()
  if err != nil {
    return nil, err
  }

  return &encFileInfo{
    name: w.name,
    size: CalculateRawFileSize(info.Size()),
    FileInfo: info,
  }, nil
}


func (v Vault) Open(name string) (afero.File, error) {
  return v.OpenFile(name, os.O_RDONLY, 0)
}

func (v Vault) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
  if flag & os.O_RDWR == os.O_RDWR {
    return nil, fmt.Errorf("can not open file in O_RDWR")
  } else if flag & os.O_WRONLY == os.O_WRONLY && flag & os.O_TRUNC != os.O_TRUNC {
    return nil, fmt.Errorf("cannot open a file for writing without truncating")
  }
  name = cleanPath(name)

  var path string
  if name == "" {
    encDirPath, err := v.PathFromDirID("")
    if err != nil {
      return nil, err
    }
    path = encDirPath
  } else {
    encFilePath, _, err := v.ResolveFileV2(name)
    if err != nil {
      return nil, err
    }
    path = encFilePath
  }

  encDir, err := v.ResolveDirV2(name)
  if err == nil {
    dir, err := v.fs.Open(filepath.Join(v.basePath, encDir.Path()))
    if err != nil {
      return nil, err
    }

    return &dirWrapper{
      dirID: encDir.ID(),
      v: v,
      File: dir,
      name: filepath.Base(name),
    }, err

  } else {
    file, err := v.fs.OpenFile(filepath.Join(v.basePath, path), flag, perm)
    if err != nil {
      return nil, err
    }
    if flag & os.O_WRONLY == os.O_WRONLY {
      wrappedWriter, err := v.NewWriter(file)
      if err != nil {
        return nil, err
      }
      return &fileWrapper{
        WriteCloser: wrappedWriter,
        File: file,
        name: filepath.Base(name),
      }, nil

    } else if flag & os.O_RDONLY == os.O_RDONLY {
      wrappedReader, err := v.NewReader(file)
      if err != nil {
        return nil, err
      }

      return &fileWrapper{
        Reader: wrappedReader,
        File: file,
        name: filepath.Base(name),
      }, nil
    } else {
      return nil, fmt.Errorf("invalid flags")
    }
  }
}

func (v Vault) Chtimes(name string, atime time.Time, mtime time.Time) error {
  info, err := v.Stat(name)
  if err != nil {
    return err
  }

  if info.IsDir() {
    encDir, err := v.ResolveDirV2(name) 
    if err != nil {
      return err
    }

    return v.fs.Chtimes(filepath.Join(v.basePath, encDir.Path()), atime, mtime)
  } else {
    name = cleanPath(name)

    encFilePath, _, err := v.ResolveFileV2(name)
    if err != nil {
      return err
    }

    return v.fs.Chtimes(filepath.Join(v.basePath, encFilePath), atime, mtime)
  }
}


func (v Vault) Remove(name string) error {
  name = cleanPath(name)

  info, err := v.Stat(name)
  if err != nil {
    return err
  }

  if info.IsDir() {
    return v.Rmdir(name)
  } else {
    encDirFile, _, err := v.ResolveFileV2(name)
    if err != nil {
      return err
    }
    return v.fs.RemoveFile(filepath.Join(v.basePath, encDirFile))
  }
}

func (v Vault) Create(name string) (afero.File, error) {
  return v.OpenFile(name, os.O_WRONLY | os.O_TRUNC | os.O_CREATE, 0666)
}
