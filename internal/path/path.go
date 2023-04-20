package path

import (
	"crypto/sha1"
	"encoding/base32"
	"path/filepath"
	/*
		"io"
		"strings"

		"github.com/fhilgers/gocryptomator/internal/constants"
		"github.com/fhilgers/gocryptomator/internal/filename"
		//"github.com/fhilgers/gocryptomator/pkg/fs"
		"github.com/spf13/afero"
	*/
	"github.com/jacobsa/crypto/siv"
)

func FromDirID(dirID string, encKey, macKey []byte) (string, error) {
	encID, err := siv.Encrypt(nil, append(macKey, encKey...), []byte(dirID), nil)
	if err != nil {
		return "", err
	}

	encIDBytes := sha1.Sum(encID)
	encIDString := base32.StdEncoding.EncodeToString(encIDBytes[:])

	return filepath.Join(encIDString[:2], encIDString[2:]), nil
}

/*
func ResolveDir(fs fs.Fs, basePath, dir, parentID string, encKey, macKey []byte) (dirID string, dirIDPath string, err error) {

    parentPath, err := FromDirID(parentID, encKey, macKey)
    if err != nil {
        return
    }

    if (dir == ".") {
        return parentID, "", nil
    }

    encDirName, err := filename.Encrypt(dir, parentID, encKey, macKey)
    if err != nil {
        return
    }

    dirIDFile, err := fs.Open(filepath.Join(basePath, parentPath, encDirName, constants.DirFile))
    if err != nil {
        return
    }

    dirIDBytes, err := io.ReadAll(dirIDFile)
    if err != nil {
        return
    }

    return string(dirIDBytes), filepath.Join(basePath, parentPath, encDirName), nil
}
*/

/*
func ResolveSymlink(fs iofs.FS, basePath, symlink, parentID string, encKey, macKey []byte) (symlinkTarget string, err error) {
    parentPath, err := FromDirID(parentID, encKey, macKey)
    if err != nil {
        return
    }

    encSymlinkName, err := filename.Encrypt(symlink, parentID, encKey, macKey)
    if err != nil {
        return
    }

    symlinkTargetFile, err := fs.Open(filepath.Join(basePath, parentPath, encSymlinkName, constants.SymlinkFile))
    if err != nil {
        return
    }

    fileHeader, err := header.Unmarshal(symlinkTargetFile, encKey, macKey)
    if err != nil {
        return
    }

    reader, err := stream.NewReader(symlinkTargetFile, fileHeader.ContentKey, fileHeader.Nonce, macKey)
    if err != nil {
        return
    }

    symlinkTargetBytes, err := io.ReadAll(reader)
    if err != nil {
        return
    }

    return string(symlinkTargetBytes), err
}
*/

/*
func ResolveFile(fs fs.Fs, basePath, file, parentID string, encKey, macKey []byte) (path string, err error) {
    parentPath, err := FromDirID(parentID, encKey, macKey)
    if err != nil {
        return
    }

    encFileName, err := filename.Encrypt(file, parentID, encKey, macKey)
    if err != nil {
        return
    }

    return filepath.Join(basePath, parentPath, encFileName), err
}


func ResolveFilePath(fs fs.Fs, basePath, path, parentID string, encKey, macKey []byte) (File, error) {

    relPath := strings.TrimPrefix(path, afero.FilePathSeparator)
    cleanPath := filepath.Clean(relPath)

    segments := strings.Split(cleanPath, afero.FilePathSeparator)

    directory, err := ResolveDirPath(fs, basePath, filepath.Join(segments[:len(segments) - 1]...), parentID, encKey, macKey)
    if err != nil {
        return nil, err
    }

    resolvedPath, err := ResolveFile(fs, basePath, segments[len(segments) - 1], directory.DirID(), encKey, macKey)
    resolvedName, err := filename.Encrypt(segments[len(segments) - 1], directory.DirID(), encKey, macKey)

    return file{ name: resolvedName, path: resolvedPath, parentID: directory.DirID() }, err
}

func ResolveDirPath(fs fs.Fs, basePath, path, parentID string, encKey, macKey []byte) (directory Directory, err error) {
  relPath := strings.TrimPrefix(path, afero.FilePathSeparator)
  cleanPath := filepath.Clean(relPath)

  segments := strings.Split(cleanPath, afero.FilePathSeparator)

  var dirID string
  for i, segment := range(segments) {
    if i == len(segments) - 1 {
      break
    }

    dirID, _, err = ResolveDir(fs, basePath, segment, parentID, encKey, macKey)
    if err != nil {
      return
    }

    parentID = dirID
  }

  dirID, dirIDPath, err := ResolveDir(fs, basePath, segments[len(segments) - 1], dirID, encKey, macKey)
  if err != nil {
    return
  }

  resolvedPath, err := FromDirID(dirID, encKey, macKey)
  if err != nil {
    return
  }
  resolvedName, err := filename.Encrypt(segments[len(segments) - 1], parentID, encKey, macKey)
  if err != nil {
    return
  }

  return dir{ dirID: dirID, parentID: parentID, path: filepath.Join(basePath, resolvedPath), name: resolvedName, dirIDPath: dirIDPath }, nil
}

type Entry interface {
  Path() string
  Name() string
  ParentID() string
}

type File interface {
  Entry
}

type Directory interface {
  Entry
  DirID() string
  DirIDPath() string
}

type dir struct {
  name string
  path string
  dirIDPath string
  parentID string
  dirID string
}
type file struct {
  name string
  path string
  parentID string
}

func (f file) Path() string {
  return f.path
}

func (f file) Name() string {
  return f.name
}

func (f file) ParentID() string {
  return f.parentID
}

func (d dir) Path() string {
  return d.path
}

func (d dir) Name() string {
  return d.name
}

func (d dir) ParentID() string {
  return d.parentID
}

func (d dir) DirID() string {
  return d.dirID
}

func (d dir) DirIDPath() string {
  return d.dirIDPath
}


type Entries []Entry

func Resolve(fs fs.Fs, basePath, path, parentID string, encKey, macKey []byte) (entries Entries, err error) {
  relPath := strings.TrimPrefix(path, afero.FilePathSeparator)
  cleanPath := filepath.Clean(relPath)

  segments := strings.Split(cleanPath, afero.FilePathSeparator)

  var dirID string
  var resolvedPath string
  var resolvedName string
  var dirIDPath string
  for i, segment := range(segments) {
    if i == len(segments) - 1 {
      break
    }

    dirID, dirIDPath, err = ResolveDir(fs, basePath, segment, parentID, encKey, macKey)
    if err != nil {
      return
    }
    resolvedPath, err = FromDirID(dirID, encKey, macKey)
    if err != nil {
      return
    }
    resolvedName, err = filename.Encrypt(segment, parentID, encKey, macKey)
    if err != nil {
      return
    }

    entries = append(entries, dir { dirID: dirID, parentID: parentID, path: resolvedPath, name: resolvedName, dirIDPath: dirIDPath })

    parentID = dirID
  }

  dirID, dirIDPath, err = ResolveDir(fs, basePath, segments[len(segments) - 1], dirID, encKey, macKey)
  if err != nil {
    // might be a file
    resolvedPath, err = ResolveFile(fs, basePath, segments[len(segments) - 1], parentID, encKey, macKey)
    resolvedName, err = filename.Encrypt(segments[len(segments) - 1], parentID, encKey, macKey)
    if err != nil {
      return
    }

    entries = append(entries, file { parentID: parentID, path: resolvedPath, name: resolvedName })
    return
  }

  resolvedPath, err = FromDirID(dirID, encKey, macKey)
  if err != nil {
    return
  }
  resolvedName, err = filename.Encrypt(segments[len(segments) - 1], parentID, encKey, macKey)
  if err != nil {
    return
  }

  entries = append(entries, dir { dirID: dirID, parentID: parentID, path: resolvedPath, name: resolvedName, dirIDPath: dirIDPath })

  return
}
*/
