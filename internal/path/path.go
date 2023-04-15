package path

import (
	"crypto/sha1"
	"encoding/base32"
	"io"
	"path/filepath"
	"strings"

	"github.com/fhilgers/gocryptomator/internal/constants"
	"github.com/fhilgers/gocryptomator/internal/filename"
	"github.com/fhilgers/gocryptomator/pkg/fs"
	"github.com/jacobsa/crypto/siv"
	"github.com/spf13/afero"
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

func ResolveDir(fs fs.Fs, basePath, dir, parentID string, encKey, macKey []byte) (dirID string, err error) {
    
    parentPath, err := FromDirID(parentID, encKey, macKey)
    if err != nil {
        return
    }

    if (dir == ".") {
        return parentID, nil
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

    return string(dirIDBytes), nil
}

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


func ResolveFilePath(fs fs.Fs, basePath, path, parentID string, encKey, macKey []byte) (resolvedPath, dirID string, err error) {

    relPath := strings.TrimPrefix(path, afero.FilePathSeparator)
    cleanPath := filepath.Clean(relPath)

    segments := strings.Split(cleanPath, afero.FilePathSeparator)

    _, dirID, err = ResolveDirPath(fs, basePath, filepath.Join(segments[:len(segments) - 1]...), parentID, encKey, macKey)
    if err != nil {
        return
    }

    resolvedPath, err = ResolveFile(fs, basePath, segments[len(segments) - 1], dirID, encKey, macKey)
    return
}

func ResolveDirPath(fs fs.Fs, basePath, path, parentID string, encKey, macKey []byte) (resolvedPath, dirID string, err error) {

    relPath := strings.TrimPrefix(path, afero.FilePathSeparator)
    cleanPath := filepath.Clean(relPath)

    segments := strings.Split(cleanPath, afero.FilePathSeparator)

    dirID = parentID
    for i, segment := range(segments) {

        if i == len(segments) - 1 {
            break
        }

        dirID, err = ResolveDir(fs, basePath, segment, dirID, encKey, macKey)
        if err != nil  {
            return
        }
    }

    id, err := ResolveDir(fs, basePath, segments[len(segments) - 1], dirID, encKey, macKey)
    if err != nil {
        return
    }

    resolvedPath, err = FromDirID(id, encKey, macKey)

    return resolvedPath, id, err
}
