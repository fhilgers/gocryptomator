package path

import (
	"io/fs"
)

func FromDirID(dirID string, encKey, macKey []byte) (string, error)

func Resolve(fs fs.FS, path string, encKey, macKey []byte) (string, error)
