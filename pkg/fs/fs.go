package fs

import (
	"github.com/spf13/afero"
)


type Fs interface {
  afero.Fs
  //Open(name string) (io.Reader, error)

  //Mkdir(name string) error
  Rmdir(name string) error
  RemoveFile(name string) error

  //Create(name string) (io.WriteCloser, error)
}
