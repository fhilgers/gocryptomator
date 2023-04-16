package fs

import (
	"io"
)


type File interface {
  io.Closer
  io.Reader

  Readdir(count int) ([]string, error)
}

type Fs interface {
  Open(name string) (File, error)
  Remove(name string) error
}
