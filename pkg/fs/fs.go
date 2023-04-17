package fs

import (
	"io"
)

type Fs interface {
  Open(name string) (io.Reader, error)
}
