package stream

import "io"

func NewReader(r io.Reader, contentKey, nonce []byte) (io.Reader, error)
func NewWriter(w io.Writer, contentKey, nonce []byte) (io.Writer, error)
