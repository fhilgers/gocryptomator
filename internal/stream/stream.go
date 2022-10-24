package stream

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"crypto/rand"
)

const (
    ContentKeySize = 32
    MacKeySize = 32

	NonceSize = 16
	MacSize   = 32
	ChunkSize = 32 * 1024

	encChunkSize = ChunkSize + NonceSize + MacSize

	lastChunk    = true
	notLastChunk = false
)

type Reader struct {
	block cipher.Block
	mac   hash.Hash
	nonce []byte

	src io.Reader

	unread []byte
	buf    [encChunkSize]byte

	chunkNr uint64

	err error
}

func NewReader(src io.Reader, contentKey, nonce, macKey []byte) (*Reader, error) {
	block, err := aes.NewCipher(contentKey)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, macKey)

	return &Reader{
		block: block,
		mac:   mac,
		src:   src,
		nonce: nonce,
	}, nil
}

func (r *Reader) Read(p []byte) (int, error) {
	if len(r.unread) > 0 {
		n := copy(p, r.unread)
		r.unread = r.unread[n:]
		return n, nil
	}

	if r.err != nil {
		return 0, r.err
	}
	if len(p) == 0 {
		return 0, nil
	}

	last, err := r.readChunk()
	if err != nil {
		r.err = err
		return 0, err
	}

	n := copy(p, r.unread)
	r.unread = r.unread[n:]

	if last {
		if _, err := r.src.Read(make([]byte, 1)); err == nil {
			r.err = errors.New("trailing data after end of encrypted file")
		} else if err != io.EOF {
			r.err = fmt.Errorf("non-EOF error reading after end of encrypted file: %w", err)
		} else {
			r.err = io.EOF
		}
	}

	return n, nil
}

func (r *Reader) readChunk() (last bool, err error) {
	if len(r.unread) != 0 {
		panic("stream: internal error: readChunk called with dirty buffer")
	}

	in := r.buf[:]
	n, err := io.ReadFull(r.src, in)

	switch {
	case err == io.EOF:
		return false, io.ErrUnexpectedEOF
	case err == io.ErrUnexpectedEOF:
		last = true
		in = in[:n]
	case err != nil:
		return false, err
	}

	chunkNonce := in[:NonceSize]
	payload := in[NonceSize : len(in)-MacSize]
	tag := in[len(in)-MacSize:]

	r.mac.Reset()
	r.mac.Write(r.nonce)
	binary.Write(r.mac, binary.BigEndian, r.chunkNr)
	r.mac.Write(chunkNonce)
	r.mac.Write(payload)

	expectedTag := r.mac.Sum(nil)

	if !hmac.Equal(expectedTag, tag) {
		return false, fmt.Errorf("stream: internal error: invalid hmac tag: wanted %#v, got %#v", expectedTag, tag)
	}

	ctr := cipher.NewCTR(r.block, chunkNonce)
	ctr.XORKeyStream(payload, payload)

	r.chunkNr++
	r.unread = r.buf[:copy(r.buf[:], payload)]
	return last, nil
}

type Writer struct {
	block cipher.Block
	mac   hash.Hash
	nonce []byte

	dst       io.Writer
	unwritten []byte
	buf       [encChunkSize]byte

	err error

	chunkNr uint64
}

func NewWriter(dst io.Writer, contentKey, nonce, macKey []byte) (*Writer, error) {
	block, err := aes.NewCipher(contentKey)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, macKey)

	w := &Writer{
		block: block,
		mac:   mac,
		nonce: nonce,
		dst:   dst,
	}

	w.unwritten = w.buf[:0]
	return w, nil
}

func (w *Writer) Write(p []byte) (n int, err error) {
	if w.err != nil {
		return 0, w.err
	}
	if len(p) == 0 {
		return 0, nil
	}

	total := len(p)
	for len(p) > 0 {
		freeBuf := w.buf[len(w.unwritten):ChunkSize]
		n := copy(freeBuf, p)
		p = p[n:]
		w.unwritten = w.unwritten[:len(w.unwritten)+n]

		if len(w.unwritten) == ChunkSize && len(p) > 0 {
			if err := w.flushChunk(notLastChunk); err != nil {
				w.err = err
				return 0, err
			}
		}
	}
	return total, nil
}

// Close flushes the last chunk. It does not close the underlying Writer.
func (w *Writer) Close() error {
	if w.err != nil {
		return w.err
	}

	w.err = w.flushChunk(lastChunk)
	if w.err != nil {
		return w.err
	}

	w.err = errors.New("stream.Writer is already closed")
	return nil
}

func (w *Writer) flushChunk(last bool) error {
	if !last && len(w.unwritten) != ChunkSize {
		panic("stream: internal error: flush called with partial chunk")
	}

	chunkNonce := make([]byte, NonceSize)
	_, err := rand.Read(chunkNonce)
	if err != nil {
		panic(err)
	}

	payload := make([]byte, len(w.unwritten))
	ctr := cipher.NewCTR(w.block, chunkNonce)
	ctr.XORKeyStream(payload, w.unwritten)

	w.mac.Reset()
	w.mac.Write(w.nonce)
	binary.Write(w.mac, binary.BigEndian, w.chunkNr)
	w.mac.Write(chunkNonce)
	w.mac.Write(payload)

	tag := w.mac.Sum(nil)

	n := copy(w.buf[0:], chunkNonce)
	n += copy(w.buf[n:], payload)
	n += copy(w.buf[n:], tag)

	_, err = w.dst.Write(w.buf[:n])

	w.unwritten = w.buf[:0]
	w.chunkNr++
	return err
}
