package header

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/fhilgers/gocryptomator/internal/constants"
)

type FileHeader struct {
	Nonce      []byte
	Reserved   []byte
	ContentKey []byte
}

type (
	encryptedFileHeader [constants.HeaderEncryptedSize]byte
	payload             [constants.HeaderPayloadSize]byte
)

func (p payload) ContentKey() []byte {
	return p[constants.HeaderReservedSize:]
}

func (p payload) Reserved() []byte {
	return p[:constants.HeaderReservedSize]
}

func (efh encryptedFileHeader) Nonce() []byte {
	return efh[:constants.HeaderNonceSize]
}

func (efh encryptedFileHeader) EncryptedPayload() []byte {
	return efh[constants.HeaderNonceSize : constants.HeaderNonceSize+constants.HeaderPayloadSize]
}

func (efh encryptedFileHeader) Mac() []byte {
	return efh[len(efh)-constants.HeaderMacSize:]
}

func New() (header FileHeader, err error) {
	header.Nonce = make([]byte, constants.HeaderNonceSize)
	header.ContentKey = make([]byte, constants.HeaderContentKeySize)
	header.Reserved = make([]byte, constants.HeaderReservedSize)

	if _, err = rand.Read(header.Nonce); err != nil {
		return
	}

	if _, err = rand.Read(header.ContentKey); err != nil {
		return
	}

	binary.BigEndian.PutUint64(header.Reserved, constants.HeaderReservedValue)

	return
}

func Unmarshal(r io.Reader, encKey, macKey []byte) (header FileHeader, err error) {
	var encHeader encryptedFileHeader

	if _, err = io.ReadFull(r, encHeader[:]); err != nil {
		return
	}

	header.Nonce = encHeader.Nonce()

	hash := hmac.New(sha256.New, macKey)

	hash.Write(encHeader.Nonce())
	hash.Write(encHeader.EncryptedPayload())

	expectedMac := hash.Sum(nil)

	if !hmac.Equal(expectedMac, encHeader.Mac()) {
		return header, fmt.Errorf("invalid hmac: wanted %s, got %s", expectedMac, encHeader.Mac())
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return
	}

	var p payload

	ctr := cipher.NewCTR(block, encHeader.Nonce())
	ctr.XORKeyStream(p[:], encHeader.EncryptedPayload())

	header.ContentKey = p.ContentKey()
	header.Reserved = p.Reserved()

	return
}

func (h FileHeader) Marshal(w io.Writer, encKey, macKey []byte) (err error) {
	payload := append(h.Reserved, h.ContentKey...)

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return
	}

	ctr := cipher.NewCTR(block, h.Nonce)
	ctr.XORKeyStream(payload, payload)

	hash := hmac.New(sha256.New, macKey)

	hash.Write(h.Nonce)
	hash.Write(payload)

	mac := hash.Sum(nil)

	buf := bytes.Buffer{}
	if _, err = buf.Write(h.Nonce); err != nil {
		return
	}
	if _, err = buf.Write(payload); err != nil {
		return
	}
	if _, err = buf.Write(mac); err != nil {
		return
	}

	_, err = buf.WriteTo(w)

	return
}
