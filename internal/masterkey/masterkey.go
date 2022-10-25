package masterkey

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"

	aesWrap "github.com/NickBall/go-aes-key-wrap"
	"github.com/fhilgers/gocryptomator/internal/constants"
	"golang.org/x/crypto/scrypt"
)

type MasterKey struct {
	EncryptKey []byte
	MacKey     []byte
}

type encryptedMasterKey struct {
	Version          uint32 `json:"version"`
	ScryptSalt       []byte `json:"scryptSalt"`
	ScryptCostParam  int    `json:"scryptCostParam"`
	ScryptBlockSize  int    `json:"scryptBlockSize"`
	PrimaryMasterKey []byte `json:"primaryMasterKey"`
	HmacMasterKey    []byte `json:"hmacMasterKey"`
	VersionMac       []byte `json:"versionMac"`
}

func New() (m MasterKey, err error) {
	m.EncryptKey = make([]byte, constants.MasterEncryptKeySize)
	m.MacKey = make([]byte, constants.MasterMacKeySize)

	if _, err = rand.Read(m.EncryptKey); err != nil {
		return
	}

	_, err = rand.Read(m.MacKey)

	return
}

func (m MasterKey) Marshal(w io.Writer, passphrase string) (err error) {
	encKey := encryptedMasterKey{
		Version:         constants.MasterVersion,
		ScryptCostParam: constants.MasterScryptCostParam,
		ScryptBlockSize: constants.MasterScryptBlockSize,
	}

	encKey.ScryptSalt = make([]byte, constants.MasterScryptSaltSize)

	if _, err = rand.Read(encKey.ScryptSalt); err != nil {
		return
	}

	kek, err := scrypt.Key([]byte(passphrase), encKey.ScryptSalt, encKey.ScryptCostParam, encKey.ScryptBlockSize, 1, constants.MasterEncryptKeySize)
	if err != nil {
		return
	}

	cipher, err := aes.NewCipher(kek)
	if err != nil {
		return
	}

	if encKey.PrimaryMasterKey, err = aesWrap.Wrap(cipher, m.EncryptKey); err != nil {
		return
	}
	if encKey.HmacMasterKey, err = aesWrap.Wrap(cipher, m.MacKey); err != nil {
		return
	}

	hash := hmac.New(sha256.New, m.MacKey)
	if err = binary.Write(hash, binary.BigEndian, encKey.Version); err != nil {
		return
	}

	encKey.VersionMac = hash.Sum(nil)

	err = json.NewEncoder(w).Encode(encKey)

	return
}

func Unmarshal(r io.Reader, passphrase string) (m MasterKey, err error) {
	encKey := &encryptedMasterKey{}

	if err = json.NewDecoder(r).Decode(encKey); err != nil {
		return
	}

	kek, err := scrypt.Key([]byte(passphrase), encKey.ScryptSalt, encKey.ScryptCostParam, encKey.ScryptBlockSize, 1, constants.MasterEncryptKeySize)
	if err != nil {
		return
	}

	cipher, err := aes.NewCipher(kek)
	if err != nil {
		return
	}

	if m.EncryptKey, err = aesWrap.Unwrap(cipher, encKey.PrimaryMasterKey); err != nil {
		return
	}
	if m.MacKey, err = aesWrap.Unwrap(cipher, encKey.HmacMasterKey); err != nil {
		return
	}

	return
}
