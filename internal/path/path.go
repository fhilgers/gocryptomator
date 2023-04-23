package path

import (
	"crypto/sha1"
	"encoding/base32"
	"path/filepath"

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
