package filename

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/fhilgers/gocryptomator/internal/constants"
	"github.com/jacobsa/crypto/siv"
)

func Encrypt(name, dirID string, encKey, macKey []byte) (string, error) {
	encNameBytes, err := siv.Encrypt(nil, append(macKey, encKey...), []byte(name), [][]byte{[]byte(dirID)})
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(encNameBytes) + constants.RegularSuffix, nil
}

func Decrypt(name, dirID string, encKey, macKey []byte) (string, error) {
	suffix := filepath.Ext(name)

	if suffix != constants.RegularSuffix {
		return "", fmt.Errorf("encrypted filename must have %s as suffix: %s", constants.RegularSuffix, name)
	}

	nameWithoutSuffix := strings.TrimSuffix(name, suffix)

	decoded, err := base64.URLEncoding.DecodeString(nameWithoutSuffix)
	if err != nil {
		return "", err
	}

	decName, err := siv.Decrypt(append(macKey, encKey...), decoded, [][]byte{[]byte(dirID)})

	return string(decName), err
}

func Shorten(encName string) string {
	hashedName := sha1.Sum([]byte(encName))

	return base64.URLEncoding.EncodeToString(hashedName[:]) + constants.ShortenedSuffix
}
