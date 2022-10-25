package masterkey_test

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fhilgers/gocryptomator/internal/constants"
	"github.com/fhilgers/gocryptomator/internal/masterkey"
	"github.com/google/go-cmp/cmp"
)

func TestNew(t *testing.T) {
	k, err := masterkey.New()
	if err != nil {
		t.Fatal(err)
	}

	if len(k.EncryptKey) != constants.MasterEncryptKeySize {
		t.Fatalf("invalid encryption key size: wanted %d, got %d", constants.MasterEncryptKeySize, len(k.EncryptKey))
	}

	if len(k.MacKey) != constants.MasterMacKeySize {
		t.Fatalf("invalid mac key size: wanted %d, got %d", constants.MasterMacKeySize, len(k.MacKey))
	}
}

func TestRoundTrip(t *testing.T) {
	passphrase := make([]byte, 16)

	if _, err := rand.Read(passphrase); err != nil {
		t.Fatal(err)
	}

	k1, err := masterkey.New()
	if err != nil {
		t.Fatal(err)
	}

	buf := &bytes.Buffer{}

	err = k1.Marshal(buf, string(passphrase))
	if err != nil {
		t.Fatal(err)
	}

	k2, err := masterkey.Unmarshal(buf, string(passphrase))
	if err != nil {
		t.Fatal(err)
	}

	if !cmp.Equal(k1, k2) {
		t.Fatal(cmp.Diff(k1, k2))
	}
}

type encKey struct {
	EncryptedMasterKey []byte
	Passphrase         string
}

func TestUnmarshalReference(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("testdata", "*.input"))
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range paths {
		filename := filepath.Base(path)
		testname := strings.TrimSuffix(filename, filepath.Ext(filename))

		input, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}

		golden, err := os.ReadFile(filepath.Join("testdata", testname+".golden"))
		if err != nil {
			t.Fatal(err)
		}

		var encKeys map[string]encKey
		err = json.Unmarshal(input, &encKeys)
		if err != nil {
			t.Fatal(err)
		}

		var keys map[string]masterkey.MasterKey
		err = json.Unmarshal(golden, &keys)
		if err != nil {
			t.Fatal(err)
		}

		for name, encKey := range encKeys {
			t.Run(fmt.Sprintf("%s:%s", testname, name), func(t *testing.T) {
				buf := bytes.NewBuffer(encKey.EncryptedMasterKey)

				h, err := masterkey.Unmarshal(buf, encKey.Passphrase)
				if err != nil {
					t.Fatal(err)
				}

				if !cmp.Equal(h, keys[name]) {
					t.Fatalf("keys differ:\n %s", cmp.Diff(h, keys[name]))
				}
			})
		}
	}
}
