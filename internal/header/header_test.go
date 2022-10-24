package header_test

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fhilgers/gocryptomator/internal/constants"
	"github.com/fhilgers/gocryptomator/internal/header"
	"github.com/google/go-cmp/cmp"
)

func TestNew(t *testing.T) {
	h, err := header.New()
	if err != nil {
		t.Fatal(err)
	}

	if len(h.Nonce) != constants.HeaderNonceSize {
		t.Fatalf("invalid nonce size: wanted %d, got %d", constants.HeaderNonceSize, len(h.Nonce))
	}

	if len(h.ContentKey) != constants.HeaderContentKeySize {
		t.Fatalf("invalid contentKey size: wanted %d, got %d", constants.HeaderContentKeySize, len(h.ContentKey))
	}

	if len(h.Reserved) != constants.HeaderReservedSize {
		t.Fatalf("invalid reserved size: wanted %d, got %d", constants.HeaderReservedSize, len(h.Reserved))
	}

	if val := binary.BigEndian.Uint64(h.Reserved); val != constants.HeaderReservedValue {
		t.Fatalf("invalid reserved value: wanted 0x%X, got 0x%X", constants.HeaderReservedValue, val)
	}
}

func TestRoundTrip(t *testing.T) {
	buf := &bytes.Buffer{}
	encKey := make([]byte, constants.MasterEncryptKeySize)
	macKey := make([]byte, constants.MasterMacKeySize)

	if _, err := rand.Read(encKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(macKey); err != nil {
		t.Fatal(err)
	}

	h1, err := header.New()
	if err != nil {
		t.Fatal(err)
	}

	err = h1.Marshal(buf, encKey, macKey)
	if err != nil {
		t.Fatal(err)
	}

	h2, err := header.Unmarshal(buf, encKey, macKey)
	if err != nil {
		t.Fatal(err)
	}

	if !cmp.Equal(h1, h2) {
		t.Fatalf("headers differ:\n %s", cmp.Diff(h1, h2))
	}
}

type encHeader struct {
	Header []byte
	EncKey []byte
	MacKey []byte
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

		var encHeaders map[string]encHeader
		err = json.Unmarshal(input, &encHeaders)
		if err != nil {
			t.Fatal(err)
		}

		var headers map[string]header.FileHeader
		err = json.Unmarshal(golden, &headers)
		if err != nil {
			t.Fatal(err)
		}

		for name, encHeader := range encHeaders {
			t.Run(fmt.Sprintf("%s:%s", testname, name), func(t *testing.T) {
				buf := bytes.NewBuffer(encHeader.Header)

				h, err := header.Unmarshal(buf, encHeader.EncKey, encHeader.MacKey)
				if err != nil {
					t.Fatal(err)
				}

				if !cmp.Equal(h, headers[name]) {
					t.Fatalf("headers differ:\n %s", cmp.Diff(h, headers[name]))
				}
			})
		}
	}
}
