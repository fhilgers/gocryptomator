package path_test

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/fhilgers/gocryptomator/internal/constants"
	"github.com/fhilgers/gocryptomator/internal/filename"
	"github.com/fhilgers/gocryptomator/internal/path"
	"github.com/fhilgers/gocryptomator/internal/testutils"
	"github.com/google/uuid"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"pgregory.net/rapid"
)

func TestDummy(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		encKey := testutils.FixedSizeByteArray(constants.MasterEncryptKeySize).Draw(t, "encKey")
		macKey := testutils.FixedSizeByteArray(constants.MasterMacKeySize).Draw(t, "macKey")
        
        memFs := afero.NewMemMapFs()

        rootDir, err := path.FromDirID("", encKey, macKey)
        assert.NoError(t, err)

        err = memFs.MkdirAll("" + rootDir, 0755)
        assert.NoError(t, err)

        dirID := uuid.NewString()


        encName, err := filename.Encrypt("testdir", "", encKey, macKey)
        assert.NoError(t, err)

        err = memFs.MkdirAll(filepath.Join("", rootDir, encName), 0755)
        assert.NoError(t, err)

        p, err := path.FromDirID(dirID, encKey, macKey)
        assert.NoError(t, err)

        err = afero.WriteFile(memFs, filepath.Join("", rootDir, encName, "dir.c9r"), []byte(dirID), 0644)
        assert.NoError(t, err)

        err = memFs.Mkdir(filepath.Join("", p), 0755)
        assert.NoError(t, err)

        afero.Walk(memFs, "", func(path string, info fs.FileInfo, err error) error {
            fmt.Println(path)
            return nil
        })

        /*
        rootDir, err = path.Resolve(afero.NewIOFS(memFs), "", "", "", encKey, macKey)
        assert.NoError(t, err)
        fmt.Println(rootDir)

        rootDir, err = path.Resolve(afero.NewIOFS(memFs), "", "testdir", "", encKey, macKey)
        assert.NoError(t, err)


        fmt.Println(rootDir)
        */

	})
}

func TestVault(tt *testing.T) {
    rapid.Check(tt, func(t *rapid.T) {

    })
}
