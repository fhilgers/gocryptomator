package testutils

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func WithTestdata[INPUT, GOLDEN any](
	t *testing.T,
	test_func func(t *testing.T, input INPUT, golden GOLDEN),
) {
	paths, err := filepath.Glob(filepath.Join("testdata", "*.input"))
	assert.NoError(t, err)

	for _, path := range paths {
		filename := filepath.Base(path)
		testname := strings.TrimSuffix(filename, filepath.Ext(filename))

		inputContents, err := os.ReadFile(path)
		assert.NoError(t, err)

		goldenContents, err := os.ReadFile(filepath.Join("testdata", testname+".golden"))
		assert.NoError(t, err)

		var input map[string]INPUT
		err = json.Unmarshal(inputContents, &input)
		assert.NoError(t, err)

		var golden map[string]GOLDEN
		err = json.Unmarshal(goldenContents, &golden)
		assert.NoError(t, err)

		for name, inputVal := range input {
			t.Run(testname+":"+name, func(t *testing.T) {
				test_func(t, inputVal, golden[name])
			})
		}
	}
}
