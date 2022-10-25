package testutils

import "pgregory.net/rapid"

func FixedSizeByteArray(constant int) *rapid.Generator[[]byte] {
	return rapid.SliceOfN(rapid.Byte(), constant, constant)
}
