package constants

const (
	MasterEncryptKeySize  = 32
	MasterMacKeySize      = MasterEncryptKeySize
	MasterVersion         = 999
	MasterScryptCostParam = 32 * 1024
	MasterScryptBlockSize = 8
	MasterScryptSaltSize  = 32

	HeaderNonceSize      = 16
	HeaderContentKeySize = 32
	HeaderReservedSize   = 8
	HeaderPayloadSize    = HeaderContentKeySize + HeaderReservedSize
	HeaderMacSize        = 32
	HeaderEncryptedSize  = HeaderNonceSize + HeaderPayloadSize + HeaderMacSize

	ChunkNonceSize     = 16
	ChunkPayloadSize   = 32 * 1024
	ChunkMacSize       = 32
	ChunkEncryptedSize = ChunkNonceSize + ChunkPayloadSize + ChunkMacSize

	HeaderReservedValue uint64 = 0xFFFFFFFFFFFFFFFF
)
