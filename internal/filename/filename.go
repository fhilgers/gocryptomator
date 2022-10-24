package filename

func Encrypt(name, dirID string, encKey, macKey []byte) (string, error)
func Decrypt(name, dirID string, encKey, macKey []byte) (string, error)
