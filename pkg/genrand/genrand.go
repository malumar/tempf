package genrand

import (
	"crypto/rand"
	"io"
	"math/big"
)

func init() {
	b := make([]byte, 1)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic("randomstr cannot intialize crypto/rand")
	}
}

const safeChars = "qwertyuiopasdfghjklzxcvbnm1234567890QWERTYUIOPASDFGHJKLZXCVBNM"

var safeCharsSize = big.NewInt(int64(len(safeChars)))

func Bytes(length int) ([]byte, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func String(length int) (string, error) {
	ret := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, safeCharsSize)
		if err != nil {
			return "", err
		}
		ret[i] = safeChars[num.Int64()]
	}
	return string(ret), nil
}
