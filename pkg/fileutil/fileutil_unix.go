package fileutil

import (
	"os"
)

func MoveFile(src string, dst string) error {
	return os.Rename(src, dst)
}
