package fileutil

func MoveFile(src string, dst string) error {
	from, _ := syscall.UTF16PtrFromString(src)
	to, _ := syscall.UTF16PtrFromString(dst)
	return syscall.MoveFile(from, to)
}
