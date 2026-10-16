package upgrade

import (
	"errors"
	"os"
)

// Lock lives in the protected installation directory. An interrupted operation
// leaves evidence for an operator rather than permitting a second replacement.
func acquireLock(dest string) (func(), error) {
	path := dest + ".upgrade-lock"
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, errors.New("无法取得升级锁；请确认管理员权限；如有遗留锁，先检查升级进程及回滚文件")
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	return func() {
		file.Close()
		if current, err := os.Lstat(path); err == nil && os.SameFile(info, current) {
			_ = os.Remove(path)
		}
	}, nil
}
