//go:build !windows

package tokencache

import "os"

func unsafeFilePermissions(mode os.FileMode) bool {
	return mode.Perm()&0o077 != 0
}
