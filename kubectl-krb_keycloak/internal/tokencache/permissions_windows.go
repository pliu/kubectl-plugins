//go:build windows

package tokencache

import "os"

// Windows file security is ACL-based; os.FileMode does not expose group or world access.
func unsafeFilePermissions(os.FileMode) bool {
	return false
}
