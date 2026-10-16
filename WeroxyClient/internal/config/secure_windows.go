//go:build windows

package config

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// secureProfile rejects inherited or explicit read grants to arbitrary users.
// The installed service profile may also grant LocalService read access.
func secureProfile(path string, _ os.FileInfo) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errors.New("secret file has no restrictive DACL")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	allowed := map[string]bool{
		user.User.Sid.String(): true,
		"S-1-5-18":             true, // SYSTEM
		"S-1-5-32-544":         true, // Administrators
		"S-1-5-19":             true, // LocalService
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("unsupported secret file ACE")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !allowed[sid.String()] {
			return errors.New("secret file ACL grants another account")
		}
	}
	return nil
}

// restrictProfile is called before writing the key into a temporary file.
func restrictProfile(path string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sddl := "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + user.User.Sid.String() + ")"
	return setProfileACL(path, sddl)
}

// SetServiceBinaryACL grants LocalService read and execute, never write.
func SetServiceBinaryACL(path string) error {
	return setProfileACL(path, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;LS)")
}

func setProfileACL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errors.New("invalid profile DACL")
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil)
}

// Preserve a verified existing DACL, including the installed service read grant.
func restrictReplacement(path, existing string) error {
	info, err := os.Lstat(existing)
	if os.IsNotExist(err) {
		return restrictProfile(path)
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("replacement destination is not regular")
	}
	if err := secureProfile(existing, info); err != nil {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(existing, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errors.New("invalid replacement ACL")
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
