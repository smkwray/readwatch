//go:build windows

package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"readwatch/internal/settings"
)

var fileSystemAuditSubcategory = GUID{
	Data1: 0x0CCE921D,
	Data2: 0x69AE,
	Data3: 0x11D9,
	Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30},
}

func queryFileSystemAuditPolicy() (AUDITPOLICYINFORMATION, error) {
	var info AUDITPOLICYINFORMATION
	err := withPrivilege("SeSecurityPrivilege", func() error {
		var infoPtr *AUDITPOLICYINFORMATION
		r, _, e := procAuditQuerySystemPolicy.Call(
			uintptr(unsafe.Pointer(&fileSystemAuditSubcategory)), 1, uintptr(unsafe.Pointer(&infoPtr)),
		)
		if r == 0 {
			return winErr("AuditQuerySystemPolicy", e)
		}
		defer procAuditFree.Call(uintptr(unsafe.Pointer(infoPtr)))
		info = *infoPtr
		return nil
	})
	return info, err
}

func setFileSystemAuditPolicy(info AUDITPOLICYINFORMATION) error {
	r, _, e := procAuditSetSystemPolicy.Call(uintptr(unsafe.Pointer(&info)), 1)
	if r == 0 {
		return winErr("AuditSetSystemPolicy", e)
	}
	return nil
}

// ensureFileSystemAuditPolicy enables successful File System auditing, writing
// its intent to the journal before the change so a crash in between is
// recoverable, and confirming the machine agrees afterwards.
func ensureFileSystemAuditPolicy(cfg *settings.Config, save func(*settings.Config) error) error {
	info, err := queryFileSystemAuditPolicy()
	if err != nil {
		return err
	}
	current := info.AuditingInformation

	if cfg.AuditPolicy != nil {
		switch {
		case current == cfg.AuditPolicy.Applied:
			if cfg.AuditPolicy.Phase != settings.PhaseApplied {
				cfg.AuditPolicy.Phase = settings.PhaseApplied
				return save(cfg)
			}
			return nil
		case current == cfg.AuditPolicy.Original:
			info.AuditingInformation = cfg.AuditPolicy.Applied
			if err := setFileSystemAuditPolicy(info); err != nil {
				return err
			}
			cfg.AuditPolicy.Phase = settings.PhaseApplied
			return save(cfg)
		case current&POLICY_AUDIT_EVENT_SUCCESS != 0:
			// Another administrator changed the policy while preserving success
			// auditing. ReadWatch no longer owns the policy state and must not
			// restore its older snapshot on Stop or uninstall.
			cfg.AuditPolicy = nil
			return save(cfg)
		default:
			return errors.New("File System audit policy changed outside ReadWatch and no longer enables successful access auditing")
		}
	}

	if current&POLICY_AUDIT_EVENT_SUCCESS != 0 {
		return nil
	}
	applied := current &^ POLICY_AUDIT_EVENT_NONE
	applied |= POLICY_AUDIT_EVENT_SUCCESS

	// Journal first: a crash between here and the verification leaves a
	// "prepared" record, which says the machine has to be examined rather than
	// assumed clean.
	cfg.AuditPolicy = &settings.AuditPolicySnapshot{Original: current, Applied: applied, Phase: settings.PhasePrepared}
	if err := save(cfg); err != nil {
		cfg.AuditPolicy = nil
		return err
	}
	info.AuditingInformation = applied
	if err := setFileSystemAuditPolicy(info); err != nil {
		cfg.AuditPolicy = nil
		_ = save(cfg)
		return err
	}
	verify, err := queryFileSystemAuditPolicy()
	if err != nil {
		return err
	}
	if verify.AuditingInformation != applied {
		return errors.New("the File System audit policy did not take the value ReadWatch set")
	}
	cfg.AuditPolicy.Phase = settings.PhaseApplied
	return save(cfg)
}

// restoreFileSystemAuditPolicy restores the pre-ReadWatch policy only when the
// current value is still exactly the value ReadWatch applied. External policy
// changes are left untouched.
func restoreFileSystemAuditPolicy(cfg *settings.Config, save func(*settings.Config) error) error {
	if cfg.AuditPolicy == nil {
		return nil
	}
	info, err := queryFileSystemAuditPolicy()
	if err != nil {
		return err
	}
	current := info.AuditingInformation
	switch current {
	case cfg.AuditPolicy.Applied:
		info.AuditingInformation = cfg.AuditPolicy.Original
		if err := setFileSystemAuditPolicy(info); err != nil {
			return err
		}
	case cfg.AuditPolicy.Original:
		// Already back where it started, whoever did it.
	default:
		// Someone else owns this now. Drop the record rather than overwrite them.
	}
	cfg.AuditPolicy = nil
	return save(cfg)
}

// readSACL reports a handle's audit entries and whether they are protected from
// inheritance. Restoring one without the other would silently change the
// folder's relationship to its parent.
func readSACL(h HANDLE) (string, bool, error) {
	var sacl, sd uintptr
	code, _, _ := procGetSecurityInfo.Call(
		uintptr(h), SE_FILE_OBJECT, SACL_SECURITY_INFORMATION,
		0, 0, 0, uintptr(unsafe.Pointer(&sacl)), uintptr(unsafe.Pointer(&sd)),
	)
	if code != ERROR_SUCCESS {
		return "", false, fmt.Errorf("read auditing rules: %w", syscall.Errno(code))
	}
	defer procLocalFree.Call(sd)

	var control uint16
	var revision uint32
	r, _, e := procGetSecurityDescriptorControl.Call(sd, uintptr(unsafe.Pointer(&control)), uintptr(unsafe.Pointer(&revision)))
	if r == 0 {
		return "", false, winErr("GetSecurityDescriptorControl", e)
	}
	var text *uint16
	var length uint32
	r, _, e = procConvertSecurityDescriptorToStringSecurityDescriptorW.Call(
		sd, 1, SACL_SECURITY_INFORMATION, uintptr(unsafe.Pointer(&text)), uintptr(unsafe.Pointer(&length)),
	)
	if r == 0 {
		return "", false, winErr("ConvertSecurityDescriptorToStringSecurityDescriptor", e)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(text)))
	return utf16FromPtr(text), control&SE_SACL_PROTECTED != 0, nil
}

func saclSecurityInformation(protected bool) uintptr {
	if protected {
		return SACL_SECURITY_INFORMATION | PROTECTED_SACL_SECURITY_INFORMATION
	}
	return SACL_SECURITY_INFORMATION | UNPROTECTED_SACL_SECURITY_INFORMATION
}

// addReadAuditRule adds "audit successful reads by anyone", inheritable to files
// and folders below, to the object this handle refers to.
func addReadAuditRule(h HANDLE, protected bool) error {
	var oldSACL, sd uintptr
	code, _, _ := procGetSecurityInfo.Call(
		uintptr(h), SE_FILE_OBJECT, SACL_SECURITY_INFORMATION,
		0, 0, 0, uintptr(unsafe.Pointer(&oldSACL)), uintptr(unsafe.Pointer(&sd)),
	)
	if code != ERROR_SUCCESS {
		return fmt.Errorf("read existing auditing rules: %w", syscall.Errno(code))
	}
	defer procLocalFree.Call(sd)

	var everyoneSID uintptr
	r, _, e := procConvertStringSidToSidW.Call(uintptr(unsafe.Pointer(utf16Ptr("S-1-1-0"))), uintptr(unsafe.Pointer(&everyoneSID)))
	if r == 0 {
		return winErr("ConvertStringSidToSid", e)
	}
	defer procLocalFree.Call(everyoneSID)

	ea := EXPLICITACCESSW{
		AccessPermissions: FILE_READ_DATA,
		AccessMode:        SET_AUDIT_SUCCESS,
		Inheritance:       OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
	}
	procBuildTrusteeWithSidW.Call(uintptr(unsafe.Pointer(&ea.Trustee)), everyoneSID)

	var newSACL uintptr
	code, _, _ = procSetEntriesInAclW.Call(1, uintptr(unsafe.Pointer(&ea)), oldSACL, uintptr(unsafe.Pointer(&newSACL)))
	if code != ERROR_SUCCESS {
		return fmt.Errorf("build auditing rules: %w", syscall.Errno(code))
	}
	defer procLocalFree.Call(newSACL)

	code, _, _ = procSetSecurityInfo.Call(
		uintptr(h), SE_FILE_OBJECT, saclSecurityInformation(protected),
		0, 0, 0, newSACL,
	)
	if code != ERROR_SUCCESS {
		return fmt.Errorf("apply auditing rules: %w", syscall.Errno(code))
	}
	return nil
}

// restoreSACL puts back exactly the descriptor that was captured, including
// whether it blocked inheritance.
func restoreSACL(h HANDLE, sddl string, protected bool) error {
	var sd uintptr
	var size uint32
	r, _, e := procConvertStringSecurityDescriptorToSecurityDescriptorW.Call(
		uintptr(unsafe.Pointer(utf16Ptr(sddl))), 1, uintptr(unsafe.Pointer(&sd)), uintptr(unsafe.Pointer(&size)),
	)
	if r == 0 {
		return winErr("ConvertStringSecurityDescriptorToSecurityDescriptor", e)
	}
	defer procLocalFree.Call(sd)

	var present, defaulted int32
	var sacl uintptr
	r, _, e = procGetSecurityDescriptorSacl.Call(sd, uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&sacl)), uintptr(unsafe.Pointer(&defaulted)))
	if r == 0 {
		return winErr("GetSecurityDescriptorSacl", e)
	}
	if present == 0 {
		// No audit entries at all is a real state, and a null SACL is how it is
		// written back.
		sacl = 0
	}
	code, _, _ := procSetSecurityInfo.Call(
		uintptr(h), SE_FILE_OBJECT, saclSecurityInformation(protected),
		0, 0, 0, sacl,
	)
	if code != ERROR_SUCCESS {
		return fmt.Errorf("restore auditing rules: %w", syscall.Errno(code))
	}
	return nil
}

// effectiveAuditRoots drops folders that already sit inside another watched
// folder: the audit entry is inheritable, so the outer one already covers them.
func effectiveAuditRoots(folders []string) []string {
	roots := append([]string(nil), folders...)
	sort.Slice(roots, func(i, j int) bool {
		if len(roots[i]) == len(roots[j]) {
			return strings.ToLower(roots[i]) < strings.ToLower(roots[j])
		}
		return len(roots[i]) < len(roots[j])
	})
	out := make([]string, 0, len(roots))
	for _, candidate := range roots {
		inside := false
		for _, parent := range out {
			if pathWithin(candidate, parent) {
				inside = true
				break
			}
		}
		if !inside {
			out = append(out, candidate)
		}
	}
	return out
}

func pathWithin(path, root string) bool {
	p := strings.TrimRight(strings.ToLower(filepath.Clean(path)), `\/`)
	r := strings.TrimRight(strings.ToLower(filepath.Clean(root)), `\/`)
	return p == r || strings.HasPrefix(p, r+`\`) || strings.HasPrefix(p, r+`/`)
}
