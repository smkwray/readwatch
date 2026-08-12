//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
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
	if err := enablePrivilege("SeSecurityPrivilege"); err != nil {
		return AUDITPOLICYINFORMATION{}, err
	}
	var infoPtr uintptr
	r, _, e := procAuditQuerySystemPolicy.Call(
		uintptr(unsafe.Pointer(&fileSystemAuditSubcategory)), 1, uintptr(unsafe.Pointer(&infoPtr)),
	)
	if r == 0 {
		return AUDITPOLICYINFORMATION{}, winErr("AuditQuerySystemPolicy", e)
	}
	defer procAuditFree.Call(infoPtr)
	return *(*AUDITPOLICYINFORMATION)(unsafe.Pointer(infoPtr)), nil
}

func setFileSystemAuditPolicy(info AUDITPOLICYINFORMATION) error {
	r, _, e := procAuditSetSystemPolicy.Call(uintptr(unsafe.Pointer(&info)), 1)
	if r == 0 {
		return winErr("AuditSetSystemPolicy", e)
	}
	return nil
}

// ensureFileSystemAuditPolicy enables successful File System auditing while
// recording enough state to undo only ReadWatch's own policy change later.
func ensureFileSystemAuditPolicy(cfg *settings.Config) error {
	info, err := queryFileSystemAuditPolicy()
	if err != nil {
		return err
	}
	current := info.AuditingInformation

	if cfg.AuditPolicyOwned {
		switch {
		case current == cfg.AuditPolicyApplied:
			return nil
		case current == cfg.AuditPolicyOriginal:
			info.AuditingInformation = cfg.AuditPolicyApplied
			return setFileSystemAuditPolicy(info)
		case current&POLICY_AUDIT_EVENT_SUCCESS != 0:
			// Another administrator changed the policy while preserving success
			// auditing. ReadWatch no longer owns the policy state and must not
			// restore its older snapshot on Stop or uninstall.
			cfg.AuditPolicyOwned = false
			cfg.AuditPolicyOriginal = 0
			cfg.AuditPolicyApplied = 0
			return nil
		default:
			return errors.New("File System audit policy changed outside ReadWatch and no longer enables successful access auditing")
		}
	}

	if current&POLICY_AUDIT_EVENT_SUCCESS != 0 {
		return nil
	}
	applied := current &^ POLICY_AUDIT_EVENT_NONE
	applied |= POLICY_AUDIT_EVENT_SUCCESS
	info.AuditingInformation = applied
	if err := setFileSystemAuditPolicy(info); err != nil {
		return err
	}
	cfg.AuditPolicyOwned = true
	cfg.AuditPolicyOriginal = current
	cfg.AuditPolicyApplied = applied
	return nil
}

// restoreFileSystemAuditPolicy restores the pre-ReadWatch policy only when the
// current value is still exactly the value ReadWatch applied. External policy
// changes are left untouched.
func restoreFileSystemAuditPolicy(cfg *settings.Config) error {
	if !cfg.AuditPolicyOwned {
		return nil
	}
	info, err := queryFileSystemAuditPolicy()
	if err != nil {
		return err
	}
	current := info.AuditingInformation
	if current == cfg.AuditPolicyApplied {
		info.AuditingInformation = cfg.AuditPolicyOriginal
		if err := setFileSystemAuditPolicy(info); err != nil {
			return err
		}
	}
	cfg.AuditPolicyOwned = false
	cfg.AuditPolicyOriginal = 0
	cfg.AuditPolicyApplied = 0
	return nil
}

func getSACLSDDL(path string) (string, error) {
	if err := enablePrivilege("SeSecurityPrivilege"); err != nil {
		return "", err
	}
	var sacl, sd uintptr
	code, _, _ := procGetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(utf16Ptr(path))), SE_FILE_OBJECT, SACL_SECURITY_INFORMATION,
		0, 0, 0, uintptr(unsafe.Pointer(&sacl)), uintptr(unsafe.Pointer(&sd)),
	)
	if code != ERROR_SUCCESS {
		return "", fmt.Errorf("read auditing rules for %s: %w", path, syscall.Errno(code))
	}
	defer procLocalFree.Call(sd)
	var text *uint16
	var length uint32
	r, _, e := procConvertSecurityDescriptorToStringSecurityDescriptorW.Call(
		sd, 1, SACL_SECURITY_INFORMATION, uintptr(unsafe.Pointer(&text)), uintptr(unsafe.Pointer(&length)),
	)
	if r == 0 {
		return "", winErr("ConvertSecurityDescriptorToStringSecurityDescriptor", e)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(text)))
	return utf16FromPtr(text), nil
}

func addReadAuditRule(path string) error {
	if err := enablePrivilege("SeSecurityPrivilege"); err != nil {
		return err
	}
	var oldSACL, sd uintptr
	code, _, _ := procGetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(utf16Ptr(path))), SE_FILE_OBJECT, SACL_SECURITY_INFORMATION,
		0, 0, 0, uintptr(unsafe.Pointer(&oldSACL)), uintptr(unsafe.Pointer(&sd)),
	)
	if code != ERROR_SUCCESS {
		return fmt.Errorf("read existing auditing rules for %s: %w", path, syscall.Errno(code))
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
		return fmt.Errorf("build auditing rules for %s: %w", path, syscall.Errno(code))
	}
	defer procLocalFree.Call(newSACL)

	code, _, _ = procSetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(utf16Ptr(path))), SE_FILE_OBJECT, SACL_SECURITY_INFORMATION,
		0, 0, 0, newSACL,
	)
	if code != ERROR_SUCCESS {
		return fmt.Errorf("apply auditing rules to %s: %w", path, syscall.Errno(code))
	}
	return nil
}

func restoreSACL(path, sddl string) error {
	if err := enablePrivilege("SeSecurityPrivilege"); err != nil {
		return err
	}
	var sd uintptr
	var size uint32
	r, _, e := procConvertStringSecurityDescriptorToSecurityDescriptorW.Call(
		uintptr(unsafe.Pointer(utf16Ptr(sddl))), 1, uintptr(unsafe.Pointer(&sd)), uintptr(unsafe.Pointer(&size)),
	)
	if r == 0 {
		return winErr("ConvertStringSecurityDescriptorToSecurityDescriptor", e)
	}
	defer procLocalFree.Call(sd)
	r, _, e = procSetFileSecurityW.Call(uintptr(unsafe.Pointer(utf16Ptr(path))), SACL_SECURITY_INFORMATION, sd)
	if r == 0 {
		return fmt.Errorf("restore auditing rules for %s: %w", path, e)
	}
	return nil
}

func validateWatchFolder(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("folder path is empty")
	}
	if strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, `//`) {
		return "", errors.New("network and UNC folders must be monitored on the file server")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	info, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("the selected path is not a folder")
	}
	volume := filepath.VolumeName(abs)
	if strings.EqualFold(abs, volume) || strings.EqualFold(abs, volume+`\`) {
		return "", errors.New("watching an entire drive is blocked because it can generate extreme audit volume")
	}
	return abs, nil
}

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

func reconcileAuditRules(cfg *settings.Config, desired []string) []error {
	if cfg.Snapshots == nil {
		cfg.Snapshots = make(map[string]settings.AuditSnapshot)
	}
	desired = effectiveAuditRoots(desired)
	desiredKeys := make(map[string]string, len(desired))
	for _, path := range desired {
		desiredKeys[strings.ToLower(filepath.Clean(path))] = filepath.Clean(path)
	}

	var errs []error
	for key, snap := range cfg.Snapshots {
		if _, keep := desiredKeys[key]; keep {
			continue
		}
		current, err := getSACLSDDL(snap.Path)
		if err != nil {
			// A deleted watched folder has no SACL left to restore. Forget its
			// snapshot instead of making Stop or uninstall fail permanently.
			if errors.Is(err, syscall.Errno(ERROR_FILE_NOT_FOUND)) || errors.Is(err, syscall.Errno(ERROR_PATH_NOT_FOUND)) {
				delete(cfg.Snapshots, key)
				continue
			}
			errs = append(errs, err)
			continue
		}
		if current != snap.Applied {
			errs = append(errs, fmt.Errorf("auditing rules on %s changed outside ReadWatch; they were left untouched", snap.Path))
			continue
		}
		if err := restoreSACL(snap.Path, snap.Original); err != nil {
			errs = append(errs, err)
			continue
		}
		delete(cfg.Snapshots, key)
	}

	for key, path := range desiredKeys {
		if snap, ok := cfg.Snapshots[key]; ok {
			current, err := getSACLSDDL(path)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if current == snap.Applied {
				continue
			}
			if current == snap.Original {
				if err := addReadAuditRule(path); err != nil {
					errs = append(errs, err)
					continue
				}
				applied, err := getSACLSDDL(path)
				if err != nil {
					if restoreErr := restoreSACL(path, snap.Original); restoreErr != nil {
						errs = append(errs, fmt.Errorf("capture applied auditing rules for %s: %v; rollback also failed: %w", path, err, restoreErr))
					} else {
						errs = append(errs, fmt.Errorf("capture applied auditing rules for %s: %w", path, err))
					}
					continue
				}
				snap.Applied = applied
				cfg.Snapshots[key] = snap
				continue
			}
			errs = append(errs, fmt.Errorf("auditing rules on %s changed outside ReadWatch; monitoring that folder was not modified", path))
			continue
		}

		original, err := getSACLSDDL(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := addReadAuditRule(path); err != nil {
			errs = append(errs, err)
			continue
		}
		applied, err := getSACLSDDL(path)
		if err != nil {
			if restoreErr := restoreSACL(path, original); restoreErr != nil {
				errs = append(errs, fmt.Errorf("capture applied auditing rules for %s: %v; rollback also failed: %w", path, err, restoreErr))
			} else {
				errs = append(errs, fmt.Errorf("capture applied auditing rules for %s: %w", path, err))
			}
			continue
		}
		cfg.Snapshots[key] = settings.AuditSnapshot{Path: path, Original: original, Applied: applied}
	}
	return errs
}
