//go:build windows

package main

import (
	"bytes"
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

// saclState is the security-relevant part of a SACL snapshot. Windows may add
// automatic-inheritance bookkeeping when it writes a descriptor, so AI/AR are
// deliberately not part of equality. SDDL also cannot persist SE_SACL_DEFAULTED.
// Protection, nullness, ACL revision and every ordered ACE byte are compared.
// Unused ACL buffer capacity is not security state and is deliberately excluded.
type saclState struct {
	sddl      string
	protected bool
	present   bool
	null      bool
	revision  uint32
	aces      [][]byte
}

type aclRevisionInformation struct {
	revision uint32
}

type aclSizeInformation struct {
	aceCount   uint32
	bytesInUse uint32
	bytesFree  uint32
}

type aceHeader struct {
	type_ uint8
	flags uint8
	size  uint16
}

// readSACL reports a handle's audit entries and whether they are protected from
// inheritance. Restoring one without the other would silently change the
// folder's relationship to its parent.
func readSACL(h HANDLE) (string, bool, error) {
	state, err := readSACLState(h)
	if err != nil {
		return "", false, err
	}
	return state.sddl, state.protected, nil
}

func readSACLState(h HANDLE) (saclState, error) {
	var sacl uintptr
	var sd uintptr
	code, _, _ := procGetSecurityInfo.Call(
		uintptr(h), SE_FILE_OBJECT, SACL_SECURITY_INFORMATION,
		0, 0, 0, uintptr(unsafe.Pointer(&sacl)), uintptr(unsafe.Pointer(&sd)),
	)
	if code != ERROR_SUCCESS {
		return saclState{}, fmt.Errorf("read auditing rules: %w", syscall.Errno(code))
	}
	defer procLocalFree.Call(sd)

	var text *uint16
	var length uint32
	r, _, e := procConvertSecurityDescriptorToStringSecurityDescriptorW.Call(
		sd, 1, SACL_SECURITY_INFORMATION, uintptr(unsafe.Pointer(&text)), uintptr(unsafe.Pointer(&length)),
	)
	if r == 0 {
		return saclState{}, winErr("ConvertSecurityDescriptorToStringSecurityDescriptor", e)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(text)))
	return saclStateFromDescriptor(sd, utf16FromPtr(text))
}

func parseSACLState(sddl string) (saclState, error) {
	var sd uintptr
	var size uint32
	r, _, e := procConvertStringSecurityDescriptorToSecurityDescriptorW.Call(
		uintptr(unsafe.Pointer(utf16Ptr(sddl))), 1, uintptr(unsafe.Pointer(&sd)), uintptr(unsafe.Pointer(&size)),
	)
	if r == 0 {
		return saclState{}, winErr("ConvertStringSecurityDescriptorToSecurityDescriptor", e)
	}
	defer procLocalFree.Call(sd)
	return saclStateFromDescriptor(sd, sddl)
}

func saclStateFromDescriptor(sd uintptr, sddl string) (saclState, error) {
	var control uint16
	var sdRevision uint32
	r, _, e := procGetSecurityDescriptorControl.Call(sd, uintptr(unsafe.Pointer(&control)), uintptr(unsafe.Pointer(&sdRevision)))
	if r == 0 {
		return saclState{}, winErr("GetSecurityDescriptorControl", e)
	}

	var present, defaulted int32
	var sacl uintptr
	r, _, e = procGetSecurityDescriptorSacl.Call(
		sd, uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&sacl)), uintptr(unsafe.Pointer(&defaulted)),
	)
	if r == 0 {
		return saclState{}, winErr("GetSecurityDescriptorSacl", e)
	}

	state := saclState{
		sddl:      sddl,
		protected: control&SE_SACL_PROTECTED != 0,
		present:   present != 0,
	}
	if !state.present {
		return state, nil
	}
	if sacl == 0 {
		state.null = true
		return state, nil
	}

	var aclRevision aclRevisionInformation
	r, _, e = procGetAclInformation.Call(
		sacl, uintptr(unsafe.Pointer(&aclRevision)), unsafe.Sizeof(aclRevision), ACL_REVISION_INFORMATION,
	)
	if r == 0 {
		return saclState{}, winErr("GetAclInformation(revision)", e)
	}
	var size aclSizeInformation
	r, _, e = procGetAclInformation.Call(
		sacl, uintptr(unsafe.Pointer(&size)), unsafe.Sizeof(size), ACL_SIZE_INFORMATION,
	)
	if r == 0 {
		return saclState{}, winErr("GetAclInformation(size)", e)
	}

	state.revision = aclRevision.revision
	state.aces = make([][]byte, 0, size.aceCount)
	for i := uint32(0); i < size.aceCount; i++ {
		var ace *aceHeader
		r, _, e = procGetAce.Call(sacl, uintptr(i), uintptr(unsafe.Pointer(&ace)))
		if r == 0 {
			return saclState{}, winErr("GetAce", e)
		}
		if ace == nil || ace.size < uint16(unsafe.Sizeof(aceHeader{})) {
			return saclState{}, errors.New("the auditing rules contain an invalid ACE header")
		}
		state.aces = append(state.aces, append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(ace)), int(ace.size))...))
	}
	return state, nil
}

// equivalentSACL is deliberately stricter than an effective-access check. It
// requires the same protection state, ACL revision and ordered ACE bytes. The only
// normalisations are:
//   - AI/AR are automatic-inheritance bookkeeping and are not compared; and
//   - absent, null and valid empty SACLs are equivalent only while both are
//     unprotected. All three contain no ACEs and remain open to inheritance.
//
// A protected null SACL remains distinct from an absent or valid empty SACL.
// describeSACL renders a state for a message the owner has to act on. An empty
// SDDL means the object has no SACL at all, which reads as nothing unless it is
// spelled out.
func describeSACL(s saclState) string {
	if s.sddl == "" {
		return "no auditing rules at all"
	}
	return s.sddl
}

func equivalentSACL(left, right saclState) bool {
	if left.protected != right.protected {
		return false
	}
	if !left.protected && left.noAuditACEs() && right.noAuditACEs() {
		return true
	}
	if left.null || right.null {
		return left.present == right.present && left.null == right.null
	}
	if left.present != right.present || left.revision != right.revision || len(left.aces) != len(right.aces) {
		return false
	}
	for i := range left.aces {
		if !bytes.Equal(left.aces[i], right.aces[i]) {
			return false
		}
	}
	return true
}

func (s saclState) noAuditACEs() bool {
	return !s.present || s.null || len(s.aces) == 0
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

// restoreSACL restores the captured audit state. SetSecurityInfo has no
// bSaclPresent input: with SACL_SECURITY_INFORMATION, a nil pSacl assigns a
// present null SACL rather than clearing SE_SACL_PRESENT. An absent original is
// therefore restored by revoking ReadWatch's sole Everyone audit entry from the
// current ACL and writing the resulting valid empty ACL as unprotected. Windows
// may retain that empty ACL or normalise it to an unprotected null SACL and add
// AI. equivalentSACL accepts those zero-ACE inheriting representations, while
// keeping protected null distinct.
func restoreSACL(h HANDLE, sddl string) error {
	original, err := parseSACLState(sddl)
	if err != nil {
		return err
	}
	if !original.present {
		return restoreAbsentSACL(h, original.protected)
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

	var present, defaulted int32
	var sacl uintptr
	r, _, e = procGetSecurityDescriptorSacl.Call(sd, uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&sacl)), uintptr(unsafe.Pointer(&defaulted)))
	if r == 0 {
		return winErr("GetSecurityDescriptorSacl", e)
	}
	if present == 0 {
		return errors.New("the captured auditing rules unexpectedly have no SACL")
	}
	code, _, _ := procSetSecurityInfo.Call(
		uintptr(h), SE_FILE_OBJECT, saclSecurityInformation(original.protected),
		0, 0, 0, sacl,
	)
	if code != ERROR_SUCCESS {
		return fmt.Errorf("restore auditing rules: %w", syscall.Errno(code))
	}
	return nil
}

// restoreAbsentSACL is called only after the caller has proved that the current
// descriptor still matches the state ReadWatch applied. With an absent original
// there were no pre-existing audit ACEs, so revoking Everyone removes only the
// rule ReadWatch added. SetEntriesInAcl must return a real empty ACL; passing nil
// back to SetSecurityInfo would recreate the protected-null bug this path fixes.
func restoreAbsentSACL(h HANDLE, protected bool) error {
	var oldSACL, sd uintptr
	code, _, _ := procGetSecurityInfo.Call(
		uintptr(h), SE_FILE_OBJECT, SACL_SECURITY_INFORMATION,
		0, 0, 0, uintptr(unsafe.Pointer(&oldSACL)), uintptr(unsafe.Pointer(&sd)),
	)
	if code != ERROR_SUCCESS {
		return fmt.Errorf("read auditing rules for removal: %w", syscall.Errno(code))
	}
	defer procLocalFree.Call(sd)

	var everyoneSID uintptr
	r, _, e := procConvertStringSidToSidW.Call(uintptr(unsafe.Pointer(utf16Ptr("S-1-1-0"))), uintptr(unsafe.Pointer(&everyoneSID)))
	if r == 0 {
		return winErr("ConvertStringSidToSid", e)
	}
	defer procLocalFree.Call(everyoneSID)

	ea := EXPLICITACCESSW{AccessMode: REVOKE_ACCESS}
	procBuildTrusteeWithSidW.Call(uintptr(unsafe.Pointer(&ea.Trustee)), everyoneSID)

	var newSACL uintptr
	code, _, _ = procSetEntriesInAclW.Call(1, uintptr(unsafe.Pointer(&ea)), oldSACL, uintptr(unsafe.Pointer(&newSACL)))
	if code != ERROR_SUCCESS {
		return fmt.Errorf("remove ReadWatch auditing rule: %w", syscall.Errno(code))
	}
	if newSACL == 0 {
		return errors.New("remove ReadWatch auditing rule: Windows returned a null ACL")
	}
	defer procLocalFree.Call(newSACL)

	code, _, _ = procSetSecurityInfo.Call(
		uintptr(h), SE_FILE_OBJECT, saclSecurityInformation(protected),
		0, 0, 0, newSACL,
	)
	if code != ERROR_SUCCESS {
		return fmt.Errorf("restore absent auditing rules: %w", syscall.Errno(code))
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
