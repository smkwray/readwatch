//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"readwatch/internal/settings"
)

// Monitoring is a transaction over machine state: an audit-policy change and a
// SACL on every watched root. Each step is written to the configuration before
// it is made and confirmed after, so a crash anywhere leaves a record of what to
// undo. The record identifies objects by identity, never by the pathname that
// was used to reach them.

func (e *ServiceEngine) saveConfig(cfg *settings.Config) error {
	return settings.Save(paths().Config, *cfg)
}

// predictAppliedSACL is the SDDL the folder is expected to carry once the rule
// is added. It goes into the journal before the change, so a crash between the
// change and its confirmation can still be told apart from an unrelated edit.
func predictAppliedSACL(sacl uintptr, protected bool) (string, error) {
	sd := make([]byte, 64)
	if r, _, e := procInitializeSecurityDescriptor.Call(uintptr(unsafe.Pointer(&sd[0])), 1); r == 0 {
		return "", winErr("InitializeSecurityDescriptor", e)
	}
	if r, _, e := procSetSecurityDescriptorSacl.Call(uintptr(unsafe.Pointer(&sd[0])), 1, sacl, 0); r == 0 {
		return "", winErr("SetSecurityDescriptorSacl", e)
	}
	if protected {
		if r, _, e := procSetSecurityDescriptorControl.Call(uintptr(unsafe.Pointer(&sd[0])), SE_SACL_PROTECTED, SE_SACL_PROTECTED); r == 0 {
			return "", winErr("SetSecurityDescriptorControl", e)
		}
	}
	var text *uint16
	var length uint32
	if r, _, e := procConvertSecurityDescriptorToStringSecurityDescriptorW.Call(
		uintptr(unsafe.Pointer(&sd[0])), 1, SACL_SECURITY_INFORMATION,
		uintptr(unsafe.Pointer(&text)), uintptr(unsafe.Pointer(&length)),
	); r == 0 {
		return "", winErr("ConvertSecurityDescriptorToStringSecurityDescriptor", e)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(text)))
	return utf16FromPtr(text), nil
}

// applyAuditRule journals its intent, applies the rule through the retained
// handle, then confirms the object really carries what was intended.
func (e *ServiceEngine) applyAuditRule(cfg *settings.Config, folder FolderCapability) error {
	original, protected, err := readSACL(folder.Security)
	if err != nil {
		return fmt.Errorf("%s: %w", folder.Path, err)
	}
	key := folder.Identity.Key()
	if existing, ok := cfg.Snapshots[key]; ok && existing.Phase == settings.PhaseApplied {
		current, err := readSACLState(folder.Security)
		if err != nil {
			return fmt.Errorf("%s: %w", folder.Path, err)
		}
		applied, err := parseSACLState(existing.Applied)
		if err != nil {
			return fmt.Errorf("%s: parse the journalled applied auditing rules: %w", folder.Path, err)
		}
		if equivalentSACL(current, applied) {
			return nil
		}
		before, err := parseSACLState(existing.Original)
		if err != nil {
			return fmt.Errorf("%s: parse the journalled original auditing rules: %w", folder.Path, err)
		}
		if !equivalentSACL(current, before) {
			return fmt.Errorf("auditing rules on %s changed outside ReadWatch; they were left untouched", folder.Path)
		}
		original = existing.Original
	}

	predicted, err := e.predictRule(folder.Security, protected)
	if err != nil {
		return fmt.Errorf("%s: %w", folder.Path, err)
	}
	cfg.Snapshots[key] = settings.AuditSnapshot{
		Path:     folder.Path,
		Identity: folder.Identity,
		Original: original,
		Applied:  predicted,
		Phase:    settings.PhasePrepared,
	}
	if err := e.saveConfig(cfg); err != nil {
		delete(cfg.Snapshots, key)
		return err
	}
	if err := addReadAuditRule(folder.Security, protected); err != nil {
		return fmt.Errorf("%s: %w", folder.Path, err)
	}
	applied, err := readSACLState(folder.Security)
	if err != nil {
		return fmt.Errorf("%s: %w", folder.Path, err)
	}
	expected, err := parseSACLState(predicted)
	if err != nil {
		return fmt.Errorf("%s: parse the predicted auditing rules: %w", folder.Path, err)
	}
	if !equivalentSACL(applied, expected) {
		return fmt.Errorf("%s: the auditing rules did not take the value ReadWatch set", folder.Path)
	}
	snapshot := cfg.Snapshots[key]
	snapshot.Applied = applied.sddl
	snapshot.Phase = settings.PhaseApplied
	cfg.Snapshots[key] = snapshot
	return e.saveConfig(cfg)
}

// predictRule builds the rule without applying it, so the journal can record
// what the folder is about to look like.
func (e *ServiceEngine) predictRule(h HANDLE, protected bool) (string, error) {
	var oldSACL, sd uintptr
	code, _, _ := procGetSecurityInfo.Call(
		uintptr(h), SE_FILE_OBJECT, SACL_SECURITY_INFORMATION,
		0, 0, 0, uintptr(unsafe.Pointer(&oldSACL)), uintptr(unsafe.Pointer(&sd)),
	)
	if code != ERROR_SUCCESS {
		return "", fmt.Errorf("read existing auditing rules: %w", syscall.Errno(code))
	}
	defer procLocalFree.Call(sd)

	var everyoneSID uintptr
	if r, _, e := procConvertStringSidToSidW.Call(uintptr(unsafe.Pointer(utf16Ptr("S-1-1-0"))), uintptr(unsafe.Pointer(&everyoneSID))); r == 0 {
		return "", winErr("ConvertStringSidToSid", e)
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
		return "", fmt.Errorf("build auditing rules: %w", syscall.Errno(code))
	}
	defer procLocalFree.Call(newSACL)
	return predictAppliedSACL(newSACL, protected)
}

// removeAuditRule undoes one folder through a handle that is either still held
// from when the rule was applied, or reopened by identity after a restart.
func removeAuditRule(cfg *settings.Config, key string, snapshot settings.AuditSnapshot, held HANDLE, save func(*settings.Config) error) error {
	h := held
	if h == 0 {
		opened, err := openByIdentity(snapshot.Identity)
		if err != nil {
			// The volume may be absent, or the object deleted. Neither is a
			// reason to fail forever; the record is kept or dropped below.
			if strings.Contains(err.Error(), "no longer exists") {
				delete(cfg.Snapshots, key)
				return save(cfg)
			}
			return fmt.Errorf("%s: %w", snapshot.Path, err)
		}
		defer closeHandle(opened)
		h = opened
	}
	current, err := readSACLState(h)
	if err != nil {
		return fmt.Errorf("%s: %w", snapshot.Path, err)
	}
	applied, err := parseSACLState(snapshot.Applied)
	if err != nil {
		return fmt.Errorf("%s: parse the journalled applied auditing rules: %w", snapshot.Path, err)
	}
	original, err := parseSACLState(snapshot.Original)
	if err != nil {
		return fmt.Errorf("%s: parse the journalled original auditing rules: %w", snapshot.Path, err)
	}
	switch {
	case equivalentSACL(current, applied):
		if err := restoreSACL(h, snapshot.Original); err != nil {
			return fmt.Errorf("%s: %w", snapshot.Path, err)
		}
		verify, err := readSACLState(h)
		if err != nil {
			return fmt.Errorf("%s: %w", snapshot.Path, err)
		}
		if !equivalentSACL(verify, original) {
			return fmt.Errorf("%s: the auditing rules did not return to what ReadWatch found", snapshot.Path)
		}
	case equivalentSACL(current, original):
		// Already back where it started. This also accepts an empty,
		// unprotected ACL for an originally absent SACL, but never a null SACL.
	default:
		// Somebody else owns this now. Leaving it alone is the only safe move,
		// and the record stays so the conflict remains visible.
		return fmt.Errorf("auditing rules on %s changed outside ReadWatch; they were left untouched", snapshot.Path)
	}
	delete(cfg.Snapshots, key)
	return save(cfg)
}

// recoverJournal resolves records left by a previous process. It runs before any
// new monitoring starts, and reaches every object by identity because the paths
// in those records are the one thing that may have changed underneath.
func recoverJournal(cfg *settings.Config, save func(*settings.Config) error) error {
	var first error
	err := withPrivilege("SeSecurityPrivilege", func() error {
		for key, snapshot := range cfg.Snapshots {
			if snapshot.Identity.Zero() {
				// Nothing identifies this object; a path is not enough to act on.
				continue
			}
			if err := removeAuditRule(cfg, key, snapshot, 0, save); err != nil && first == nil {
				first = err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if cfg.AuditPolicy != nil {
		if err := restoreFileSystemAuditPolicy(cfg, save); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// startMonitoringBound is the whole Start transaction. Nothing privileged
// happens until every configured object has been opened under the caller's own
// token, so a folder the owner cannot reach never becomes something SYSTEM
// touches on their behalf.
func (e *ServiceEngine) startMonitoringBound(pipe HANDLE, clearError bool) error {
	if e.watcher.Running() {
		return nil
	}
	e.mu.RLock()
	cfg := cloneConfig(e.cfg)
	e.mu.RUnlock()
	if len(cfg.Folders) == 0 {
		return errors.New("add at least one folder before starting")
	}

	bound, err := bindPublicConfigAsPipeClient(pipe, cfg.OwnerSID, cfg.Public())
	if err != nil {
		return err
	}
	if err := e.resumeIdentitiesMatch(&cfg, bound); err != nil {
		bound.Close()
		return err
	}
	if err := recoverJournal(&cfg, e.saveConfig); err != nil {
		bound.Close()
		return err
	}
	if err := e.startWithCapabilities(&cfg, bound, clearError); err != nil {
		bound.Close()
		return err
	}
	return nil
}

// resumeIdentitiesMatch refuses to reuse an authorisation for a different
// object. A folder that has been replaced since the owner last approved it gets
// a fresh decision from them, not an automatic one from a stored pathname.
func (e *ServiceEngine) resumeIdentitiesMatch(cfg *settings.Config, bound *BoundConfig) error {
	if len(cfg.FolderBindings) == 0 && cfg.LogBinding == nil {
		return nil
	}
	for _, folder := range bound.Folders {
		expected, ok := cfg.FolderBindings[strings.ToLower(folder.Path)]
		if !ok || expected.Identity.Zero() {
			continue
		}
		if !expected.Identity.Equal(folder.Identity) {
			return fmt.Errorf("%s now refers to a different folder than the one ReadWatch was set up to watch; review Settings and press Start to authorise it", folder.Path)
		}
	}
	if cfg.LogBinding != nil && !cfg.LogBinding.Identity.Zero() && !cfg.LogBinding.Identity.Equal(bound.Log.Identity) {
		return fmt.Errorf("%s is not the log file ReadWatch was set up to write to; review Settings and press Start to authorise it", bound.Log.Path)
	}
	return nil
}

// startWithCapabilities applies the machine changes and starts the watcher. On
// any failure it unwinds through the same handles it applied with.
func (e *ServiceEngine) startWithCapabilities(cfg *settings.Config, bound *BoundConfig, clearError bool) error {
	roots := effectiveAuditRoots(bound.Public.Folders)
	applied := make([]FolderCapability, 0, len(roots))

	rollback := func() {
		_ = withPrivilege("SeSecurityPrivilege", func() error {
			for i := len(applied) - 1; i >= 0; i-- {
				key := applied[i].Identity.Key()
				if snapshot, ok := cfg.Snapshots[key]; ok {
					if err := removeAuditRule(cfg, key, snapshot, applied[i].Security, e.saveConfig); err != nil {
						writeServiceDiagnostic(err)
					}
				}
			}
			return nil
		})
		if err := restoreFileSystemAuditPolicy(cfg, e.saveConfig); err != nil {
			writeServiceDiagnostic(err)
		}
	}

	if err := ensureFileSystemAuditPolicy(cfg, e.saveConfig); err != nil {
		return err
	}
	err := withPrivilege("SeSecurityPrivilege", func() error {
		for _, root := range roots {
			capability := bound.folderByPath(root)
			if capability == nil {
				return fmt.Errorf("%s: no open handle for this folder", root)
			}
			if err := e.applyAuditRule(cfg, *capability); err != nil {
				return err
			}
			applied = append(applied, *capability)
		}
		return nil
	})
	if err != nil {
		rollback()
		return err
	}

	cfg.ApplyPublic(bound.Public)
	cfg.FolderBindings, cfg.LogBinding = bound.Bindings()
	cfg.Enabled = true
	if err := e.saveConfig(cfg); err != nil {
		rollback()
		return err
	}

	logFile, err := duplicateLogForWatcher(bound.Log.Master)
	if err != nil {
		rollback()
		return err
	}
	if err := e.watcher.Start(*cfg, logFile); err != nil {
		rollback()
		cfg.Enabled = false
		_ = e.saveConfig(cfg)
		return err
	}

	e.mu.Lock()
	previous := e.active
	e.active = bound
	e.cfg = *cfg
	if clearError {
		e.lastError = ""
	}
	e.mu.Unlock()
	previous.Close()
	return nil
}

// duplicateLogForWatcher hands the watcher its own reference to the same open
// file. The master stays with the service so a watcher restart does not have to
// resolve the pathname again.
func duplicateLogForWatcher(master HANDLE) (*os.File, error) {
	if master == 0 {
		return nil, errors.New("the log file is not open")
	}
	process := procGetCurrentProcessHandle()
	var dup HANDLE
	r, _, e := procDuplicateHandle.Call(
		process, uintptr(master), process,
		uintptr(unsafe.Pointer(&dup)), 0, 0, DUPLICATE_SAME_ACCESS,
	)
	if r == 0 {
		return nil, winErr("DuplicateHandle(log)", e)
	}
	return os.NewFile(uintptr(dup), "ReadWatch.log"), nil
}

// stopMonitoringLocked withdraws every machine change through the handles that
// made them, then releases the capabilities. opMu is already held.
func (e *ServiceEngine) stopMonitoringLocked(removeRules bool, clearEnabled bool) error {
	e.watcher.Stop()
	e.mu.RLock()
	cfg := cloneConfig(e.cfg)
	active := e.active
	e.mu.RUnlock()

	var first error
	if removeRules {
		err := withPrivilege("SeSecurityPrivilege", func() error {
			for key, snapshot := range cfg.Snapshots {
				var held HANDLE
				if active != nil {
					if capability := active.folderByPath(snapshot.Path); capability != nil {
						held = capability.Security
					}
				}
				if err := removeAuditRule(&cfg, key, snapshot, held, e.saveConfig); err != nil && first == nil {
					first = err
				}
			}
			return nil
		})
		if err != nil && first == nil {
			first = err
		}
		if err := restoreFileSystemAuditPolicy(&cfg, e.saveConfig); err != nil && first == nil {
			first = err
		}
		if clearEnabled {
			cfg.Enabled = false
		}
	}
	if err := e.saveConfig(&cfg); err != nil && first == nil {
		first = err
	}

	e.mu.Lock()
	e.cfg = cfg
	released := e.active
	e.active = nil
	if first == nil {
		e.lastError = ""
	} else {
		e.lastError = first.Error()
	}
	e.mu.Unlock()
	released.Close()
	return first
}

// applyBound swaps one configuration for another. The candidate is opened in
// full before the running one is disturbed, and the old capabilities are kept
// until the new ones are live so a failed transition can be undone through
// handles rather than names.
func (e *ServiceEngine) applyBound(pipe HANDLE, public settings.PublicConfig) error {
	e.opMu.Lock()
	defer e.opMu.Unlock()
	if err := e.rejectIfStopping(); err != nil {
		return err
	}

	e.mu.RLock()
	cfg := cloneConfig(e.cfg)
	e.mu.RUnlock()
	wasRunning := e.watcher.Running()

	candidate, err := bindPublicConfigAsPipeClient(pipe, cfg.OwnerSID, public)
	if err != nil {
		return err
	}

	if !wasRunning {
		// Nothing privileged is in force, so this only records the choice. The
		// log file may have been created during binding, under the owner's own
		// authority.
		cfg.ApplyPublic(candidate.Public)
		cfg.FolderBindings, cfg.LogBinding = candidate.Bindings()
		if err := e.saveConfig(&cfg); err != nil {
			candidate.Close()
			return err
		}
		candidate.Close()
		e.mu.Lock()
		e.cfg = cfg
		e.lastError = ""
		e.mu.Unlock()
		return nil
	}

	e.mu.RLock()
	old := e.active
	oldCfg := cloneConfig(e.cfg)
	e.mu.RUnlock()

	e.watcher.Stop()
	// Withdraw the old rules through the old handles before applying the new
	// ones, keeping the audit policy in place across the swap.
	removeErr := withPrivilege("SeSecurityPrivilege", func() error {
		var first error
		for key, snapshot := range oldCfg.Snapshots {
			var held HANDLE
			if old != nil {
				if capability := old.folderByPath(snapshot.Path); capability != nil {
					held = capability.Security
				}
			}
			if err := removeAuditRule(&oldCfg, key, snapshot, held, e.saveConfig); err != nil && first == nil {
				first = err
			}
		}
		return first
	})
	if removeErr != nil {
		candidate.Close()
		e.restoreRunning(old, &oldCfg)
		return removeErr
	}

	cfg = cloneConfig(oldCfg)
	if err := e.startWithCapabilities(&cfg, candidate, true); err != nil {
		candidate.Close()
		e.restoreRunning(old, &oldCfg)
		return err
	}
	return nil
}

// restoreRunning puts the previous configuration back after a failed swap,
// using the handles it was applied with. If that fails too, monitoring stays off
// and the journal keeps whatever is unresolved: claiming the old configuration
// is running when it is not would be worse than saying so.
func (e *ServiceEngine) restoreRunning(old *BoundConfig, oldCfg *settings.Config) {
	if old == nil {
		return
	}
	if err := e.startWithCapabilities(oldCfg, old, false); err != nil {
		writeServiceDiagnostic(fmt.Errorf("restore the previous configuration: %w", err))
		e.setLastError(fmt.Errorf("monitoring is stopped: the change failed and the previous settings could not be restored (%v)", err))
	}
}

// recoverJournalOffline resolves outstanding records with no running engine,
// which is the uninstall path when the service cannot be reached. It reaches
// every object by identity for the same reason the online path does.
func recoverJournalOffline(cfg *settings.Config) error {
	save := func(c *settings.Config) error { return settings.Save(paths().Config, *c) }
	return recoverJournal(cfg, save)
}
