//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"sort"
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
	var current saclState
	haveCurrent := false
	if h != 0 {
		state, err := readSACLState(h)
		if err == nil {
			current, haveCurrent = state, true
		} else {
			// The handle the rule was applied through has stopped working, which is
			// exactly what a drive being pulled out looks like from in here. Fall
			// through to the reopen: it is the only path that can tell "not attached"
			// from "gone", so a stale handle used to be worse than no handle at all.
			h = 0
		}
	}
	if !haveCurrent {
		opened, err := openByIdentity(snapshot.Identity)
		if err != nil {
			// Three outcomes, and only one of them may forget the record.
			//
			// A condition that will clear on its own is worth waiting for: the
			// folder is still there and so is the rule.
			if transientOpenFailure(err) {
				return fmt.Errorf("%s: %w", snapshot.Path, err)
			}
			if errors.Is(err, errObjectGone) {
				// An audit rule lives on the object, so it went with it. There is
				// nothing to restore and nothing that will ever make this record
				// actionable - keeping it blocks Stop, Apply and uninstall
				// permanently, which is exactly what it used to do.
				writeServiceDiagnostic(fmt.Errorf("%s: forgetting the audit record, the folder no longer exists: %w", snapshot.Path, err))
				delete(cfg.Snapshots, key)
				return save(cfg)
			}
			// Anything else is indeterminate: the volume is attached and the object
			// could not be reached, but nothing here establishes that it is gone.
			// Keep the record and report it. Being visibly stuck is recoverable;
			// silently abandoning a rule that is still applied is not.
			return fmt.Errorf("%s: %w", snapshot.Path, err)
		}
		defer closeHandle(opened)
		h = opened
		if current, err = readSACLState(h); err != nil {
			return fmt.Errorf("%s: %w", snapshot.Path, err)
		}
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
		// Already back where it started. This also accepts a valid empty or null
		// unprotected SACL for an originally absent SACL, but never protected null.
	default:
		// The rules are neither what ReadWatch applied nor what it found, so
		// somebody else has changed them and they are left alone. The record is
		// dropped rather than kept: ReadWatch no longer owns this state, and a
		// record it will never be able to act on blocks Stop, Apply and uninstall
		// permanently. Same reasoning as the audit policy, which already does
		// this. Reported once, then forgotten.
		writeServiceDiagnostic(fmt.Errorf("auditing rules on %s changed outside ReadWatch; they were left untouched and ReadWatch has stopped tracking them", snapshot.Path))
	}
	delete(cfg.Snapshots, key)
	return save(cfg)
}

// recoverJournal resolves records left by a previous process. It runs before any
// new monitoring starts, and reaches every object by identity because the paths
// in those records are the one thing that may have changed underneath.
// It returns the records it could not resolve because the disk holding them is
// not in the machine. Those are kept, not forgotten: the audit rule is still on
// that disk, and forgetting the record would abandon it there for good.
func recoverJournal(cfg *settings.Config, save func(*settings.Config) error) ([]string, error) {
	var first error
	var deferred []string
	err := withPrivilege("SeSecurityPrivilege", func() error {
		for key, snapshot := range cfg.Snapshots {
			if snapshot.Identity.Zero() {
				// Nothing identifies this object; a path is not enough to act on.
				continue
			}
			if err := removeAuditRule(cfg, key, snapshot, 0, save); err != nil {
				if deferredRemoval(err) {
					deferred = append(deferred, snapshot.Path)
					continue
				}
				if first == nil {
					first = err
				}
			}
		}
		return nil
	})
	sort.Strings(deferred)
	if err != nil {
		return deferred, err
	}
	if cfg.AuditPolicy != nil {
		if err := restoreFileSystemAuditPolicy(cfg, save); err != nil && first == nil {
			first = err
		}
	}
	return deferred, first
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

	// Which mechanism runs is decided before anything privileged happens, because
	// it decides whether anything privileged happens at all: event tracing writes
	// no marker and needs no audit-policy change.
	choice := settings.ChooseMechanism(cfg.Mechanism, markerCapability(cfg.Folders))
	e.setMechanism(choice)

	bound, err := bindPublicConfigAsPipeClient(pipe, cfg.OwnerSID, cfg.Public(), choice.Use == settings.MechanismETW)
	if err != nil {
		return err
	}
	refuseChangedIdentities(&cfg, bound)
	e.setFolderStatus(bound)
	if err := logIdentityMatches(&cfg, bound); err != nil {
		bound.Close()
		return err
	}
	deferred, err := recoverJournal(&cfg, e.saveConfig)
	e.setPendingRules(deferred)
	if err != nil {
		bound.Close()
		return err
	}
	if err := e.startWithCapabilities(&cfg, bound, choice, clearError); err != nil {
		bound.Close()
		return err
	}
	return nil
}

// errNoFolderAvailable means every configured folder is somewhere ReadWatch
// cannot reach at the moment. With a watched folder on a drive that is not
// always plugged in this is a resting state rather than a fault, so it is a
// value callers can recognise instead of one more error string.
var errNoFolderAvailable = errors.New("none of the watched folders are available right now")

// refuseChangedIdentities takes out of the attached set any folder that no
// longer refers to the object the owner authorised. It is per folder rather than
// fatal: a substituted folder must not be watched, and it must not stop the
// folders that are still what they were from being watched either.
//
// A folder with no recorded binding has never been opened successfully - it was
// added while its drive was out, which is now a supported way to add one - and
// this bind is its authorisation. That is only safe because a binding survives
// its folder being unreachable (BoundConfig.MergeBindings), so "no binding" can
// never mean "the binding was lost while the drive was out".
func refuseChangedIdentities(cfg *settings.Config, bound *BoundConfig) {
	for i := len(bound.Folders) - 1; i >= 0; i-- {
		expected, ok := cfg.FolderBindings[strings.ToLower(bound.Folders[i].Path)]
		if !ok || expected.Identity.Zero() || expected.Identity.Equal(bound.Folders[i].Identity) {
			continue
		}
		bound.markUnavailable(i, errors.New("this path now refers to a different folder than the one ReadWatch was set up to watch; open Settings and press Save to authorise the folder that is there now"), false)
	}
}

// refuseIdentityBearingChange rejects an apply that did not claim to be an owner
// decision but would change which objects ReadWatch is pointed at. The watched
// folders and the log are the only two settings that name an object; everything
// else is a preference and may be changed by anything.
//
// Without this, an apply sent for some unrelated reason - excluding a process,
// putting a sign-in setting back - could introduce a path that has no recorded
// binding, and a path with no binding is treated as one being authorised for the
// first time. The owner would have approved a process exclusion and got a new
// watched object.
func refuseIdentityBearingChange(cfg *settings.Config, public *settings.PublicConfig) error {
	normalized := *cfg
	normalized.Folders = append([]string(nil), public.Folders...)
	normalized.LogPath = public.LogPath
	normalized.Normalize()

	current := cfg.Public()
	if !strings.EqualFold(normalized.LogPath, current.LogPath) {
		return errors.New("this change would point ReadWatch at a different log file; open Settings and press Save to make it")
	}
	if len(normalized.Folders) != len(current.Folders) {
		return errors.New("this change would alter the watched folders; open Settings and press Save to make it")
	}
	for i := range normalized.Folders {
		if !strings.EqualFold(normalized.Folders[i], current.Folders[i]) {
			return errors.New("this change would alter the watched folders; open Settings and press Save to make it")
		}
	}
	return nil
}

// logIdentityMatches keeps the log all or nothing. There is no partial state for
// the one file every event has to be written to, so a substituted log is refused
// outright rather than skipped.
func logIdentityMatches(cfg *settings.Config, bound *BoundConfig) error {
	if cfg.LogBinding == nil || cfg.LogBinding.Identity.Zero() {
		return nil
	}
	if !cfg.LogBinding.Identity.Equal(bound.Log.Identity) {
		// Save is what re-authorises, here as for a folder. Telling the owner to
		// press Start would send them round the same refusal every time.
		return fmt.Errorf("%s is not the log file ReadWatch was set up to write to; open Settings and press Save to authorise the file that is there now", bound.Log.Path)
	}
	return nil
}

// startWithCapabilities applies the machine changes and starts the watcher. On
// any failure it unwinds through the same handles it applied with.
func (e *ServiceEngine) startWithCapabilities(cfg *settings.Config, bound *BoundConfig, choice settings.MechanismChoice, clearError bool) error {
	// Only folders that were actually opened get a rule. Driving this from the
	// configured list instead would ask for a handle that does not exist, and
	// would do so after the audit policy had already been changed.
	roots := effectiveAuditRoots(bound.AttachedPaths())
	if len(roots) == 0 {
		// Nothing reachable to watch. Stopping here is what keeps the machine-wide
		// audit policy from being switched on with no folder carrying a rule: a
		// change to the machine, a live Security-log subscription, and nothing
		// being watched to show for either.
		return errNoFolderAvailable
	}
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

	// Under event tracing nothing is written to any volume and the machine-wide
	// audit policy is not touched, so there is nothing to apply and nothing to
	// unwind. Skipping it is the point of the mechanism, not an optimisation.
	if choice.Use == settings.MechanismMarkers {
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
	}

	cfg.ApplyPublic(bound.Public)
	cfg.FolderBindings, cfg.LogBinding = bound.MergeBindings(cfg.FolderBindings)
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
	// The watcher matches event paths textually, so it is given the folders that
	// carry a rule rather than every configured one. Otherwise a drive letter
	// reclaimed by some other volume while its own folder is unreachable would
	// have reads under it reported as if they came from the watched folder.
	watchCfg := cloneConfig(*cfg)
	watchCfg.Folders = append([]string(nil), bound.AttachedPaths()...)
	if err := e.watcher.Start(watchCfg, logFile, choice.Use); err != nil {
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
	// restoreRunning reinstates the capability set that is already active, so the
	// two can be the same value; closing it then would drop the handles that hold
	// the watched folders still.
	if previous != bound {
		previous.Close()
	}
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
	var deferred []string
	if removeRules {
		err := withPrivilege("SeSecurityPrivilege", func() error {
			for key, snapshot := range cfg.Snapshots {
				var held HANDLE
				if active != nil {
					if capability := active.folderByPath(snapshot.Path); capability != nil {
						held = capability.Security
					}
				}
				if err := removeAuditRule(&cfg, key, snapshot, held, e.saveConfig); err != nil {
					// A rule on a disk that is not in the machine cannot be removed
					// now and will be removable later. Reporting it as a failure would
					// leave a warning on screen that nothing can clear, and clearing it
					// silently would abandon a rule ReadWatch still owns. It is kept,
					// counted and named instead.
					if deferredRemoval(err) {
						deferred = append(deferred, snapshot.Path)
						continue
					}
					if first == nil {
						first = err
					}
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
	sort.Strings(deferred)
	if err := e.saveConfig(&cfg); err != nil && first == nil {
		first = err
	}

	e.mu.Lock()
	e.cfg = cfg
	e.pendingRules = deferred
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
//
// authorise says whether this is the owner making a decision. A Save is: it
// records whatever object each configured path names now. A refresh triggered by
// a drive appearing is not, so an identity that has changed under a path is
// refused there rather than quietly approved by a device event nobody asked for.
func (e *ServiceEngine) applyBound(pipe HANDLE, public settings.PublicConfig, authorise bool) error {
	e.opMu.Lock()
	defer e.opMu.Unlock()
	if err := e.rejectIfStopping(); err != nil {
		return err
	}

	e.mu.RLock()
	cfg := cloneConfig(e.cfg)
	e.mu.RUnlock()
	wasRunning := e.watcher.Running()

	// The flag says what the sender meant; this says what the service will let
	// that mean. A message is not authority on its own, so an apply that does not
	// claim to be an owner decision may not carry one: it may change settings, and
	// it may not change which objects ReadWatch is pointed at.
	if !authorise {
		if err := refuseIdentityBearingChange(&cfg, &public); err != nil {
			return err
		}
	}

	// The candidate's own folders decide the candidate's mechanism, and that
	// decides whether a volume with no file identity may be admitted. Using the
	// running configuration's answer here would let a folder be admitted under a
	// mechanism the apply is about to replace.
	candidateChoice := settings.ChooseMechanism(public.Mechanism, markerCapability(public.Folders))
	candidate, err := bindPublicConfigAsPipeClient(pipe, cfg.OwnerSID, public, candidateChoice.Use == settings.MechanismETW)
	if err != nil {
		return err
	}
	if !authorise {
		refuseChangedIdentities(&cfg, candidate)
		// Before anything is disturbed. The log has no per-folder state to fall
		// back on, and going any further would overwrite the recorded identity
		// with the substitute's - after which nothing could ever notice it again.
		if err := logIdentityMatches(&cfg, candidate); err != nil {
			candidate.Close()
			return err
		}
	}
	e.setFolderStatus(candidate)

	if !wasRunning {
		// Nothing privileged is in force, so this only records the choice. The
		// log file may have been created during binding, under the owner's own
		// authority.
		//
		// Monitoring being off also means any record still in the journal is a
		// rule that should not exist. If the drive carrying it has come back, this
		// is the moment to remove it - a refresh while stopped is otherwise the
		// one path that reaches the service with a drive newly attached and does
		// nothing about it.
		var recoverErr error
		if len(cfg.Snapshots) > 0 || cfg.AuditPolicy != nil {
			var deferred []string
			deferred, recoverErr = recoverJournal(&cfg, e.saveConfig)
			e.setPendingRules(deferred)
			if recoverErr != nil {
				writeServiceDiagnostic(recoverErr)
			}
		}
		recordErr := e.recordBound(&cfg, candidate)
		// A rule that could not be withdrawn outranks a successful save. Returning
		// the save's success here would tell the viewer the new configuration is
		// cleanly in force while ReadWatch still owns a change it failed to undo.
		if recoverErr != nil {
			e.setLastError(recoverErr)
			return recoverErr
		}
		return recordErr
	}

	e.mu.RLock()
	old := e.active
	oldCfg := cloneConfig(e.cfg)
	e.mu.RUnlock()

	e.watcher.Stop()
	// Withdraw the old rules through the old handles before applying the new
	// ones, keeping the audit policy in place across the swap.
	var removeErr error
	var deferred []string
	privErr := withPrivilege("SeSecurityPrivilege", func() error {
		for key, snapshot := range oldCfg.Snapshots {
			var held HANDLE
			if old != nil {
				if capability := old.folderByPath(snapshot.Path); capability != nil {
					held = capability.Security
				}
			}
			if err := removeAuditRule(&oldCfg, key, snapshot, held, e.saveConfig); err != nil {
				// The drive this rule is on left. That must not abandon the change:
				// refusing here is what stopped the owner removing the dead folder
				// from the list, since keeping it failed at bind and dropping it
				// failed here.
				if deferredRemoval(err) {
					deferred = append(deferred, snapshot.Path)
					continue
				}
				if removeErr == nil {
					removeErr = err
				}
			}
		}
		return nil
	})
	if privErr != nil && removeErr == nil {
		removeErr = privErr
	}
	sort.Strings(deferred)
	e.setPendingRules(deferred)
	if removeErr != nil {
		candidate.Close()
		if restoreErr := e.restoreRunning(old, &oldCfg); restoreErr != nil {
			return fmt.Errorf("%w (and restoring the previous settings failed too: %v)", removeErr, restoreErr)
		}
		return removeErr
	}

	cfg = cloneConfig(oldCfg)
	// Recomputed rather than carried over: an apply can add or remove a folder,
	// and a folder on a volume that cannot carry a marker changes the answer.
	choice := settings.ChooseMechanism(cfg.Mechanism, markerCapability(cfg.Folders))
	e.setMechanism(choice)
	err = e.startWithCapabilities(&cfg, candidate, choice, true)
	if errors.Is(err, errNoFolderAvailable) {
		// The change itself is fine; there is just nothing reachable left to
		// watch. Go idle with the desired state still on, so the folders are
		// picked up when their drives come back.
		return e.goIdle(&cfg, candidate)
	}
	if err != nil {
		candidate.Close()
		if restoreErr := e.restoreRunning(old, &oldCfg); restoreErr != nil {
			return fmt.Errorf("%w (and restoring the previous settings failed too: %v)", err, restoreErr)
		}
		return err
	}
	return nil
}

// goIdle takes monitoring down because nothing reachable is left to watch. It is
// not the same as recording a configuration change: the swap above withdrew the
// old rules but deliberately kept the machine-wide audit policy, on the
// expectation that new rules were about to replace them. None arrived, so the
// policy has to go back - otherwise ReadWatch would sit idle owning a
// machine-wide change with no folder carrying a rule to show for it.
// A failure to put the policy back is returned, not just logged. Recording the
// idle configuration afterwards usually succeeds, and returning that success
// would report a clean stop while a machine-wide change ReadWatch owns is still
// in force - the one thing the contract here does not allow.
func (e *ServiceEngine) goIdle(cfg *settings.Config, bound *BoundConfig) error {
	restoreErr := restoreFileSystemAuditPolicy(cfg, e.saveConfig)
	if restoreErr != nil {
		writeServiceDiagnostic(restoreErr)
	}
	// Release the handles and persist the journal regardless: a stuck policy is no
	// reason to hold folders open as well.
	recordErr := e.recordBound(cfg, bound)
	if restoreErr != nil {
		e.setLastError(restoreErr)
		return restoreErr
	}
	return recordErr
}

// recordBound stores a configuration whose objects are known but not being
// watched, releases the capabilities, and leaves monitoring off. It is the
// shared tail of "the owner changed settings while stopped" and "the change is
// valid but every folder's drive is out".
func (e *ServiceEngine) recordBound(cfg *settings.Config, bound *BoundConfig) error {
	cfg.ApplyPublic(bound.Public)
	cfg.FolderBindings, cfg.LogBinding = bound.MergeBindings(cfg.FolderBindings)
	err := e.saveConfig(cfg)
	bound.Close()
	e.mu.Lock()
	e.cfg = *cfg
	released := e.active
	e.active = nil
	if err == nil {
		e.lastError = ""
	}
	e.mu.Unlock()
	released.Close()
	return err
}

// restoreRunning puts the previous configuration back after a failed swap,
// using the handles it was applied with. If that fails too, monitoring stays off
// and the journal keeps whatever is unresolved: claiming the old configuration
// is running when it is not would be worse than saying so.
// It returns what went wrong so the caller can combine it with the failure that
// sent it here. Swallowing it would let a transition report only its first
// problem while a second one silently left the machine changed.
func (e *ServiceEngine) restoreRunning(old *BoundConfig, oldCfg *settings.Config) error {
	if old == nil {
		return nil
	}
	// The configuration being restored is the old one, so its mechanism is
	// decided from the old one too. Reusing the rejected candidate's answer could
	// put the previous folders under a mechanism they were never started with.
	choice := settings.ChooseMechanism(oldCfg.Mechanism, markerCapability(oldCfg.Folders))
	e.setMechanism(choice)
	err := e.startWithCapabilities(oldCfg, old, choice, false)
	if err == nil {
		// The status recorded for the rejected candidate would otherwise keep
		// describing folders this configuration does not have.
		e.setFolderStatus(old)
		return nil
	}
	if errors.Is(err, errNoFolderAvailable) {
		// There is nothing to put back: the folders the previous configuration
		// watched are not reachable any more either. Monitoring is off because of
		// where the drives are, which is a state, not a fault - unless going idle
		// could not undo the machine-wide change, which is.
		return e.goIdle(oldCfg, old)
	}
	writeServiceDiagnostic(fmt.Errorf("restore the previous configuration: %w", err))
	restoreErr := fmt.Errorf("monitoring is stopped: the change failed and the previous settings could not be restored (%v)", err)
	e.setLastError(restoreErr)
	return restoreErr
}

// recoverJournalOffline resolves outstanding records with no running engine,
// which is the uninstall path when the service cannot be reached. It reaches
// every object by identity for the same reason the online path does.
func recoverJournalOffline(cfg *settings.Config) ([]string, error) {
	save := func(c *settings.Config) error { return settings.Save(paths().Config, *c) }
	return recoverJournal(cfg, save)
}

// transientOpenFailure reports conditions that say "not now" rather than "not
// ever": another process holding the folder incompatibly, or a volume that is
// not mounted. The record is kept so the next Stop or start can finish the job.
// Anything else is treated as the object being gone, because a record ReadWatch
// can never act on strands the whole application - a deleted watched folder did
// exactly that.
func transientOpenFailure(err error) bool {
	// A drive that is not in the machine is the clearest "not now" there is, and
	// it does not announce itself with a device-shaped error code: measured on
	// this host, an unattached volume GUID fails with ERROR_FILE_NOT_FOUND, which
	// by number alone is indistinguishable from a folder that was deleted.
	// openByIdentity tells the two apart by which of its two opens failed and
	// says so with this value rather than with a number, which is what makes an
	// unplugged drive keep its record instead of being written off as gone.
	if errors.Is(err, errVolumeUnavailable) {
		return true
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	switch uintptr(errno) {
	case ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION, ERROR_NOT_READY, ERROR_DEV_NOT_EXIST:
		return true
	}
	return false
}

// deferredRemoval is the subset of transient failures that need no attention:
// the disk is elsewhere, so there is nothing wrong and nothing to do but plug it
// back in. It is not silence either - ReadWatch still owns an audit rule it has
// not removed - so callers report it as its own state rather than as an error or
// as success.
func deferredRemoval(err error) bool { return errors.Is(err, errVolumeUnavailable) }
