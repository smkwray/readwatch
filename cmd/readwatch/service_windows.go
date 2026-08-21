//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"readwatch/internal/etw"
	"readwatch/internal/model"
	"readwatch/internal/protocol"
	"readwatch/internal/settings"
)

type ServiceEngine struct {
	opMu    sync.Mutex
	mu      sync.RWMutex
	cfg     settings.Config
	watcher *EventWatcher
	ipc     *IPCServer
	// active holds the open folder and log handles the current monitoring
	// session was authorised with. Everything privileged goes through these.
	active    *BoundConfig
	lastError string
	// folders is what the last binding attempt found at each configured path, and
	// pendingRules names audit rules ReadWatch still owns on a disk that is not in
	// the machine. Both are reported rather than folded into lastError: neither is
	// a fault, and a warning nothing can clear is worse than a plain statement.
	folders      []protocol.FolderStatus
	pendingRules []string
	// mechanism is what the last start decided and why. Reported to the viewer so
	// the owner is told which mechanism is running, and told when the one they
	// asked for could not be used, rather than left to infer it.
	mechanism    settings.MechanismChoice
	ready        bool
	shuttingDown atomic.Bool
}

func NewServiceEngine() (*ServiceEngine, error) {
	p := paths()
	cfg, err := loadServiceConfig(p.Config, p.DefaultLog)
	if err != nil {
		return nil, err
	}
	if cfg.OwnerSID == "" {
		return nil, errors.New("ReadWatch configuration has no owner SID; reinstall ReadWatch")
	}
	e := &ServiceEngine{cfg: cfg}
	e.watcher = NewEventWatcher(e.onEvent, e.onWatcherError)
	e.ipc = NewIPCServer(cfg.OwnerSID, e)
	return e, nil
}

func (e *ServiceEngine) setMechanism(c settings.MechanismChoice) {
	e.mu.Lock()
	e.mechanism = c
	e.mu.Unlock()
}

func loadServiceConfig(path, defaultLog string) (settings.Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return settings.Config{}, err
	}
	var raw struct {
		OwnerSID  string `json:"owner_sid"`
		OwnerName string `json:"owner_name"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return settings.Config{}, err
	}
	cfg, err := settings.Load(path, defaultLog, raw.OwnerSID, raw.OwnerName)
	if err != nil {
		return cfg, err
	}
	// A version-1 configuration that still owns audit state cannot be carried
	// forward: its records name paths, and a path no longer identifies an
	// object well enough to undo a privileged change safely.
	if err := cfg.MigrateFromV1(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// Start brings up IPC and nothing else. A persisted Enabled=true is desired
// state, not permission: resuming means opening the owner's folders and log,
// and the authority for that is a connected owner's token, which does not exist
// yet. The resume happens on the first viewer hello instead.
func (e *ServiceEngine) Start() error {
	// An ETW session outlives the process that created it, so a service that was
	// killed rather than stopped leaves one running with nobody consuming it.
	// Clear both here as well as at monitoring start: the service can sit idle
	// for a long time before anything else would notice. A failure to confirm
	// them gone is recorded and surfaced rather than passed over - an orphaned
	// machine-wide logger is the state this service most may not be in silently.
	if err := etw.StopStale(); err != nil {
		writeServiceDiagnostic(err)
		e.setLastError(err)
	}
	e.ipc.Start()
	e.mu.Lock()
	e.ready = true
	e.mu.Unlock()
	e.ipc.BroadcastState()
	return nil
}

// OnViewerHello resumes monitoring for a configuration that was left enabled,
// bound to the token of the viewer that just connected.
func (e *ServiceEngine) OnViewerHello(pipe HANDLE) error {
	e.opMu.Lock()
	defer e.opMu.Unlock()
	if err := e.rejectIfStopping(); err != nil {
		return err
	}
	if e.watcher.Running() {
		return nil
	}
	// Resolve anything a previous session left behind before deciding whether to
	// resume. Exiting clears the desired state, so without this an audit rule
	// left on a drive that was out at the time would never be revisited: the only
	// other route to the journal is a Start the owner might never press again.
	// Nothing here needs the client's token - it undoes ReadWatch's own recorded
	// changes, found by identity - and monitoring is off, so no rule in force can
	// be withdrawn by mistake.
	e.mu.RLock()
	cfg := cloneConfig(e.cfg)
	enabled := cfg.Enabled
	folders := len(cfg.Folders)
	e.mu.RUnlock()
	var recoverErr error
	if len(cfg.Snapshots) > 0 || cfg.AuditPolicy != nil {
		var deferred []string
		deferred, recoverErr = recoverJournal(&cfg, e.saveConfig)
		e.setPendingRules(deferred)
		if recoverErr != nil {
			writeServiceDiagnostic(recoverErr)
		}
		e.mu.Lock()
		e.cfg = cfg
		e.mu.Unlock()
	}
	// A change ReadWatch owns and could not undo is reported even though the
	// viewer only said hello. Publishing a clean state here would hide it behind
	// whatever happens next.
	if recoverErr != nil {
		e.setLastError(recoverErr)
		return recoverErr
	}
	if !enabled || folders == 0 {
		return nil
	}
	if err := e.startMonitoringBound(pipe, false); err != nil {
		// Every folder being on a drive that is out is the resting state for a
		// configuration like that, not a failure to report. The folder statuses
		// already say which ones are waiting, and a device arrival resumes it.
		if errors.Is(err, errNoFolderAvailable) {
			return nil
		}
		e.setLastError(err)
		return err
	}
	return nil
}

func (e *ServiceEngine) StartMonitoringFromClient(pipe HANDLE) error {
	e.opMu.Lock()
	defer e.opMu.Unlock()
	if err := e.rejectIfStopping(); err != nil {
		return err
	}
	// An explicit Start deserves an answer, so the "nothing is reachable" case is
	// returned to the caller that asked - but it is not stored as lastError,
	// which would leave a warning on the status line that nothing clears.
	return e.startMonitoringBound(pipe, true)
}

// RefreshFromClient re-binds the configuration the service already holds. A
// drive appearing or leaving changes what can be watched without changing what
// the owner asked for, and only a connected owner's token may open a folder, so
// the viewer notices the device and this turns it into a re-bind.
func (e *ServiceEngine) RefreshFromClient(pipe HANDLE) error {
	e.mu.RLock()
	public := cloneConfig(e.cfg).Public()
	e.mu.RUnlock()
	return e.applyBound(pipe, public, false)
}

// Shutdown stops everything and says whether the cleanup actually succeeded.
//
// It used to swallow the error, and the service then reported exit code 0
// regardless - so a stop that failed to withdraw an audit rule, restore the
// audit policy or tear down a trace session was indistinguishable from a clean
// one, in the Service Control Manager and in the event log. That is precisely
// the state the first non-negotiable is about, and it was the state hardest to
// find out about.
func (e *ServiceEngine) Shutdown() error {
	e.shuttingDown.Store(true)
	e.mu.Lock()
	e.ready = false
	e.mu.Unlock()
	e.ipc.Stop()
	e.opMu.Lock()
	// Stopping the service must leave nothing of ReadWatch's behind. The SACLs
	// and the audit-policy change are ours, and Windows keeps writing 4663 events
	// into the Security log for as long as they are applied - with no service
	// running to consume them.
	//
	// Exiting also means monitoring is off, not paused: the desired state is
	// cleared, so opening ReadWatch again starts idle and waits to be told. The
	// owner's words - "exit should stop the monitoring as well". Nothing here
	// affects a service that died while the viewer stayed open; that path still
	// resumes on reconnect, because the owner never said to stop.
	err := e.stopMonitoringLocked(true, true)
	if err != nil {
		writeServiceDiagnostic(err)
	}
	e.opMu.Unlock()
	return err
}

func (e *ServiceEngine) rejectIfStopping() error {
	if e.shuttingDown.Load() {
		return errors.New("ReadWatch service is stopping")
	}
	return nil
}

func (e *ServiceEngine) CurrentState() protocol.State {
	e.mu.RLock()
	cfg := cloneConfig(e.cfg)
	last := e.lastError
	ready := e.ready
	folders := append([]protocol.FolderStatus(nil), e.folders...)
	pending := append([]string(nil), e.pendingRules...)
	mechanism := e.mechanism
	e.mu.RUnlock()
	return protocol.State{
		Running:     e.watcher.Running(),
		Config:      cfg.Public(),
		LastError:   last,
		LogDropped:  e.watcher.Dropped(),
		LiveDropped: e.ipc.Dropped(),
		Suppressed:  e.watcher.Suppressed(),

		Mechanism:           string(mechanism.Use),
		MechanismReason:     mechanism.Reason,
		MechanismOverridden: mechanism.Overridden,

		DirListingUnavailable: e.watcher.DirectoryListingUnavailable(),
		ServiceReady:          ready,
		Folders:               folders,
		PendingRules:          pending,
	}
}

// ApplyFromClient records a configuration the viewer sent. Only a Save from the
// Settings dialog arrives with authorise set: that is the one place the owner
// looks at the folder list and decides what each path means.
func (e *ServiceEngine) ApplyFromClient(pipe HANDLE, public settings.PublicConfig, authorise bool) error {
	return e.applyBound(pipe, public, authorise)
}

// setFolderStatus records what the last bind found, in the order the owner
// configured the folders. Every configured path appears exactly once, so the
// counts the window shows always add up to the list in Settings.
func (e *ServiceEngine) setFolderStatus(bound *BoundConfig) {
	byPath := make(map[string]protocol.FolderStatus, len(bound.Public.Folders))
	for _, f := range bound.Folders {
		byPath[strings.ToLower(f.Path)] = protocol.FolderStatus{Path: f.Path, State: protocol.FolderAvailable}
	}
	for _, u := range bound.Unavailable {
		state := protocol.FolderRefused
		if u.Waiting {
			state = protocol.FolderWaiting
		}
		byPath[strings.ToLower(u.Path)] = protocol.FolderStatus{Path: u.Path, State: state, Detail: u.Reason}
	}
	out := make([]protocol.FolderStatus, 0, len(bound.Public.Folders))
	for _, path := range bound.Public.Folders {
		if status, ok := byPath[strings.ToLower(path)]; ok {
			out = append(out, status)
		}
	}
	e.mu.Lock()
	e.folders = out
	e.mu.Unlock()
}

func (e *ServiceEngine) setPendingRules(paths []string) {
	e.mu.Lock()
	e.pendingRules = paths
	e.mu.Unlock()
}

func (e *ServiceEngine) StopMonitoring(removeRules bool) error {
	e.opMu.Lock()
	defer e.opMu.Unlock()
	if err := e.rejectIfStopping(); err != nil {
		return err
	}
	// An explicit Stop clears the desired state; a shutdown keeps it, so the
	// next viewer session resumes what the owner had running.
	return e.stopMonitoringLocked(removeRules, true)
}

func (e *ServiceEngine) Cleanup() error {
	return e.StopMonitoring(true)
}

func (e *ServiceEngine) onEvent(event model.Event) {
	if e.ipc != nil {
		e.ipc.BroadcastEvent(event)
	}
}

func (e *ServiceEngine) onWatcherError(err error) {
	e.setLastError(err)
	if e.ipc != nil {
		e.ipc.BroadcastState()
	}
}

func (e *ServiceEngine) setLastError(err error) {
	e.mu.Lock()
	if err == nil {
		e.lastError = ""
	} else {
		e.lastError = err.Error()
	}
	e.mu.Unlock()
}

// cloneConfig deep-copies everything a caller may go on to mutate. Sharing any
// of it is a data race against CurrentState, and ApplyPublic writes through
// Folders and ExcludedProcesses in place - the exclusion list was being shared,
// which is the same defect that was already fixed for the folder list.
func cloneConfig(in settings.Config) settings.Config {
	out := in
	out.Folders = append([]string(nil), in.Folders...)
	out.ExcludedProcesses = append([]string(nil), in.ExcludedProcesses...)
	out.Snapshots = make(map[string]settings.AuditSnapshot, len(in.Snapshots))
	for k, v := range in.Snapshots {
		out.Snapshots[k] = v
	}
	out.FolderBindings = make(map[string]settings.ObjectBinding, len(in.FolderBindings))
	for k, v := range in.FolderBindings {
		out.FolderBindings[k] = v
	}
	return out
}

var (
	serviceMainCallback    = syscall.NewCallback(serviceMain)
	serviceHandlerCallback = syscall.NewCallback(serviceControlHandler)
	serviceStatusHandle    SERVICE_STATUS_HANDLE
	serviceStopOnce        sync.Once
	serviceStopCh          chan struct{}
)

func runServiceDispatcher() error {
	name := utf16Ptr(serviceName)
	table := []SERVICE_TABLE_ENTRYW{
		{ServiceName: name, ServiceProc: serviceMainCallback},
		{},
	}
	r, _, e := procStartServiceCtrlDispatcherW.Call(uintptr(unsafe.Pointer(&table[0])))
	if r == 0 {
		return winErr("StartServiceCtrlDispatcher", e)
	}
	return nil
}

func serviceMain(_ uint32, _ uintptr) uintptr {
	serviceStopOnce = sync.Once{}
	serviceStopCh = make(chan struct{})
	h, _, _ := procRegisterServiceCtrlHandlerExW.Call(
		uintptr(unsafe.Pointer(utf16Ptr(serviceName))),
		serviceHandlerCallback,
		0,
	)
	if h == 0 {
		writeServiceDiagnostic(lastErr("RegisterServiceCtrlHandlerEx"))
		return 0
	}
	serviceStatusHandle = SERVICE_STATUS_HANDLE(h)
	setServiceStatus(SERVICE_START_PENDING, 0, 0, 10_000)

	engine, err := NewServiceEngine()
	if err != nil {
		writeServiceDiagnostic(err)
		setServiceStatus(SERVICE_STOPPED, uint32(ERROR_ACCESS_DENIED), 0, 0)
		return 0
	}
	if err := engine.Start(); err != nil {
		writeServiceDiagnostic(err)
		setServiceStatus(SERVICE_STOPPED, 1, 0, 0)
		return 0
	}
	setServiceStatus(SERVICE_RUNNING, 0, SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN|SERVICE_ACCEPT_PRESHUTDOWN, 0)
	<-serviceStopCh
	setServiceStatus(SERVICE_STOP_PENDING, 0, 0, 10_000)
	if err := engine.Shutdown(); err != nil {
		// Stopped, but not cleanly. Windows has a field for exactly this, and
		// using it is the difference between a stop the owner can trust and one
		// that merely looks like it worked. The detail is already in the
		// diagnostic log; this is what makes anyone go and read it.
		setServiceStoppedWithError(serviceExitCleanupFailed)
		return 0
	}
	setServiceStatus(SERVICE_STOPPED, 0, 0, 0)
	return 0
}

func serviceControlHandler(control uint32, _ uint32, _ uintptr, _ uintptr) uintptr {
	switch control {
	case SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_PRESHUTDOWN:
		requestServiceStop()
	}
	return 0
}

// requestServiceStop is the one way the service ends, whether the SCM asked or
// the viewer lease expired. It hands control back to serviceMain rather than
// tearing down from whichever goroutine noticed, so the status transition and
// the serialized shutdown stay in one place.
func requestServiceStop() {
	serviceStopOnce.Do(func() {
		if serviceStopCh != nil {
			close(serviceStopCh)
		}
	})
}

// serviceExitCleanupFailed is reported when the service stopped but could not
// withdraw everything it owned. Any non-zero value would do; a fixed one makes
// it searchable.
const serviceExitCleanupFailed = 1

// setServiceStoppedWithError reports a stop that did not clean up. Windows
// carries a service's own code in ServiceSpecificExitCode, and only reads it
// when Win32ExitCode is ERROR_SERVICE_SPECIFIC_ERROR - so both have to be set,
// or the failure is reported as success.
func setServiceStoppedWithError(code uint32) {
	if serviceStatusHandle == 0 {
		return
	}
	status := SERVICE_STATUS{
		ServiceType:             SERVICE_WIN32_OWN_PROCESS,
		CurrentState:            SERVICE_STOPPED,
		Win32ExitCode:           ERROR_SERVICE_SPECIFIC_ERROR,
		ServiceSpecificExitCode: code,
	}
	procSetServiceStatus.Call(uintptr(serviceStatusHandle), uintptr(unsafe.Pointer(&status)))
}

func setServiceStatus(state, win32Exit, accepted, waitHint uint32) {
	if serviceStatusHandle == 0 {
		return
	}
	status := SERVICE_STATUS{
		ServiceType:      SERVICE_WIN32_OWN_PROCESS,
		CurrentState:     state,
		ControlsAccepted: accepted,
		Win32ExitCode:    win32Exit,
		WaitHint:         waitHint,
	}
	procSetServiceStatus.Call(uintptr(serviceStatusHandle), uintptr(unsafe.Pointer(&status)))
}

func writeServiceDiagnostic(err error) {
	if err == nil {
		return
	}
	p := paths()
	_ = os.MkdirAll(p.DataDir, 0o755)
	line := fmt.Sprintf("%s | %s\r\n", time.Now().Format(time.RFC3339), err)
	f, openErr := os.OpenFile(filepath.Join(p.DataDir, "service-error.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if openErr == nil {
		_, _ = f.WriteString(line)
		_ = f.Close()
	}
}
