//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"readwatch/internal/model"
	"readwatch/internal/protocol"
	"readwatch/internal/settings"
)

type ServiceEngine struct {
	opMu         sync.Mutex
	mu           sync.RWMutex
	cfg          settings.Config
	watcher      *EventWatcher
	ipc          *IPCServer
	lastError    string
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
	return settings.Load(path, defaultLog, raw.OwnerSID, raw.OwnerName)
}

// Start brings up IPC and nothing else. A persisted Enabled=true is desired
// state, not permission: resuming means opening the owner's folders and log,
// and the authority for that is a connected owner's token, which does not exist
// yet. The resume happens on the first viewer hello instead.
func (e *ServiceEngine) Start() error {
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
	e.mu.RLock()
	enabled := e.cfg.Enabled
	folders := len(e.cfg.Folders)
	e.mu.RUnlock()
	if !enabled || folders == 0 {
		return nil
	}
	if err := e.startMonitoringBound(pipe, false); err != nil {
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
	return e.startMonitoringBound(pipe, true)
}

func (e *ServiceEngine) Shutdown() {
	e.shuttingDown.Store(true)
	e.mu.Lock()
	e.ready = false
	e.mu.Unlock()
	e.ipc.Stop()
	e.opMu.Lock()
	e.watcher.Stop()
	// Stopping the service must leave nothing of ReadWatch's behind. The SACLs
	// and the audit-policy change are ours, and Windows keeps writing 4663 events
	// into the Security log for as long as they are applied - with no service
	// running to consume them. Enabled is deliberately left as-is so the next
	// start resumes monitoring; only the machine-visible state is withdrawn.
	e.mu.RLock()
	cfg := cloneConfig(e.cfg)
	e.mu.RUnlock()
	if err := cleanupAuditState(&cfg); err != nil {
		writeServiceDiagnostic(err)
	} else if err := settings.Save(paths().Config, cfg); err != nil {
		writeServiceDiagnostic(err)
	} else {
		e.mu.Lock()
		e.cfg.Snapshots = cfg.Snapshots
		e.mu.Unlock()
	}
	e.opMu.Unlock()
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
	e.mu.RUnlock()
	return protocol.State{
		Running:      e.watcher.Running(),
		Config:       cfg.Public(),
		LastError:    last,
		LogDropped:   e.watcher.Dropped(),
		LiveDropped:  e.ipc.Dropped(),
		Suppressed:   e.watcher.Suppressed(),
		ServiceReady: ready,
	}
}

func (e *ServiceEngine) ApplyFromClient(pipe HANDLE, public settings.PublicConfig) error {
	validated, err := validatePublicConfigAsPipeClient(pipe, public)
	if err != nil {
		return err
	}
	return e.apply(validated)
}

func (e *ServiceEngine) apply(public settings.PublicConfig) error {
	e.opMu.Lock()
	defer e.opMu.Unlock()
	if err := e.rejectIfStopping(); err != nil {
		return err
	}

	e.mu.RLock()
	old := cloneConfig(e.cfg)
	e.mu.RUnlock()
	wasRunning := e.watcher.Running()

	candidate := cloneConfig(old)
	candidate.ApplyPublic(public)
	candidate.Enabled = old.Enabled

	if !wasRunning {
		if err := cleanupAuditState(&candidate); err != nil {
			return err
		}
		if err := settings.Save(paths().Config, candidate); err != nil {
			return err
		}
		e.mu.Lock()
		e.cfg = candidate
		e.lastError = ""
		e.mu.Unlock()
		return nil
	}

	e.watcher.Stop()
	old.Enabled = true
	if errs := reconcileAuditRules(&old, nil); len(errs) > 0 {
		_ = e.restoreRunningConfig(old)
		return errs[0]
	}
	candidate.Snapshots = make(map[string]settings.AuditSnapshot)
	candidate.Enabled = true
	if err := ensureFileSystemAuditPolicy(&candidate); err != nil {
		_ = e.restoreRunningConfig(old)
		return err
	}
	if errs := reconcileAuditRules(&candidate, candidate.Folders); len(errs) > 0 {
		_ = reconcileAndDiscard(&candidate)
		_ = e.restoreRunningConfig(old)
		return errs[0]
	}
	if err := settings.Save(paths().Config, candidate); err != nil {
		_ = reconcileAndDiscard(&candidate)
		_ = e.restoreRunningConfig(old)
		return err
	}
	if err := e.watcher.Start(candidate); err != nil {
		_ = reconcileAndDiscard(&candidate)
		_ = e.restoreRunningConfig(old)
		return err
	}
	e.mu.Lock()
	e.cfg = candidate
	e.lastError = ""
	e.mu.Unlock()
	return nil
}

func reconcileAndDiscard(cfg *settings.Config) error {
	if errs := reconcileAuditRules(cfg, nil); len(errs) > 0 {
		return errs[0]
	}
	return nil
}

func cleanupAuditState(cfg *settings.Config) error {
	if err := reconcileAndDiscard(cfg); err != nil {
		return err
	}
	return restoreFileSystemAuditPolicy(cfg)
}

func (e *ServiceEngine) restoreRunningConfig(old settings.Config) error {
	old.Enabled = true
	old.Snapshots = make(map[string]settings.AuditSnapshot)
	if err := ensureFileSystemAuditPolicy(&old); err != nil {
		return err
	}
	if errs := reconcileAuditRules(&old, old.Folders); len(errs) > 0 {
		return errs[0]
	}
	if err := settings.Save(paths().Config, old); err != nil {
		return err
	}
	if err := e.watcher.Start(old); err != nil {
		return err
	}
	e.mu.Lock()
	e.cfg = old
	e.mu.Unlock()
	return nil
}

// startMonitoringBound takes the pipe handle so the objects it is about to make
// SYSTEM act on are the ones the connected owner can reach. Q2 replaces the
// pathname re-resolution inside it with retained handles; the seam is here.
func (e *ServiceEngine) startMonitoringBound(_ HANDLE, clearError bool) error {
	if e.watcher.Running() {
		return nil
	}
	e.mu.RLock()
	cfg := cloneConfig(e.cfg)
	e.mu.RUnlock()
	if len(cfg.Folders) == 0 {
		return errors.New("add at least one folder before starting")
	}
	if err := ensureFileSystemAuditPolicy(&cfg); err != nil {
		return err
	}
	if errs := reconcileAuditRules(&cfg, cfg.Folders); len(errs) > 0 {
		_ = cleanupAuditState(&cfg)
		return errs[0]
	}
	cfg.Enabled = true
	if err := settings.Save(paths().Config, cfg); err != nil {
		_ = cleanupAuditState(&cfg)
		return err
	}
	if err := e.watcher.Start(cfg); err != nil {
		cfg.Enabled = false
		_ = cleanupAuditState(&cfg)
		_ = settings.Save(paths().Config, cfg)
		return err
	}
	e.mu.Lock()
	e.cfg = cfg
	if clearError {
		e.lastError = ""
	}
	e.mu.Unlock()
	return nil
}

func (e *ServiceEngine) StopMonitoring(removeRules bool) error {
	e.opMu.Lock()
	defer e.opMu.Unlock()
	if err := e.rejectIfStopping(); err != nil {
		return err
	}
	e.watcher.Stop()
	e.mu.RLock()
	cfg := cloneConfig(e.cfg)
	e.mu.RUnlock()
	var first error
	if removeRules {
		if errs := reconcileAuditRules(&cfg, nil); len(errs) > 0 {
			first = errs[0]
		} else if err := restoreFileSystemAuditPolicy(&cfg); err != nil {
			first = err
		}
		cfg.Enabled = false
	}
	if err := settings.Save(paths().Config, cfg); err != nil && first == nil {
		first = err
	}
	e.mu.Lock()
	e.cfg = cfg
	if first == nil {
		e.lastError = ""
	} else {
		e.lastError = first.Error()
	}
	e.mu.Unlock()
	return first
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

func cloneConfig(in settings.Config) settings.Config {
	out := in
	out.Folders = append([]string(nil), in.Folders...)
	out.Snapshots = make(map[string]settings.AuditSnapshot, len(in.Snapshots))
	for k, v := range in.Snapshots {
		out.Snapshots[k] = v
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
	engine.Shutdown()
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
