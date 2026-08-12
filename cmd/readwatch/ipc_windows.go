//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"readwatch/internal/model"
	"readwatch/internal/protocol"
	"readwatch/internal/settings"
)

type serviceCommandHandler interface {
	CurrentState() protocol.State
	Apply(settings.PublicConfig) error
	StartMonitoring() error
	StopMonitoring(removeRules bool) error
	Cleanup() error
}

type IPCServer struct {
	name     string
	ownerSID string
	handler  serviceCommandHandler
	mu       sync.Mutex
	clients  map[*serverPipeClient]struct{}
	pending  HANDLE
	stop     chan struct{}
	done     chan struct{}
	stopped  atomic.Bool
	dropped  atomic.Uint64
}

type serverPipeClient struct {
	server *IPCServer
	handle HANDLE
	file   *os.File
	out    chan protocol.Message
	done   chan struct{}
	once   sync.Once
}

func NewIPCServer(ownerSID string, handler serviceCommandHandler) *IPCServer {
	return &IPCServer{
		name:     pipeName(ownerSID),
		ownerSID: ownerSID,
		handler:  handler,
		clients:  make(map[*serverPipeClient]struct{}),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

func (s *IPCServer) Start() { go s.acceptLoop() }

func (s *IPCServer) Stop() {
	if !s.stopped.CompareAndSwap(false, true) {
		return
	}
	close(s.stop)
	s.mu.Lock()
	pending := s.pending
	clients := make([]*serverPipeClient, 0, len(s.clients))
	for c := range s.clients {
		clients = append(clients, c)
	}
	s.mu.Unlock()
	if pending != 0 {
		closeHandle(pending)
	}
	for _, c := range clients {
		c.close()
	}
	<-s.done
}

func (s *IPCServer) BroadcastEvent(event model.Event) {
	msg := protocol.Message{Version: protocol.Version, Type: protocol.TypeEvent, Event: &event}
	s.mu.Lock()
	clients := make([]*serverPipeClient, 0, len(s.clients))
	for c := range s.clients {
		clients = append(clients, c)
	}
	s.mu.Unlock()
	for _, c := range clients {
		select {
		case c.out <- msg:
		default:
			// Live UI delivery is best effort. The disk log and Security log remain authoritative.
			s.dropped.Add(1)
		}
	}
}

func (s *IPCServer) Dropped() uint64 { return s.dropped.Load() }

func (s *IPCServer) BroadcastState() {
	state := s.handler.CurrentState()
	msg := protocol.Message{Version: protocol.Version, Type: protocol.TypeState, State: &state}
	s.mu.Lock()
	clients := make([]*serverPipeClient, 0, len(s.clients))
	for c := range s.clients {
		clients = append(clients, c)
	}
	s.mu.Unlock()
	for _, c := range clients {
		select {
		case c.out <- msg:
		default:
		}
	}
}

func (s *IPCServer) acceptLoop() {
	defer close(s.done)
	for {
		select {
		case <-s.stop:
			return
		default:
		}
		h, err := s.createPipe()
		if err != nil {
			select {
			case <-s.stop:
				return
			case <-time.After(500 * time.Millisecond):
				continue
			}
		}
		s.mu.Lock()
		s.pending = h
		s.mu.Unlock()
		r, _, callErr := procConnectNamedPipe.Call(uintptr(h), 0)
		if r == 0 {
			last := syscall.Errno(0)
			if errno, ok := callErr.(syscall.Errno); ok {
				last = errno
			}
			if last != ERROR_PIPE_CONNECTED {
				s.mu.Lock()
				if s.pending == h {
					s.pending = 0
				}
				s.mu.Unlock()
				closeHandle(h)
				select {
				case <-s.stop:
					return
				default:
					continue
				}
			}
		}
		s.mu.Lock()
		if s.pending == h {
			s.pending = 0
		}
		s.mu.Unlock()
		select {
		case <-s.stop:
			closeHandle(h)
			return
		default:
		}
		c := &serverPipeClient{server: s, handle: h, file: os.NewFile(uintptr(h), s.name), out: make(chan protocol.Message, 256), done: make(chan struct{})}
		s.mu.Lock()
		s.clients[c] = struct{}{}
		s.mu.Unlock()
		go c.writer()
		go c.reader()
	}
}

func (s *IPCServer) createPipe() (HANDLE, error) {
	sddl := `D:P(A;;GA;;;SY)(A;;GRGW;;;` + s.ownerSID + `)`
	sa, sd, err := securityAttributesFromSDDL(sddl)
	if err != nil {
		return 0, err
	}
	defer procLocalFree.Call(sd)
	r, _, e := procCreateNamedPipeW.Call(
		uintptr(unsafe.Pointer(utf16Ptr(s.name))),
		PIPE_ACCESS_DUPLEX,
		PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,
		PIPE_UNLIMITED_INSTANCES,
		64*1024, 64*1024, 0,
		uintptr(unsafe.Pointer(&sa)),
	)
	if r == INVALID_HANDLE_VALUE || r == 0 {
		return 0, winErr("CreateNamedPipe", e)
	}
	return HANDLE(r), nil
}

func (c *serverPipeClient) close() {
	c.once.Do(func() {
		close(c.done)
		_ = c.file.Close()
		c.server.mu.Lock()
		delete(c.server.clients, c)
		c.server.mu.Unlock()
	})
}

func (c *serverPipeClient) writer() {
	enc := json.NewEncoder(c.file)
	for {
		select {
		case msg := <-c.out:
			if err := enc.Encode(msg); err != nil {
				c.close()
				return
			}
		case <-c.done:
			return
		}
	}
}

func (c *serverPipeClient) reader() {
	defer c.close()
	dec := json.NewDecoder(c.file)
	for {
		var msg protocol.Message
		if err := dec.Decode(&msg); err != nil {
			return
		}
		c.handleMessage(msg)
	}
}

func (c *serverPipeClient) handleMessage(msg protocol.Message) {
	if msg.Type == protocol.TypeHello || (msg.Type == protocol.TypeCommand && msg.Command == protocol.CmdGetState) {
		state := c.server.handler.CurrentState()
		c.send(protocol.Message{Version: protocol.Version, Type: protocol.TypeState, ID: msg.ID, State: &state, OK: true})
		return
	}
	if msg.Type != protocol.TypeCommand {
		return
	}
	var err error
	switch msg.Command {
	case protocol.CmdApply:
		if msg.Config == nil {
			err = errors.New("configuration is missing")
		} else {
			validated, validateErr := validatePublicConfigAsPipeClient(c.handle, *msg.Config)
			if validateErr != nil {
				err = validateErr
			} else {
				err = c.server.handler.Apply(validated)
			}
		}
	case protocol.CmdStart:
		err = c.server.handler.StartMonitoring()
	case protocol.CmdStop:
		err = c.server.handler.StopMonitoring(true)
	case protocol.CmdCleanup:
		err = c.server.handler.Cleanup()
	default:
		err = fmt.Errorf("unknown command %q", msg.Command)
	}
	state := c.server.handler.CurrentState()
	resp := protocol.Message{Version: protocol.Version, Type: protocol.TypeResponse, ID: msg.ID, OK: err == nil, State: &state}
	if err != nil {
		resp.Error = err.Error()
	}
	c.send(resp)
	c.server.BroadcastState()
}

func (c *serverPipeClient) send(msg protocol.Message) {
	select {
	case c.out <- msg:
	case <-c.done:
	}
}

func validatePublicConfigAsPipeClient(pipe HANDLE, cfg settings.PublicConfig) (settings.PublicConfig, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	r, _, e := procImpersonateNamedPipeClient.Call(uintptr(pipe))
	if r == 0 {
		return cfg, winErr("ImpersonateNamedPipeClient", e)
	}
	defer procRevertToSelf.Call()

	if len(cfg.Folders) > 32 {
		return cfg, errors.New("a maximum of 32 watched folders is supported")
	}
	validatedFolders := make([]string, 0, len(cfg.Folders))
	for _, raw := range cfg.Folders {
		folder, err := validateWatchFolder(raw)
		if err != nil {
			return cfg, fmt.Errorf("%s: %w", raw, err)
		}
		h, err := openFolderForValidation(folder)
		if err != nil {
			return cfg, fmt.Errorf("%s: your account cannot open this folder: %w", folder, err)
		}
		closeHandle(h)
		validatedFolders = append(validatedFolders, folder)
	}

	logPath, err := validateLogPathForClient(cfg.LogPath)
	if err != nil {
		return cfg, err
	}
	cfg.Folders = validatedFolders
	cfg.LogPath = logPath
	if cfg.LogFormat != "text" && cfg.LogFormat != "jsonl" && cfg.LogFormat != "csv" {
		return cfg, errors.New("unsupported log format")
	}
	if cfg.MaxRows < 200 || cfg.MaxRows > 5000 {
		cfg.MaxRows = 1000
	}
	return cfg, nil
}

func openFolderForValidation(path string) (HANDLE, error) {
	r, _, e := procCreateFileW.Call(
		uintptr(unsafe.Pointer(utf16Ptr(path))),
		FILE_LIST_DIRECTORY,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		0, OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if r == INVALID_HANDLE_VALUE || r == 0 {
		return 0, winErr("CreateFile(folder)", e)
	}
	return HANDLE(r), nil
}

func validateLogPathForClient(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("choose a log file")
	}
	if strings.HasPrefix(raw, `\\`) || strings.HasPrefix(raw, `//`) {
		return "", errors.New("the log file must be on a local drive")
	}
	abs, err := filepath.Abs(raw)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	if info, statErr := os.Stat(abs); statErr == nil && info.IsDir() {
		return "", errors.New("the log path points to a folder")
	}
	parent := filepath.Dir(abs)
	if info, statErr := os.Stat(parent); statErr != nil || !info.IsDir() {
		return "", errors.New("the log folder does not exist or is not accessible")
	}
	r, _, e := procCreateFileW.Call(
		uintptr(unsafe.Pointer(utf16Ptr(abs))),
		FILE_APPEND_DATA,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		0, OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if r == INVALID_HANDLE_VALUE || r == 0 {
		return "", fmt.Errorf("your account cannot append to the selected log: %w", e)
	}
	closeHandle(HANDLE(r))
	return abs, nil
}

// IPCClient is used only by the non-elevated UI.
type IPCClient struct {
	name      string
	file      *os.File
	writeMu   sync.Mutex
	pendingMu sync.Mutex
	pending   map[uint64]chan protocol.Message
	nextID    atomic.Uint64
	done      chan struct{}
	closeOnce sync.Once
	onState   func(protocol.State)
	onEvent   func(model.Event)
	onClose   func(error)
}

func ConnectIPC(ownerSID string, timeout time.Duration, onState func(protocol.State), onEvent func(model.Event), onClose func(error)) (*IPCClient, error) {
	name := pipeName(ownerSID)
	deadline := time.Now().Add(timeout)
	for {
		r, _, e := procWaitNamedPipeW.Call(uintptr(unsafe.Pointer(utf16Ptr(name))), 250)
		if r != 0 {
			break
		}
		if time.Now().After(deadline) {
			return nil, winErr("WaitNamedPipe", e)
		}
		time.Sleep(50 * time.Millisecond)
	}
	r, _, e := procCreateFileW.Call(
		uintptr(unsafe.Pointer(utf16Ptr(name))),
		GENERIC_READ|GENERIC_WRITE,
		0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0,
	)
	if r == INVALID_HANDLE_VALUE || r == 0 {
		return nil, winErr("CreateFile(named pipe)", e)
	}
	c := &IPCClient{
		name: name, file: os.NewFile(r, name), pending: make(map[uint64]chan protocol.Message), done: make(chan struct{}),
		onState: onState, onEvent: onEvent, onClose: onClose,
	}
	go c.reader()
	if err := c.send(protocol.Message{Version: protocol.Version, Type: protocol.TypeHello}); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (c *IPCClient) Close() {
	c.closeWithError(nil)
}

func (c *IPCClient) closeWithError(err error) {
	c.closeOnce.Do(func() {
		close(c.done)
		_ = c.file.Close()
		c.pendingMu.Lock()
		for id, ch := range c.pending {
			delete(c.pending, id)
			close(ch)
		}
		c.pendingMu.Unlock()
		if c.onClose != nil {
			c.onClose(err)
		}
	})
}

func (c *IPCClient) send(msg protocol.Message) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return json.NewEncoder(c.file).Encode(msg)
}

func (c *IPCClient) Command(ctx context.Context, command string, cfg *settings.PublicConfig) error {
	id := c.nextID.Add(1)
	ch := make(chan protocol.Message, 1)
	c.pendingMu.Lock()
	c.pending[id] = ch
	c.pendingMu.Unlock()
	msg := protocol.Message{Version: protocol.Version, Type: protocol.TypeCommand, ID: id, Command: command, Config: cfg}
	if err := c.send(msg); err != nil {
		c.pendingMu.Lock()
		delete(c.pending, id)
		c.pendingMu.Unlock()
		return err
	}
	select {
	case resp, ok := <-ch:
		if !ok {
			return errors.New("ReadWatch service disconnected")
		}
		if !resp.OK {
			if resp.Error == "" {
				return errors.New("ReadWatch service rejected the command")
			}
			return errors.New(resp.Error)
		}
		return nil
	case <-ctx.Done():
		c.pendingMu.Lock()
		delete(c.pending, id)
		c.pendingMu.Unlock()
		return ctx.Err()
	case <-c.done:
		return errors.New("ReadWatch service disconnected")
	}
}

func (c *IPCClient) reader() {
	dec := json.NewDecoder(c.file)
	for {
		var msg protocol.Message
		if err := dec.Decode(&msg); err != nil {
			c.closeWithError(err)
			return
		}
		switch msg.Type {
		case protocol.TypeResponse:
			if msg.State != nil && c.onState != nil {
				c.onState(*msg.State)
			}
			c.pendingMu.Lock()
			ch := c.pending[msg.ID]
			delete(c.pending, msg.ID)
			c.pendingMu.Unlock()
			if ch != nil {
				ch <- msg
				close(ch)
			}
		case protocol.TypeState:
			if msg.State != nil && c.onState != nil {
				c.onState(*msg.State)
			}
		case protocol.TypeEvent:
			if msg.Event != nil && c.onEvent != nil {
				c.onEvent(*msg.Event)
			}
		}
	}
}
