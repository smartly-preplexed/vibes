// backend/internal/capture/dumpcap_manager.go
package capture

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

type DumpcapManagerConfig struct {
	Binary             string // default "dumpcap"
	Iface              string
	OutputDir          string
	FileSizeMB         int // per ring file, default 500
	RingFiles          int // ring length, default 20
	BufferMB           int // dumpcap -B, default 1024 (BH-2025-proven)
	RestartBackoffBase time.Duration
}

// syncStderr is a concurrency-safe io.Writer used to capture a child's
// stderr. It is needed because supervise reaps the process via
// cmd.Process.Wait() (see the comment on DumpcapManager) rather than
// cmd.Wait(), which means the os/exec-internal goroutine that copies the
// stderr pipe into this buffer keeps running independently of — and
// concurrently with — supervise reading the buffer's contents.
type syncStderr struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncStderr) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncStderr) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

type DumpcapManagerStatus struct {
	Running   bool
	PID       int
	Restarts  int
	LastError string
}

// DumpcapManager launches and supervises a dumpcap child process, restarting
// it with backoff if it dies unexpectedly, and shutting it down cleanly on
// Stop. The process is reaped exactly once, by the supervise goroutine —
// Stop synchronizes with it via waitDone rather than waiting on the process
// itself, since only one goroutine may wait on a given *os.Process.
//
// supervise reaps via cmd.Process.Wait() rather than cmd.Wait(). The two
// differ in an important way: cmd.Wait() additionally blocks until the
// pipes feeding cmd.Stdout/cmd.Stderr have seen EOF, which does not happen
// until every process holding the write end exits — including grandchildren
// that inherited the fd (e.g. a child shell backgrounding or exec-ing into
// another process). A dumpcap child that outlives its immediate parent via
// such a descendant would otherwise wedge Stop() until that descendant
// exits. cmd.Process.Wait() reaps strictly by PID and has no such
// dependency. Since we bypass cmd.Wait(), stderr capture uses syncStderr —
// os/exec's internal stderr-copying goroutine still runs (started at
// cmd.Start(), independent of Wait()) and keeps writing to it after the
// process is reaped, so reads of it must be synchronized.
type DumpcapManager struct {
	cfg      DumpcapManagerConfig
	mu       sync.Mutex
	cmd      *exec.Cmd
	waitDone chan struct{} // closed by supervise after cmd.Process.Wait() returns, for this launch
	stopping bool
	restarts int
	lastErr  string
	stopCh   chan struct{}
}

func NewDumpcapManager(cfg DumpcapManagerConfig) *DumpcapManager {
	if cfg.Binary == "" {
		cfg.Binary = "dumpcap"
	}
	if cfg.FileSizeMB <= 0 {
		cfg.FileSizeMB = 500
	}
	if cfg.RingFiles <= 0 {
		cfg.RingFiles = 20
	}
	if cfg.BufferMB <= 0 {
		cfg.BufferMB = 1024
	}
	if cfg.RestartBackoffBase <= 0 {
		cfg.RestartBackoffBase = time.Second
	}
	return &DumpcapManager{cfg: cfg, stopCh: make(chan struct{})}
}

func dumpcapArgs(cfg DumpcapManagerConfig) []string {
	out := filepath.Join(cfg.OutputDir, fmt.Sprintf("vibes_%s.pcap", cfg.Iface))
	return []string{
		"-i", cfg.Iface,
		"-P",
		"-B", fmt.Sprintf("%d", cfg.BufferMB),
		"-b", fmt.Sprintf("filesize:%d", cfg.FileSizeMB*1024), // dumpcap unit: KB
		"-b", fmt.Sprintf("files:%d", cfg.RingFiles),
		"-w", out,
	}
}

func preflightAdvice(goos string) string {
	switch goos {
	case "darwin":
		return "On macOS install ChmodBPF (bundled with Wireshark: 'Install ChmodBPF' package) or run the backend with sudo."
	default:
		return "On Linux grant capture rights: sudo setcap cap_net_raw,cap_net_admin=eip $(which dumpcap) — or run the backend with sudo."
	}
}

// Preflight verifies dumpcap exists and can enumerate interfaces (the same
// permission needed to capture). Failure is actionable, never silent.
func (m *DumpcapManager) Preflight() error {
	cmd := exec.Command(m.cfg.Binary, "-D")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		return fmt.Errorf("dumpcap preflight failed: %s. %s", detail, preflightAdvice(runtime.GOOS))
	}
	return nil
}

func (m *DumpcapManager) Start() error {
	if err := m.Preflight(); err != nil {
		return err
	}
	if err := os.MkdirAll(m.cfg.OutputDir, 0755); err != nil {
		return fmt.Errorf("cannot create dumpcap output dir: %w", err)
	}
	if err := m.launchLocked(); err != nil {
		return err
	}
	m.mu.Lock()
	pid := m.cmd.Process.Pid
	m.mu.Unlock()
	log.Printf("✅ dumpcap launched (pid %d): %s %s", pid, m.cfg.Binary, strings.Join(dumpcapArgs(m.cfg), " "))
	return nil
}

func (m *DumpcapManager) launchLocked() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cmd := exec.Command(m.cfg.Binary, dumpcapArgs(m.cfg)...)
	stderr := &syncStderr{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start dumpcap: %w", err)
	}
	m.cmd = cmd
	waitDone := make(chan struct{})
	m.waitDone = waitDone
	go m.supervise(cmd, stderr, waitDone)
	return nil
}

// supervise is the single waiter for cmd: it owns cmd.Process.Wait() for the
// entire lifetime of this launch's process and closes waitDone once Wait
// returns, which is how Stop learns the process has exited without itself
// waiting on it (that would race with this goroutine's call). See the
// DumpcapManager doc comment for why this is cmd.Process.Wait() and not
// cmd.Wait().
func (m *DumpcapManager) supervise(cmd *exec.Cmd, stderr *syncStderr, waitDone chan struct{}) {
	// Note: unlike cmd.Wait(), the error returned by cmd.Process.Wait() does
	// NOT reflect a non-zero exit code or termination by signal — it is only
	// non-nil on a wait4(2) syscall failure. Exit status must be read from
	// the returned *os.ProcessState instead (this is exactly what
	// cmd.Wait()/exec.ExitError does internally).
	ps, waitErr := cmd.Process.Wait()
	close(waitDone)
	m.mu.Lock()
	stopping := m.stopping
	switch {
	case waitErr != nil:
		m.lastErr = fmt.Sprintf("dumpcap wait failed: %v", waitErr)
	case ps == nil || !ps.Success():
		m.lastErr = fmt.Sprintf("dumpcap exited: %v — stderr: %s", ps, strings.TrimSpace(stderr.String()))
	default:
		m.lastErr = "dumpcap exited cleanly"
	}
	restarts := m.restarts
	m.mu.Unlock()
	if stopping {
		return
	}
	backoff := m.cfg.RestartBackoffBase * (1 << uint(minInt(restarts, 5)))
	if backoff > 30*time.Second {
		backoff = 30 * time.Second
	}
	log.Printf("❌ %s — restarting in %s", m.lastErr, backoff)
	select {
	case <-m.stopCh:
		return
	case <-time.After(backoff):
	}
	m.mu.Lock()
	m.restarts++
	m.mu.Unlock()
	if err := m.launchLocked(); err != nil {
		log.Printf("❌ dumpcap restart failed: %v", err)
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (m *DumpcapManager) Stop() {
	m.mu.Lock()
	m.stopping = true
	cmd := m.cmd
	waitDone := m.waitDone
	m.mu.Unlock()
	close(m.stopCh)
	if cmd == nil || cmd.Process == nil {
		return
	}
	cmd.Process.Signal(syscall.SIGTERM)
	if waitDone != nil {
		select {
		case <-waitDone:
		case <-time.After(3 * time.Second):
			cmd.Process.Kill()
			<-waitDone // supervise's cmd.Process.Wait() always returns after Kill
		}
	}
	log.Printf("🛑 dumpcap stopped")
}

func (m *DumpcapManager) Status() DumpcapManagerStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := DumpcapManagerStatus{Restarts: m.restarts, LastError: m.lastErr}
	if m.cmd != nil && m.cmd.Process != nil && !m.stopping {
		s.Running = true
		s.PID = m.cmd.Process.Pid
	}
	return s
}
