// backend/internal/capture/dumpcap_manager_test.go
package capture

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDumpcapArgs(t *testing.T) {
	cfg := DumpcapManagerConfig{
		Iface: "en0", OutputDir: "/data/pcaps",
		FileSizeMB: 500, RingFiles: 20, BufferMB: 1024,
	}
	args := dumpcapArgs(cfg)
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"-i en0", "-P", "-B 1024",
		"-b filesize:512000", // 500 MB in KB — dumpcap's filesize unit is KB
		"-b files:20",
		"-w /data/pcaps/vibes_en0.pcap",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args missing %q in %q", want, joined)
		}
	}
}

func TestPreflightAdvice(t *testing.T) {
	if !strings.Contains(preflightAdvice("darwin"), "ChmodBPF") {
		t.Error("darwin advice must mention ChmodBPF")
	}
	linux := preflightAdvice("linux")
	if !strings.Contains(linux, "setcap") && !strings.Contains(linux, "sudo") {
		t.Error("linux advice must mention setcap or sudo")
	}
}

// fakeScript writes an executable shell script and returns its path.
func fakeScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-dumpcap")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestManagerPreflightFailure(t *testing.T) {
	bin := fakeScript(t, `echo "no permission" >&2; exit 2`)
	m := NewDumpcapManager(DumpcapManagerConfig{Binary: bin, Iface: "x", OutputDir: t.TempDir()})
	err := m.Preflight()
	if err == nil {
		t.Fatal("expected preflight error")
	}
	if !strings.Contains(err.Error(), "no permission") {
		t.Errorf("error should include child stderr, got: %v", err)
	}
}

func TestManagerRestartsOnDeath(t *testing.T) {
	// -D probe succeeds; the capture invocation dies immediately.
	bin := fakeScript(t, `if [ "$1" = "-D" ]; then echo "1. lo"; exit 0; fi; echo "boom" >&2; exit 1`)
	m := NewDumpcapManager(DumpcapManagerConfig{
		Binary: bin, Iface: "lo", OutputDir: t.TempDir(),
		RestartBackoffBase: 10 * time.Millisecond,
	})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if m.Status().Restarts >= 2 {
			return // supervised restart works
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected >=2 restarts, got %d", m.Status().Restarts)
}

func TestManagerStopKillsChild(t *testing.T) {
	bin := fakeScript(t, `if [ "$1" = "-D" ]; then exit 0; fi; sleep 60`)
	m := NewDumpcapManager(DumpcapManagerConfig{
		Binary: bin, Iface: "lo", OutputDir: t.TempDir(),
		RestartBackoffBase: 10 * time.Millisecond,
	})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	pid := m.Status().PID
	if pid <= 0 {
		t.Fatal("expected live child PID")
	}
	m.Stop()
	time.Sleep(200 * time.Millisecond)
	if m.Status().Running {
		t.Fatal("manager still running after Stop")
	}
	// Signal 0 probes existence without actually signaling; ESRCH means the
	// child (and, since it was the process group leader / direct child, its
	// process) is gone. This is deterministic, unlike os.Process.Signal with
	// a nil signal.
	err := syscall.Kill(pid, 0)
	if err != syscall.ESRCH {
		t.Fatalf("expected child pid %d to be gone (ESRCH), got err=%v", pid, err)
	}
}

// countLaunches counts newline-delimited entries appended to path by the
// fake script, treating a missing file as zero launches so far.
func countLaunches(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatal(err)
	}
	if len(data) == 0 {
		return 0
	}
	return len(strings.Split(strings.TrimRight(string(data), "\n"), "\n"))
}

// Finding 1: a restart racing with Stop() must never spawn a new child.
// Without the m.stopping check inside launchLocked (taken under the same
// mutex Stop() uses), a restart whose backoff timer fires concurrently with
// Stop() can slip past the stopCh check in supervise's select and launch an
// orphan that nothing will ever signal to stop.
func TestManagerStopDuringBackoffDoesNotSpawnOrphan(t *testing.T) {
	countFile := filepath.Join(t.TempDir(), "launches")
	bin := fakeScript(t, fmt.Sprintf(`if [ "$1" = "-D" ]; then exit 0; fi; echo x >> %q; exit 1`, countFile))
	m := NewDumpcapManager(DumpcapManagerConfig{
		Binary: bin, Iface: "lo", OutputDir: t.TempDir(),
		RestartBackoffBase: 100 * time.Millisecond,
	})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	// The first launch dies almost instantly and enters its 100ms backoff.
	// Call Stop() close to when that backoff would fire, to exercise the
	// race window described above as tightly as a test reasonably can.
	time.Sleep(90 * time.Millisecond)
	m.Stop()
	countAtStop := countLaunches(t, countFile)
	// If the fix were absent, a racing restart would fire within roughly
	// one more backoff period; wait well past that and confirm no growth.
	time.Sleep(500 * time.Millisecond)
	countAfter := countLaunches(t, countFile)
	if countAfter != countAtStop {
		t.Fatalf("child spawned after Stop() returned: %d launches at Stop, %d after waiting (orphan leaked)", countAtStop, countAfter)
	}
	if m.Status().Running {
		t.Fatal("manager reports Running after Stop()")
	}
}

// Finding 2: a second Stop() call must be a safe no-op, not a panic from a
// double close(m.stopCh).
func TestManagerDoubleStopDoesNotPanic(t *testing.T) {
	bin := fakeScript(t, `if [ "$1" = "-D" ]; then exit 0; fi; sleep 60`)
	m := NewDumpcapManager(DumpcapManagerConfig{
		Binary: bin, Iface: "lo", OutputDir: t.TempDir(),
		RestartBackoffBase: 10 * time.Millisecond,
	})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	m.Stop()
	m.Stop() // must not panic
	if m.Status().Running {
		t.Fatal("manager reports Running after Stop()")
	}
}

// Finding 3: if a supervised restart's cmd.Start() itself fails (as opposed
// to the child starting and later dying), Status() must not keep reporting
// Running=true against the previous, already-dead process — and LastError
// must explain why.
func TestManagerStatusReflectsFailedRestart(t *testing.T) {
	bin := fakeScript(t, `if [ "$1" = "-D" ]; then exit 0; fi; exit 1`)
	m := NewDumpcapManager(DumpcapManagerConfig{
		Binary: bin, Iface: "lo", OutputDir: t.TempDir(),
		RestartBackoffBase: 50 * time.Millisecond,
	})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	// Let the first child die and start its backoff, then make the binary
	// non-executable so the pending restart's cmd.Start() itself fails.
	time.Sleep(20 * time.Millisecond)
	if err := os.Chmod(bin, 0644); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s := m.Status()
		if !s.Running && strings.Contains(s.LastError, "failed to start") {
			return // Status correctly reflects the failed restart
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected Status to report a failed restart, got %+v", m.Status())
}

// Finding 4: stderr from a dying child must be captured in full, not
// truncated by a race between supervise reading it and the background copy
// goroutine still writing it.
func TestManagerCapturesFullStderrOnRestart(t *testing.T) {
	bin := fakeScript(t, `if [ "$1" = "-D" ]; then exit 0; fi; echo "boom with full detail attached" >&2; exit 1`)
	m := NewDumpcapManager(DumpcapManagerConfig{
		Binary: bin, Iface: "lo", OutputDir: t.TempDir(),
		RestartBackoffBase: 10 * time.Millisecond,
	})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(m.Status().LastError, "boom with full detail attached") {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected LastError to contain full stderr, got %q", m.Status().LastError)
}
