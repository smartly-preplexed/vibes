// backend/internal/capture/dumpcap_manager_test.go
package capture

import (
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
