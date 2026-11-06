// Package exec is the single entry point for running system commands.
//
// Commands are always executed as binary + separate argv; there is deliberately
// no way to pass a shell string, so user input can never be interpreted by a shell.
package exec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	osexec "os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/zahit5834/hostpanel/internal/logs"
)

// DefaultTimeout applies when Cmd.Timeout is zero.
const DefaultTimeout = 2 * time.Minute

// maxCapture bounds captured stdout/stderr per stream to keep memory flat.
const maxCapture = 256 * 1024

// Cmd describes one command invocation.
type Cmd struct {
	Name    string        // binary (absolute path or looked up in PATH)
	Args    []string      // passed verbatim, never through a shell
	Timeout time.Duration // 0 = DefaultTimeout
	Stdin   io.Reader
	Dir     string
	Env     []string  // nil = inherit
	Secrets []string  // literal values to mask in logs/output
	Output  io.Writer // optional live stream of stdout+stderr (masked), e.g. a job log
}

// Result is what a command produced.
type Result struct {
	ExitCode  int
	Stdout    string
	Stderr    string
	Duration  time.Duration
	Truncated bool
	DryRun    bool
}

// ExitError is returned when the command ran but exited non-zero.
type ExitError struct {
	Cmd    string
	Code   int
	Stderr string
}

func (e *ExitError) Error() string {
	msg := strings.TrimSpace(e.Stderr)
	if len(msg) > 500 {
		msg = "…" + msg[len(msg)-500:]
	}
	return fmt.Sprintf("%s: exit %d: %s", e.Cmd, e.Code, msg)
}

// Runner runs commands. Implementations: *Real and *DryRun.
type Runner interface {
	Run(ctx context.Context, c Cmd) (Result, error)
}

var helperName = regexp.MustCompile(`^hp-[a-z0-9-]+\.sh$`)

// Helper builds a "sudo -n <scriptsDir>/<name> args..." command for a root helper script.
// -n makes sudo fail instead of prompting if the sudoers rule is missing.
func Helper(scriptsDir, name string, args ...string) Cmd {
	if !helperName.MatchString(name) {
		// Programming error, not user input: helper names are constants in code.
		panic("exec.Helper: invalid helper name " + name)
	}
	return Cmd{Name: "sudo", Args: append([]string{"-n", filepath.Join(scriptsDir, name)}, args...)}
}

// Display renders the command for logs with secrets masked.
func (c Cmd) Display() string {
	parts := append([]string{c.Name}, logs.MaskArgs(c.Args, c.Secrets)...)
	return strings.Join(parts, " ")
}

// Real executes commands.
type Real struct {
	Log *slog.Logger
}

// Run executes c and waits for it.
func (r *Real) Run(ctx context.Context, c Cmd) (Result, error) {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := osexec.CommandContext(ctx, c.Name, c.Args...)
	cmd.Stdin = c.Stdin
	cmd.Dir = c.Dir
	cmd.Env = c.Env
	cmd.WaitDelay = 5 * time.Second // don't hang forever on children holding pipes

	stdout := &capBuffer{max: maxCapture}
	stderr := &capBuffer{max: maxCapture}
	var outW, errW io.Writer = stdout, stderr
	if c.Output != nil {
		live := &maskWriter{w: c.Output, secrets: c.Secrets}
		outW = io.MultiWriter(stdout, live)
		errW = io.MultiWriter(stderr, live)
	}
	cmd.Stdout, cmd.Stderr = outW, errW

	start := time.Now()
	err := cmd.Run()
	res := Result{
		Stdout:    logs.MaskString(stdout.String(), c.Secrets),
		Stderr:    logs.MaskString(stderr.String(), c.Secrets),
		Duration:  time.Since(start),
		Truncated: stdout.truncated || stderr.truncated,
	}
	var exitErr *osexec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		res.ExitCode = exitErr.ExitCode()
		err = &ExitError{Cmd: c.Display(), Code: res.ExitCode, Stderr: res.Stderr}
	case ctx.Err() != nil:
		res.ExitCode = -1
		err = fmt.Errorf("%s: %w", c.Display(), ctx.Err())
	default:
		res.ExitCode = -1
		err = fmt.Errorf("%s: %w", c.Display(), err)
	}
	if r.Log != nil {
		lvl := slog.LevelInfo
		if err != nil {
			lvl = slog.LevelWarn
		}
		r.Log.Log(ctx, lvl, "exec", "cmd", c.Display(), "exit", res.ExitCode,
			"duration_ms", res.Duration.Milliseconds())
	}
	return res, err
}

// DryRun logs commands to the Log Center instead of running them.
type DryRun struct {
	Log      *slog.Logger
	Activity *logs.Activity
}

// Run records "[DRY-RUN] cmd" and reports success.
func (d *DryRun) Run(ctx context.Context, c Cmd) (Result, error) {
	line := "[DRY-RUN] " + c.Display()
	if c.Output != nil {
		io.WriteString(c.Output, line+"\n")
	}
	if d.Log != nil {
		d.Log.Info("exec", "cmd", c.Display(), "dry_run", true)
	}
	if d.Activity != nil {
		d.Activity.Record(ctx, logs.Entry{Action: "exec.dryrun", Summary: line}, nil)
	}
	return Result{DryRun: true}, nil
}

// capBuffer keeps at most max bytes and notes truncation.
type capBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (b *capBuffer) Write(p []byte) (int, error) {
	room := b.max - b.buf.Len()
	if room <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if len(p) > room {
		b.buf.Write(p[:room])
		b.truncated = true
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *capBuffer) String() string { return b.buf.String() }

// maskWriter masks secrets on the live stream. Stdout and stderr share it, so it locks.
type maskWriter struct {
	mu      sync.Mutex
	w       io.Writer
	secrets []string
}

func (m *maskWriter) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := io.WriteString(m.w, logs.MaskString(string(p), m.secrets)); err != nil {
		return 0, err
	}
	return len(p), nil
}
