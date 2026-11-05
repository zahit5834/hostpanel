package exec

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRealRunSuccessAndExitCode(t *testing.T) {
	r := &Real{}
	res, err := r.Run(context.Background(), Cmd{Name: "echo", Args: []string{"hello", "; rm -rf /"}})
	if err != nil {
		t.Fatal(err)
	}
	// The shell metacharacters must arrive as a literal argument.
	if strings.TrimSpace(res.Stdout) != "hello ; rm -rf /" {
		t.Fatalf("stdout=%q", res.Stdout)
	}
	_, err = r.Run(context.Background(), Cmd{Name: "false"})
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != 1 {
		t.Fatalf("err=%v", err)
	}
}

func TestRealRunTimeoutAndMasking(t *testing.T) {
	r := &Real{}
	start := time.Now()
	_, err := r.Run(context.Background(), Cmd{Name: "sleep", Args: []string{"5"}, Timeout: 100 * time.Millisecond})
	if err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("timeout not enforced: %v", err)
	}
	var live bytes.Buffer
	res, err := r.Run(context.Background(), Cmd{Name: "echo", Args: []string{"pw=Sup3rSecret"}, Secrets: []string{"Sup3rSecret"}, Output: &live})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Stdout, "Sup3rSecret") || strings.Contains(live.String(), "Sup3rSecret") {
		t.Fatalf("secret leaked: %q / %q", res.Stdout, live.String())
	}
}

func TestDryRun(t *testing.T) {
	var out bytes.Buffer
	d := &DryRun{}
	c := Helper("/opt/hostpanel/scripts", "hp-selftest.sh", "--password", "x1234")
	c.Output = &out
	res, err := d.Run(context.Background(), c)
	if err != nil || !res.DryRun {
		t.Fatal(err)
	}
	want := "[DRY-RUN] sudo -n /opt/hostpanel/scripts/hp-selftest.sh --password ***\n"
	if out.String() != want {
		t.Fatalf("got %q", out.String())
	}
}

func TestHelperRejectsBadName(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	Helper("/x", "../bin/bash")
}
