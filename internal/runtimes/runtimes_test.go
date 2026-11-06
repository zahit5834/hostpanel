package runtimes

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hostpanel/internal/exec"
)

type fakeRunner struct{ out string }

func (f fakeRunner) Run(ctx context.Context, c exec.Cmd) (exec.Result, error) {
	return exec.Result{Stdout: f.out}, nil
}

func load(t *testing.T, out string) *Registry {
	t.Helper()
	r, err := Load("../../deploy/runtimes", fakeRunner{out: out}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Errors()) > 0 {
		t.Fatalf("load errors: %v", r.Errors())
	}
	return r
}

func TestDefaultDefinitionsLoad(t *testing.T) {
	r := load(t, "")
	var ids []string
	for _, p := range r.All() {
		ids = append(ids, p.Def().ID)
	}
	if strings.Join(ids, ",") != "dotnet,node,php,static" {
		t.Fatalf("ids %v", ids)
	}
}

func TestDotnetVersionsAndArgs(t *testing.T) {
	out := "Microsoft.AspNetCore.App 8.0.33 [/usr/share/dotnet/shared/Microsoft.AspNetCore.App]\n" +
		"Microsoft.AspNetCore.App 10.0.14 [/usr/share/dotnet/shared/Microsoft.AspNetCore.App]\n" +
		"Microsoft.NETCore.App 10.0.14 [/usr/share/dotnet/shared/Microsoft.NETCore.App]\n"
	p, _ := load(t, out).Get("dotnet")
	vs, err := p.InstalledVersions(context.Background())
	if err != nil || strings.Join(vs, ",") != "10.0.14,8.0.33" {
		t.Fatalf("%v %v", vs, err)
	}
	f, err := p.ValidateFields(map[string]string{"entryPoint": "MyApp.dll", "junk": "x"})
	if err != nil || len(f) != 1 {
		t.Fatalf("%v %v", f, err)
	}
	if _, err := p.ValidateFields(map[string]string{"entryPoint": "../x.dll"}); err == nil {
		t.Fatal("traversal accepted")
	}
	argv, err := p.StartArgs(Vars{Port: 5001, Fields: f})
	if err != nil || strings.Join(argv, " ") != "/usr/share/dotnet/dotnet MyApp.dll" {
		t.Fatalf("%v %v", argv, err)
	}
	if env := p.Env(Vars{Port: 5001}); env["ASPNETCORE_URLS"] != "http://127.0.0.1:5001" {
		t.Fatalf("%v", env)
	}
}

func TestNodeListDirAndArgs(t *testing.T) {
	dir := t.TempDir()
	for _, v := range []string{"v22.23.4", "v24.22.2", "junk"} {
		os.MkdirAll(filepath.Join(dir, v), 0o755)
	}
	b, _ := os.ReadFile("../../deploy/runtimes/node.yaml")
	d, err := Parse([]byte(strings.Replace(string(b), "list-dir: /opt/node", "list-dir: "+dir, 1)))
	if err != nil {
		t.Fatal(err)
	}
	p := &yamlProvider{def: d}
	vs, _ := p.InstalledVersions(context.Background())
	if strings.Join(vs, ",") != "24.22.2,22.23.4" {
		t.Fatalf("%v", vs)
	}
	argv, err := p.StartArgs(Vars{Version: "22.23.4", Fields: map[string]string{"entryPoint": "dist/main.js", "args": "--a=1 --b"}})
	if err != nil || strings.Join(argv, " ") != "/opt/node/v22.23.4/bin/node dist/main.js --a=1 --b" {
		t.Fatalf("%v %v", argv, err)
	}
	// No args → placeholder disappears cleanly.
	argv, _ = p.StartArgs(Vars{Version: "22.23.4", Fields: map[string]string{"entryPoint": "s.js"}})
	if len(argv) != 2 {
		t.Fatalf("%v", argv)
	}
	if _, err := p.StartArgs(Vars{Version: "22.23.4", Fields: map[string]string{"entryPoint": "s.js;rm"}}); err == nil {
		t.Fatal("bad token accepted")
	}
}

func TestParseRejects(t *testing.T) {
	bad := []string{
		"id: X\ntype: static",
		"id: a1\ntype: weird",
		"id: a1\ntype: proxy",
		"id: a1\ntype: static\nnginxTemplate: ../../etc/x",
		"id: a1\ntype: static\nversions:\n  install-script: ../x.sh",
		"id: a1\ntype: static\nenvironment:\n  'A B': x",
	}
	for _, b := range bad {
		if _, err := Parse([]byte(b)); err == nil {
			t.Errorf("accepted: %q", b)
		}
	}
}

func TestRemoteParsers(t *testing.T) {
	d, err := parseDotnetIndex(strings.NewReader(`{"releases-index":[
		{"channel-version":"10.0","latest-runtime":"10.0.14","support-phase":"active","release-type":"lts"},
		{"channel-version":"7.0","latest-runtime":"7.0.20","support-phase":"eol","release-type":"sts"}]}`))
	if err != nil || len(d) != 1 || d[0].Version != "10.0.14" {
		t.Fatalf("%v %v", d, err)
	}
	n, err := parseNodeIndex(strings.NewReader(`[{"version":"v27.0.0","lts":false},{"version":"v24.22.2","lts":"Krypton"},{"version":"v24.22.1","lts":"Krypton"},{"version":"v22.23.4","lts":"Jod"}]`))
	if err != nil || len(n) != 2 || n[0].Version != "24.22.2" {
		t.Fatalf("%v %v", n, err)
	}
}

func TestPHPDefinition(t *testing.T) {
	p, _ := load(t, "PHP 8.3.6 (fpm-fcgi) (built: Jul 14 2025 18:30:55)\nCopyright (c) The PHP Group\n").Get("php")
	if !p.Def().HasUnit() || p.Def().Type != TypeFastCGI {
		t.Fatal("php must be a fastcgi runtime with its own unit")
	}
	vs, _ := p.InstalledVersions(context.Background())
	if strings.Join(vs, ",") != "8.3" {
		t.Fatalf("versions %v", vs)
	}
	av, _ := p.AvailableVersions(context.Background())
	if len(av) != 1 || av[0].Version != "8.3" {
		t.Fatalf("available %v", av)
	}
	f, err := p.ValidateFields(map[string]string{"docroot": "public"})
	if err != nil || f["index"] != "index.php" || f["maxChildren"] != "5" || f["memoryLimit"] != "256" || f["frontController"] != "evet" {
		t.Fatalf("%v %v", f, err)
	}
	for _, bad := range []map[string]string{{"docroot": "../x"}, {"docroot": "/abs"}, {"maxChildren": "51"}, {"maxChildren": "0"}, {"memoryLimit": "5000"}, {"memoryLimit": "8"}} {
		if _, err := p.ValidateFields(bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	argv, err := p.StartArgs(Vars{Domain: "ornek.com", Version: "8.3", Fields: f})
	if err != nil || strings.Join(argv, " ") != "/usr/sbin/php-fpm8.3 --nodaemonize --fpm-config=/etc/hostpanel/php/ornek.com.conf" {
		t.Fatalf("%v %v", argv, err)
	}
	if !ValidInstallVersion("8.3") || !ValidInstallVersion("10.0.14") || ValidInstallVersion("8") || ValidInstallVersion("8.3;x") {
		t.Fatal("ValidInstallVersion")
	}
}

func TestDotnetSDKs(t *testing.T) {
	p, _ := load(t, "8.0.415 [/usr/share/dotnet/sdk]\n10.0.403 [/usr/share/dotnet/sdk]\n").Get("dotnet")
	sdks := p.InstalledSDKs(context.Background())
	if strings.Join(sdks, ",") != "10.0.403,8.0.415" {
		t.Fatalf("%v", sdks)
	}
	if !HasSDKFor(sdks, "10.0.14") || HasSDKFor(sdks, "9.0.1") {
		t.Fatal("HasSDKFor")
	}
	n, _ := load(t, "").Get("node")
	if n.InstalledSDKs(context.Background()) != nil {
		t.Fatal("node has no SDK definition")
	}
}
