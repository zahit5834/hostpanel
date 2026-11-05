package runtimes

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Available is an installable version from the official source.
type Available struct {
	Version string
	Label   string // e.g. "LTS", "STS · bakım"
}

var semverRe = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// IsSemver reports whether v looks like X.Y.Z.
func IsSemver(v string) bool { return semverRe.MatchString(v) }

// remoteCache fetches version metadata on demand and caches it for an hour.
// Nothing is fetched until a page asks, so idle cost is zero.
type remoteCache struct {
	mu      sync.Mutex
	entries map[string]remoteEntry
	client  *http.Client
	urls    map[string]string
}

type remoteEntry struct {
	at   time.Time
	list []Available
}

func newRemoteCache() *remoteCache {
	return &remoteCache{
		entries: map[string]remoteEntry{},
		client:  &http.Client{Timeout: 10 * time.Second},
		urls: map[string]string{
			"dotnet-releases": "https://builds.dotnet.microsoft.com/dotnet/release-metadata/releases-index.json",
			"node-dist":       "https://nodejs.org/dist/index.json",
		},
	}
}

func (c *remoteCache) get(ctx context.Context, source string) ([]Available, error) {
	c.mu.Lock()
	if e, ok := c.entries[source]; ok && time.Since(e.at) < time.Hour {
		c.mu.Unlock()
		return e.list, nil
	}
	c.mu.Unlock()
	url, ok := c.urls[source]
	if !ok {
		return nil, fmt.Errorf("bilinmeyen sürüm kaynağı %q", source)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "hostpanel")
	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("%s: HTTP %d", url, res.StatusCode)
	}
	// Node's index.json is a few hundred KB; cap the read.
	body := io.LimitReader(res.Body, 4<<20)
	var list []Available
	switch source {
	case "dotnet-releases":
		list, err = parseDotnetIndex(body)
	case "node-dist":
		list, err = parseNodeIndex(body)
	}
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.entries[source] = remoteEntry{at: time.Now(), list: list}
	c.mu.Unlock()
	return list, nil
}

// parseDotnetIndex keeps supported channels (active + maintenance), latest ASP.NET runtime each.
func parseDotnetIndex(r io.Reader) ([]Available, error) {
	var idx struct {
		Releases []struct {
			Channel string `json:"channel-version"`
			Latest  string `json:"latest-runtime"`
			Phase   string `json:"support-phase"`
			Type    string `json:"release-type"`
		} `json:"releases-index"`
	}
	if err := json.NewDecoder(r).Decode(&idx); err != nil {
		return nil, err
	}
	var out []Available
	for _, rel := range idx.Releases {
		if (rel.Phase != "active" && rel.Phase != "maintenance") || !IsSemver(rel.Latest) {
			continue
		}
		label := strings.ToUpper(rel.Type)
		if rel.Phase == "maintenance" {
			label += " · bakım"
		}
		out = append(out, Available{Version: rel.Latest, Label: label})
	}
	return out, nil
}

// parseNodeIndex keeps the newest release of each LTS major line.
func parseNodeIndex(r io.Reader) ([]Available, error) {
	var rels []struct {
		Version string `json:"version"`
		LTS     any    `json:"lts"` // false or codename
	}
	if err := json.NewDecoder(r).Decode(&rels); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []Available
	for _, rel := range rels { // index.json is newest-first
		name, ok := rel.LTS.(string)
		v := strings.TrimPrefix(rel.Version, "v")
		if !ok || !IsSemver(v) {
			continue
		}
		major := strings.SplitN(v, ".", 2)[0]
		if seen[major] {
			continue
		}
		seen[major] = true
		out = append(out, Available{Version: v, Label: "LTS · " + name})
	}
	if len(out) > 4 { // only currently relevant LTS lines
		out = out[:4]
	}
	return out, nil
}

// SortVersions sorts X.Y.Z strings newest first; non-semver strings go last.
func SortVersions(vs []string) {
	key := func(s string) [3]int {
		var k [3]int
		for i, p := range strings.SplitN(strings.TrimPrefix(s, "v"), ".", 3) {
			k[i], _ = strconv.Atoi(p)
		}
		return k
	}
	sort.SliceStable(vs, func(i, j int) bool {
		a, b := key(vs[i]), key(vs[j])
		for n := 0; n < 3; n++ {
			if a[n] != b[n] {
				return a[n] > b[n]
			}
		}
		return vs[i] > vs[j]
	})
}
