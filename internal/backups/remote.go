package backups

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// rclone pinned with the admin (Faz 4): official zip, SHA-256 in hp-backup.sh.
const (
	RcloneVersion = "v1.75.2"
	RcloneBin     = "/usr/local/bin/rclone"
)

// Remote types.
const (
	RemoteOAuth = "drive_oauth"
	RemoteSA    = "drive_sa"
)

// Settings keys.
const (
	setRemoteType = "backup_remote_type"
	setRootFolder = "backup_root_folder"
	setServerName = "backup_server_name"
	setBwlimit    = "backup_bwlimit"
	setCrypt      = "backup_crypt"
	setCryptKey   = "backup_crypt_sealed"
	setRcloneOK   = "backup_rclone_installed" // dry-run only
	setSharedID   = "backup_shared_drive"
)

// DefaultRootFolder is the Drive folder used unless changed.
const DefaultRootFolder = "HostPanel-Backups"

var (
	folderRe   = regexp.MustCompile(`^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+){0,4}$`)
	serverRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
	bwlimitRe  = regexp.MustCompile(`^[1-9][0-9]{0,5}[KMG]?$`)
	sharedRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{10,100}$`)
	clientIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,200}\.apps\.googleusercontent\.com$`)
	secretRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{10,100}$`)
)

// ValidFolder checks the Drive root folder path (no "..", no spaces).
func ValidFolder(s string) bool {
	if len(s) > 200 || !folderRe.MatchString(s) {
		return false
	}
	for _, p := range strings.Split(s, "/") {
		if p == "." || p == ".." {
			return false
		}
	}
	return true
}

// DefaultServerName is the hostname, made safe for a folder name.
func DefaultServerName() string {
	h, _ := os.Hostname()
	var b strings.Builder
	for _, r := range h {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_' {
			b.WriteRune(r)
		}
	}
	if s := b.String(); serverRe.MatchString(s) {
		return s
	}
	return "hostpanel"
}

// ExtractToken pulls the JSON token out of `rclone authorize "drive"` output
// (the admin may paste the whole "Paste the following…" block) and checks it.
func ExtractToken(raw string) (string, error) {
	i, j := strings.Index(raw, "{"), strings.LastIndex(raw, "}")
	if i < 0 || j < i {
		return "", errors.New("token bulunamadı: `rclone authorize \"drive\"` çıktısındaki {…} kısmını yapıştırın")
	}
	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
	}
	js := raw[i : j+1]
	if err := json.Unmarshal([]byte(js), &tok); err != nil {
		return "", fmt.Errorf("token geçerli JSON değil: %v", err)
	}
	if tok.RefreshToken == "" || tok.AccessToken == "" {
		return "", errors.New("token'da access_token/refresh_token yok")
	}
	return compactJSON(js)
}

// CheckServiceAccount validates a service account key file.
func CheckServiceAccount(raw string) (string, string, error) {
	var sa struct {
		Type        string `json:"type"`
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &sa); err != nil {
		return "", "", fmt.Errorf("service account JSON okunamadı: %v", err)
	}
	if sa.Type != "service_account" || sa.ClientEmail == "" || !strings.Contains(sa.PrivateKey, "PRIVATE KEY") {
		return "", "", errors.New("bu bir service account anahtar dosyası değil (type: service_account bekleniyor)")
	}
	js, err := compactJSON(raw)
	return js, sa.ClientEmail, err
}

func compactJSON(s string) (string, error) {
	var b bytes.Buffer
	if err := json.Compact(&b, []byte(strings.TrimSpace(s))); err != nil {
		return "", err
	}
	if b.Len() > 32*1024 {
		return "", errors.New("JSON çok büyük")
	}
	return b.String(), nil
}

// RemoteInput is the Drive connection form.
type RemoteInput struct {
	Type         string // drive_oauth | drive_sa
	Token        string // rclone authorize output (OAuth)
	ClientID     string // optional own OAuth client
	ClientSecret string
	SAJSON       string // service account key (SA)
	SharedDrive  string // Shared Drive ID (required for SA: service accounts have no storage quota)
	RootFolder   string
	ServerName   string
	Crypt        bool
}

// CryptSecret are the rclone crypt password + salt (password2).
type CryptSecret struct {
	Password string `json:"password"`
	Salt     string `json:"salt"`
}
