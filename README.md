# HostPanel

Ubuntu 24.04 için tek yöneticili, ultra hafif hosting kontrol paneli (Go, tek statik binary, boşta < 30 MB RAM).
.NET / Node.js / statik siteler, Let's Encrypt ve ücretli SSL, Docker üzerinde MSSQL, Google Drive yedekleme ve merkezi log görüntüleme.

> Durum: **Faz 0 (iskelet)** tamamlandı. Kurulum betiği Faz 6'da gelecek.

## Geliştirme
```bash
export PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH"
make run-dev        # http://127.0.0.1:8080 — admin şifresi ilk açılışta terminale basılır
make test lint
make build build-arm64
```
Ayrıntılar: [CLAUDE.md](CLAUDE.md). Gereksinimler: [PROMPT.md](PROMPT.md).
