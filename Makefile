GO       ?= go
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X main.version=$(VERSION)
BUILD    := CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)"
BIN      := bin

.PHONY: manifest build build-amd64 build-arm64 dist test test-scripts lint fmt run-dev measure check-sudoers clean

build: build-amd64

# SHA-256 of the installed scripts/templates/sudoers/unit, compiled into the
# binary (script integrity check); TestManifestFresh fails when it is stale.
manifest:
	$(GO) run ./tools/genmanifest

build-amd64: manifest
	GOOS=linux GOARCH=amd64 $(BUILD) -o $(BIN)/hostpanel-linux-amd64 ./cmd/hostpanel
	@ls -lh $(BIN)/hostpanel-linux-amd64 | awk '{print "binary size:", $$5}'

build-arm64: manifest
	GOOS=linux GOARCH=arm64 $(BUILD) -o $(BIN)/hostpanel-linux-arm64 ./cmd/hostpanel
	@ls -lh $(BIN)/hostpanel-linux-arm64 | awk '{print "binary size:", $$5}'

# Release artifacts (what .github/workflows/release.yml publishes):
#   make dist VERSION=v0.1.0 → dist/hostpanel-v0.1.0-linux-{amd64,arm64}.tar.gz, install.sh, SHA256SUMS
dist: manifest
	@[[ "$(VERSION)" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$$ ]] || { echo "VERSION=vX.Y.Z gerekli (şu an: $(VERSION))"; exit 1; }
	rm -rf dist && mkdir -p dist
	for a in amd64 arm64; do \
	  GOOS=linux GOARCH=$$a $(BUILD) -o dist/.bin-$$a ./cmd/hostpanel && \
	  deploy/package.sh $(VERSION) $$a dist/.bin-$$a dist || exit 1; \
	done
	rm -f dist/.bin-*
	cp install.sh dist/
	cd dist && sha256sum hostpanel-*.tar.gz install.sh > SHA256SUMS && cat SHA256SUMS

test: test-scripts
	$(GO) test ./...

test-scripts:
	bash deploy/scripts/test_lib.sh
	bash deploy/scripts/test_install.sh
	for f in deploy/scripts/*.sh deploy/scripts/runtimes/*.sh deploy/package.sh install.sh update.sh uninstall.sh; do bash -n $$f || exit 1; done

lint: check-sudoers
	$(GO) vet ./...
	staticcheck ./...
	@if command -v shellcheck >/dev/null; then shellcheck -x -S error deploy/scripts/*.sh deploy/scripts/runtimes/*.sh deploy/package.sh install.sh update.sh uninstall.sh; else echo "shellcheck yok, atlandı"; fi

fmt:
	gofmt -w cmd internal

# Development: ./data for state, dry-run commands, templates read from disk.
run-dev:
	mkdir -p data
	$(GO) run ./cmd/hostpanel serve --dev

# Measure idle RSS of a running panel (pass PID=... or it finds the dev process).
measure:
	@pid=$${PID:-$$(pgrep -n -f 'hostpanel.* serve')}; \
	if [ -z "$$pid" ]; then echo "çalışan hostpanel yok"; exit 1; fi; \
	grep -E 'VmRSS|VmHWM|Threads' /proc/$$pid/status; \
	ps -o pid,%cpu,rss,etime,cmd -p $$pid

# Every hp-*.sh must be whitelisted in sudoers and vice versa.
check-sudoers:
	@diff <(ls deploy/scripts | grep -E '^hp-.*\.sh$$' | sort) \
	      <(grep -oE '/opt/hostpanel/scripts/hp-[a-z0-9-]+\.sh' deploy/sudoers/hostpanel | xargs -n1 basename | sort) \
	  && echo "sudoers ↔ scripts: eşleşiyor"

clean:
	rm -rf $(BIN) dist

SHELL := /bin/bash
