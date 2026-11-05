GO       ?= go
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X main.version=$(VERSION)
BUILD    := CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)"
BIN      := bin

.PHONY: build build-amd64 build-arm64 test test-scripts lint fmt run-dev measure check-sudoers clean

build: build-amd64

build-amd64:
	GOOS=linux GOARCH=amd64 $(BUILD) -o $(BIN)/hostpanel-linux-amd64 ./cmd/hostpanel
	@ls -lh $(BIN)/hostpanel-linux-amd64 | awk '{print "binary size:", $$5}'

build-arm64:
	GOOS=linux GOARCH=arm64 $(BUILD) -o $(BIN)/hostpanel-linux-arm64 ./cmd/hostpanel
	@ls -lh $(BIN)/hostpanel-linux-arm64 | awk '{print "binary size:", $$5}'

test: test-scripts
	$(GO) test ./...

test-scripts:
	bash deploy/scripts/test_lib.sh
	bash -n deploy/scripts/*.sh

lint: check-sudoers
	$(GO) vet ./...
	staticcheck ./...
	@command -v shellcheck >/dev/null && shellcheck -x deploy/scripts/*.sh || echo "shellcheck yok, atlandı"

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
	rm -rf $(BIN)

SHELL := /bin/bash
