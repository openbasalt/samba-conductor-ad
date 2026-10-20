# Quality gates for the ad library.
# GOWORK=off by default: the module is checked on its own, against the
# versions go.mod pins (what CI and release builds use), not through a
# family go.work; `make check GOWORK=$PWD/../go.work` checks it against
# local copies of the sibling modules instead.
export GOWORK ?= off
# Gate tools, pinned (the same versions as CI) and built into
# .tools/<go version>/, so a stale or mismatched binary on $GOPATH/bin
# never runs the gates. staticcheck v0.8.1 pins golang.org/x/tools v0.44,
# which cannot read the export data version 5 written by Go 1.27.2, so it
# is built against XTOOLS_VERSION until a staticcheck release carries it.
STATICCHECK_VERSION := v0.8.1
XTOOLS_VERSION := v0.51.0
GOVULNCHECK_VERSION := v1.8.0
TOOLS_DIR := $(CURDIR)/.tools/$(shell go env GOVERSION)
STATICCHECK := $(TOOLS_DIR)/staticcheck-$(STATICCHECK_VERSION)-xtools-$(XTOOLS_VERSION)
GOVULNCHECK := $(TOOLS_DIR)/govulncheck-$(GOVULNCHECK_VERSION)
FUZZTIME ?= 20s

.PHONY: test lab-test check fmt vet staticcheck vulncheck fuzz tools

test:
	go test -race ./...

# Integration tests against the lab (https://github.com/openbasalt/samba-conductor-docs/blob/main/testing.md).
# LAB_HOST=local when running on the lab host itself; RUN=<regexp> to filter.
lab-test:
	./scripts/lab-test.sh

check: fmt vet staticcheck vulncheck test

fmt:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	go vet ./...
	go vet -tags lab ./...

staticcheck: tools
	$(STATICCHECK) ./...
	$(STATICCHECK) -tags lab ./...

vulncheck: tools
	$(GOVULNCHECK) ./...

fuzz:
	go test ./escape -run '^$$' -fuzz FuzzFilterValue -fuzztime $(FUZZTIME)
	go test ./escape -run '^$$' -fuzz FuzzDNValue -fuzztime $(FUZZTIME)
	go test ./sid -run '^$$' -fuzz FuzzSID -fuzztime $(FUZZTIME)
	go test ./sd -run '^$$' -fuzz FuzzParse -fuzztime $(FUZZTIME)
	go test ./sambatool -run '^$$' -fuzz FuzzValidateValue -fuzztime $(FUZZTIME)
	go test ./helper -run '^$$' -fuzz FuzzDecode -fuzztime $(FUZZTIME)
	go test . -run '^$$' -fuzz FuzzDecodeDNSRecord -fuzztime $(FUZZTIME)

# Installs the linters in the user's GOPATH (no root).
tools: $(STATICCHECK) $(GOVULNCHECK)

$(STATICCHECK):
	@mkdir -p $(TOOLS_DIR)
	tmp="$$(mktemp -d)" && trap 'rm -rf "$$tmp"' EXIT && cd "$$tmp" && \
		go mod init gatetools >/dev/null 2>&1 && \
		go get honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) golang.org/x/tools@$(XTOOLS_VERSION) && \
		go build -o $@ honnef.co/go/tools/cmd/staticcheck

$(GOVULNCHECK):
	@mkdir -p $(TOOLS_DIR)
	tmp="$$(mktemp -d)" && trap 'rm -rf "$$tmp"' EXIT && \
		GOBIN="$$tmp" go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) && \
		mv "$$tmp/govulncheck" $@
