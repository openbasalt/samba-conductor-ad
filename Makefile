# Quality gates for the ad library. GOWORK=off: the module is checked on its
# own, not through the family go.work.
export GOWORK := off
GOBIN := $(shell go env GOPATH)/bin
STATICCHECK := $(GOBIN)/staticcheck
GOVULNCHECK := $(GOBIN)/govulncheck
FUZZTIME ?= 20s

.PHONY: test lab-test check fmt vet staticcheck vulncheck fuzz tools

test:
	go test -race ./...

# Integration tests against the server-home lab (planning/docs/lab.md).
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
	go test ./sambatool -run '^$$' -fuzz FuzzValidateValue -fuzztime $(FUZZTIME)
	go test ./helper -run '^$$' -fuzz FuzzDecode -fuzztime $(FUZZTIME)
	go test . -run '^$$' -fuzz FuzzDecodeDNSRecord -fuzztime $(FUZZTIME)

# Installs the linters in the user's GOPATH (no root).
tools:
	@test -x $(STATICCHECK) || go install honnef.co/go/tools/cmd/staticcheck@latest
	@test -x $(GOVULNCHECK) || go install golang.org/x/vuln/cmd/govulncheck@latest
