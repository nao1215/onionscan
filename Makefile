.PHONY: build test test-short test-integration e2e coverage clean help lint

APP         = onionscan
VERSION     = $(shell git describe --tags --abbrev=0)
GIT_REVISION := $(shell git rev-parse HEAD)
GO          = go
GO_BUILD    = $(GO) build
GO_TEST     = $(GO) test -v
GO_TOOL     = $(GO) tool
GOOS        = ""
GOARCH      = ""
GO_PKGROOT  = ./...
GO_PACKAGES = $(shell $(GO_LIST) $(GO_PKGROOT))
GO_LDFLAGS  =

TOR_USE_EXTERNAL ?= 0
TOR_CONTROL      ?= 127.0.0.1:9051
TOR_SOCKS        ?= 127.0.0.1:9050
TOR_COOKIE       ?= $(HOME)/.tor/control.authcookie
TOR_PASSWORD     ?=q

build:  ## Build binary
	env GO111MODULE=on GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO_BUILD) $(GO_LDFLAGS) -o $(APP) ./cmd/$(APP)

clean: ## Clean project
	-rm -rf $(APP) coverage* .coverage

test: ## Run unit tests
	env GOOS=$(GOOS) $(GO_TEST) -short -cover -coverpkg=$(GO_PKGROOT) -coverprofile=coverage.out $(GO_PKGROOT)
	-$(GO_TOOL) cover -html=coverage.out -o coverage.html

test-short: test ## Alias for test

test-integration: ## Run the opt-in legacy real-Tor Go integration tests
	env ONIONSCAN_RUN_TOR_INTEGRATION=1 $(GO_TEST) -timeout 45m ./cmd/onionscan

e2e: ## Run atago E2E against a tornago-hosted onion service
	./e2e/run.sh

coverage: ## Combine unit and atago E2E coverage
	./scripts/coverage.sh

lint: ## Run golangci-lint
	golangci-lint run

.DEFAULT_GOAL := help
help: ## Show help message
	@grep -E '^[0-9a-zA-Z_-]+[[:blank:]]*:.*?## .*$$' $(MAKEFILE_LIST) | sort \
	| awk 'BEGIN {FS = ":.*?## "}; {printf "\033[1;32m%-15s\033[0m %s\n", $$1, $$2}'
