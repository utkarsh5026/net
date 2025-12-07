# Makefile for Go Network Protocol Implementation
# Module: github.com/utkarsh5026/net

.PHONY: help all build test test-verbose test-coverage clean fmt fmt-check vet lint modernize tidy deps bench install-tools examples run-capture run-arp run-arp-demo

# Default target
.DEFAULT_GOAL := help

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet

# Directories
PKG_DIR=./pkg/...
EXAMPLES_DIR=./examples/...
COVERAGE_DIR=coverage

# Binary output
BINARY_DIR=bin
EXAMPLE_BINARIES=$(BINARY_DIR)/capture $(BINARY_DIR)/arp-visualizer

# Colors for output
COLOR_RESET=\033[0m
COLOR_BOLD=\033[1m
COLOR_GREEN=\033[32m
COLOR_YELLOW=\033[33m
COLOR_BLUE=\033[34m

##@ General

help: ## Display this help message
	@echo "$(COLOR_BOLD)Available targets:$(COLOR_RESET)"
	@awk 'BEGIN {FS = ":.*##"; printf "\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  $(COLOR_BLUE)%-20s$(COLOR_RESET) %s\n", $$1, $$2 } /^##@/ { printf "\n$(COLOR_BOLD)%s$(COLOR_RESET)\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

all: clean fmt vet test build ## Run all checks and build

##@ Development

fmt: ## Format all Go source files
	@echo "$(COLOR_GREEN)Formatting code...$(COLOR_RESET)"
	@$(GOFMT) $(PKG_DIR)
	@$(GOFMT) $(EXAMPLES_DIR)

fmt-check: ## Check if code is formatted properly
	@echo "$(COLOR_GREEN)Checking code formatting...$(COLOR_RESET)"
	@test -z "$$(gofmt -l .)" || (echo "$(COLOR_YELLOW)Files need formatting:$(COLOR_RESET)" && gofmt -l . && exit 1)

vet: ## Run go vet on all packages
	@echo "$(COLOR_GREEN)Running go vet...$(COLOR_RESET)"
	@$(GOVET) $(PKG_DIR)
	@$(GOVET) $(EXAMPLES_DIR)

lint: ## Run golangci-lint (requires golangci-lint installation)
	@echo "$(COLOR_GREEN)Running golangci-lint...$(COLOR_RESET)"
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "$(COLOR_YELLOW)golangci-lint not installed. Run 'make install-tools' to install it.$(COLOR_RESET)"; \
	fi

modernize: ## Modernize Go code using gopls modernize analyzer
	@echo "$(COLOR_GREEN)Running modernize...$(COLOR_RESET)"
	@$(GOCMD) run golang.org/x/tools/gopls/internal/analysis/modernize/cmd/modernize@latest -fix -test ./...

##@ Testing

test: ## Run all tests
	@echo "$(COLOR_GREEN)Running tests...$(COLOR_RESET)"
	@$(GOTEST) -race -short $(PKG_DIR)

test-verbose: ## Run all tests with verbose output
	@echo "$(COLOR_GREEN)Running tests (verbose)...$(COLOR_RESET)"
	@$(GOTEST) -v -race $(PKG_DIR)

test-coverage: ## Run tests with coverage report
	@echo "$(COLOR_GREEN)Running tests with coverage...$(COLOR_RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) -race -coverprofile=$(COVERAGE_DIR)/coverage.out -covermode=atomic $(PKG_DIR)
	@$(GOCMD) tool cover -html=$(COVERAGE_DIR)/coverage.out -o $(COVERAGE_DIR)/coverage.html
	@echo "$(COLOR_GREEN)Coverage report generated: $(COVERAGE_DIR)/coverage.html$(COLOR_RESET)"
	@$(GOCMD) tool cover -func=$(COVERAGE_DIR)/coverage.out

test-integration: ## Run integration tests
	@echo "$(COLOR_GREEN)Running integration tests...$(COLOR_RESET)"
	@$(GOTEST) -v -race $(PKG_DIR)

bench: ## Run benchmarks
	@echo "$(COLOR_GREEN)Running benchmarks...$(COLOR_RESET)"
	@$(GOTEST) -bench=. -benchmem $(PKG_DIR)

##@ Build

build: ## Build all example binaries
	@echo "$(COLOR_GREEN)Building examples...$(COLOR_RESET)"
	@mkdir -p $(BINARY_DIR)
	@$(GOBUILD) -o $(BINARY_DIR)/capture ./examples/capture
	@$(GOBUILD) -o $(BINARY_DIR)/arp-visualizer ./examples/arp

build-all: build ## Build all binaries (alias for build)

examples: build ## Build example programs

##@ Examples

run-capture: build ## Run the packet capture example (requires sudo). Use ARGS for flags (e.g., ARGS="-i eth0 -c 10")
	@echo "$(COLOR_GREEN)Running capture example...$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)Note: This requires root privileges$(COLOR_RESET)"
	@sudo $(BINARY_DIR)/capture $(ARGS)

run-arp: build ## Run the ARP network scanner (requires sudo). Usage: make run-arp IFACE=eth0 LOCAL_IP=192.168.1.100
	@echo "$(COLOR_GREEN)Running ARP Network Scanner...$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)Note: This requires root privileges$(COLOR_RESET)"
	@if [ -z "$(IFACE)" ] || [ -z "$(LOCAL_IP)" ]; then \
		echo "$(COLOR_YELLOW)Usage: make run-arp IFACE=<interface> LOCAL_IP=<your-ip>$(COLOR_RESET)"; \
		echo "$(COLOR_YELLOW)Example: make run-arp IFACE=eth0 LOCAL_IP=192.168.1.100$(COLOR_RESET)"; \
		echo ""; \
		echo "Find your network info with:"; \
		echo "  - List interfaces: ip addr show"; \
		echo "  - Show your IP: ip addr show <interface>"; \
		exit 1; \
	fi
	@sudo $(BINARY_DIR)/arp-visualizer $(IFACE) $(LOCAL_IP)

run-arp-demo: build ## Run ARP scanner demo (interactive - will prompt for network info)
	@echo "$(COLOR_GREEN)ARP Network Scanner - Interactive Setup$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_BOLD)Find your network interface:$(COLOR_RESET)"
	@echo "Available interfaces:"
	@ip -brief addr show | grep -v "lo" || true
	@echo ""
	@read -p "Enter interface name (e.g., eth0, wlan0): " iface; \
	read -p "Enter your IP address: " local_ip; \
	echo ""; \
	echo "$(COLOR_GREEN)Starting ARP Network Scanner...$(COLOR_RESET)"; \
	echo "$(COLOR_YELLOW)Will scan subnet for $$local_ip on $$iface$(COLOR_RESET)"; \
	echo "$(COLOR_YELLOW)Press 's' in the app to start scanning!$(COLOR_RESET)"; \
	echo ""; \
	sudo $(BINARY_DIR)/arp-visualizer $$iface $$local_ip

install: ## Install binaries to GOPATH/bin
	@echo "$(COLOR_GREEN)Installing binaries...$(COLOR_RESET)"
	@$(GOCMD) install ./examples/...

##@ Dependencies

deps: ## Download dependencies
	@echo "$(COLOR_GREEN)Downloading dependencies...$(COLOR_RESET)"
	@$(GOMOD) download

tidy: ## Tidy and verify module dependencies
	@echo "$(COLOR_GREEN)Tidying module dependencies...$(COLOR_RESET)"
	@$(GOMOD) tidy
	@$(GOMOD) verify

vendor: ## Create vendor directory
	@echo "$(COLOR_GREEN)Creating vendor directory...$(COLOR_RESET)"
	@$(GOMOD) vendor

upgrade-deps: ## Upgrade all dependencies
	@echo "$(COLOR_GREEN)Upgrading dependencies...$(COLOR_RESET)"
	@$(GOGET) -u ./...
	@$(GOMOD) tidy

##@ Cleanup

clean: ## Clean build artifacts and coverage reports
	@echo "$(COLOR_GREEN)Cleaning...$(COLOR_RESET)"
	@$(GOCLEAN)
	@rm -rf $(BINARY_DIR)
	@rm -rf $(COVERAGE_DIR)
	@rm -rf vendor

clean-cache: ## Clean Go build cache
	@echo "$(COLOR_GREEN)Cleaning build cache...$(COLOR_RESET)"
	@$(GOCMD) clean -cache -testcache -modcache

##@ Tools

install-tools: ## Install development tools
	@echo "$(COLOR_GREEN)Installing development tools...$(COLOR_RESET)"
	@echo "Installing golangci-lint..."
	@$(GOCMD) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@echo "$(COLOR_GREEN)Tools installed successfully$(COLOR_RESET)"

##@ CI/CD

ci: fmt-check vet test ## Run CI checks (format check, vet, test)

pre-commit: fmt vet test ## Run pre-commit checks (format, vet, test)

check: fmt-check vet lint test ## Run all checks without modifying files
