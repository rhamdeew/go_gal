.PHONY: build run clean all test test-coverage help deps

# Default target - display help
.DEFAULT_GOAL := help

all: build ## Build the application (default)

build:
	go build -o go_gal .

help: ## Show this help message
	@echo "Usage: make [target]"
	@echo ""
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

run: build ## Build and run the application
	./go_gal

run-ssl: build ## Build and run with SSL enabled on port 8443
	./go_gal --ssl --cert=cert.pem --key=key.pem --port=8443

clean: ## Remove build artifacts
	rm -f go_gal

deps: ## Download Go module dependencies
	go mod download

test: ## Run all tests with verbose output
	go test -v ./...

test-coverage: ## Run tests with coverage report (opens in browser)
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out