.PHONY: build run clean all test test-coverage

all: build

build:
	go build -o go_gal main.go

run: build
	./go_gal

run-ssl: build
	./go_gal --ssl --cert=cert.pem --key=key.pem --port=8443

clean:
	rm -f go_gal

deps:
	go mod download

test:
	go test -v ./...

test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out