.PHONY: build run clean all

all: build

build:
	go build -o go_gal main.go

run: build
	./go_gal

clean:
	rm -f go_gal

deps:
	go mod download