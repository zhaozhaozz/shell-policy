BINARY := bin/shell-policy
PKG := ./...

.PHONY: all build test vet fmt cover clean run

all: build

build:
	go build -o $(BINARY) ./cmd/shell-policy

test:
	go test $(PKG)

vet:
	go vet $(PKG)

fmt:
	gofmt -l -w .

cover:
	go test -cover $(PKG)

clean:
	rm -rf bin

# Convenience target: make run CMD='rm -rf /'
run: build
	./$(BINARY) explain $(CMD)
