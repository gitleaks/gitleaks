.PHONY: test test-cover

PKG=github.com/zricethezav/gitleaks
VERSION := `git fetch --tags && git tag | sort -V | tail -1`
LDFLAGS=-ldflags "-X=github.com/zricethezav/gitleaks/v8/cmd.Version=$(VERSION)"
COVER=--cover --coverprofile=cover.out

test-cover:
	go test -v ./... --race $(COVER) $(PKG)
	go tool cover -html=cover.out

format:
	go fmt ./...

test: format
	go vet ./...
	go test -v ./... --race $(PKG) 

build: format
	go vet ./...
	go mod tidy
	go build $(LDFLAGS)

clean:
	find . -type f -name '*.got.*' -delete
	find . -type f -name '*.out' -delete
