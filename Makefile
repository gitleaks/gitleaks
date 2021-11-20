.PHONY: test test-cover

PKG=github.com/zricethezav/gitleaks
COVER=--cover --coverprofile=cover.out

test-cover:
	go test ./... --race $(COVER) $(PKG) -v
	go tool cover -html=cover.out

format:
	go fmt ./...

test: format
	go vet ./...
	go test ./... --race $(PKG) -v

build: format
	go vet ./...
	go mod tidy
	go build

