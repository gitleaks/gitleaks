.PHONY: test test-cover build release-builds

VERSION := `git fetch --tags && git tag | sort -V | tail -1`
PKG=github.com/zricethezav/gitleaks
LDFLAGS=-ldflags "-X=github.com/zricethezav/gitleaks/v5/version.Version=$(VERSION)"
_LDFLAGS="github.com/zricethezav/gitleaks/v5/version.Version=$(VERSION)"
COVER=--cover --coverprofile=cover.out

test-cover:
	go test ./... --race $(COVER) $(PKG) -v
	go tool cover -html=cover.out

test:
	go get golang.org/x/lint/golint
	go fmt ./...
	go vet ./...
	golint ./...
	go test ./... --race $(PKG) -v

test-integration:
	go test github.com/zricethezav/gitleaks/hosts -v -integration

build:
	go fmt ./...
	golint ./...
	go vet ./...
	go mod tidy
	go build $(LDFLAGS)

security-scan:
	go get github.com/securego/gosec/cmd/gosec
	gosec -no-fail ./...

release-builds:
	rm -rf build
	mkdir build
	env GOOS="windows" GOARCH="amd64" go build -o "build/gitleaks-windows-amd64.exe" $(LDFLAGS)
	env GOOS="windows" GOARCH="386" go build -o "build/gitleaks-windows-386.exe" $(LDFLAGS)
	env GOOS="linux" GOARCH="amd64" go build -o "build/gitleaks-linux-amd64" $(LDFLAGS)
	env GOOS="linux" GOARCH="arm" go build -o "build/gitleaks-linux-arm" $(LDFLAGS)
	env GOOS="linux" GOARCH="mips" go build -o "build/gitleaks-linux-mips" $(LDFLAGS)
	env GOOS="linux" GOARCH="mips" go build -o "build/gitleaks-linux-mips" $(LDFLAGS)
	env GOOS="darwin" GOARCH="amd64" go build -o "build/gitleaks-darwin-amd64" $(LDFLAGS)

deploy:
	@echo "$(DOCKER_PASSWORD)" | docker login -u "$(DOCKER_USERNAME)" --password-stdin
	docker build --build-arg ldflags=$(_LDFLAGS) -f Dockerfile -t zricethezav/gitleaks:latest -t zricethezav/gitleaks:$(VERSION) . 
	echo "Pushing zricethezav/gitleaks:$(VERSION) and zricethezav/gitleaks:latest"
	docker push zricethezav/gitleaks

dockerbuild: 
	docker build --build-arg ldflags=$(_LDFLAGS) -f Dockerfile -t zricethezav/gitleaks:latest -t zricethezav/gitleaks:$(VERSION) . 
