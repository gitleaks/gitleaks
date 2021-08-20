.PHONY: test test-cover build release-builds

VERSION := `git fetch --tags && git tag | sort -V | tail -1`
PKG=github.com/zricethezav/gitleaks
LDFLAGS=-ldflags "-X=github.com/zricethezav/gitleaks/v7/version.Version=$(VERSION)"
_LDFLAGS="github.com/zricethezav/gitleaks/v7/version.Version=$(VERSION)"
COVER=--cover --coverprofile=cover.out
IMAGE_PATH = "zricethezav/gitleaks"
ALPINE_VERSION = 3.14.1
GOLANG_VERSION = 1.17.0
DOCKER_BUILD_ARGS=--build-arg ALPINE_IMAGE_VERSION=$(ALPINE_VERSION) --build-arg GOLANG_IMAGE_VERSION=$(GOLANG_VERSION) --build-arg ldflags=$(_LDFLAGS)

test-cover:
	go test ./... --race $(COVER) $(PKG) -v
	go tool cover -html=cover.out

format:
	go fmt ./...

test: format
	go get golang.org/x/lint/golint
	go vet ./...
	golint ./...
	go test ./... --race $(PKG) -v

build: format
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
	env GOOS="windows" GOARCH="386" go$(DOCKER_BUILD_ARGS) uild -o "build/gitleaks-linux-amd64" $(LDFLAGS)
	env GOOS="linux" GOARCH="arm" go build -o "build/gitleaks-linux-arm" $(LDFLAGS)
	env GOOS="linux" GOARCH="mips" go build -o "build/gitleaks-linux-mips" $(LDFLAGS)
	env GOOS="linux" GOARCH="mips" go build -o "build/gitleaks-linux-mips" $(LDFLAGS)
	env GOOS="darwin" GOARCH="amd64" go build -o "build/gitleaks-darwin-amd64" $(LDFLAGS)

deploy:
	@echo "$(DOCKER_PASSWORD)" | docker login -u "$(DOCKER_USERNAME)" --password-stdin
	docker build $(DOCKER_BUILD_ARGS) -f Dockerfile -t $(IMAGE_PATH):latest -t $(IMAGE_PATH):$(VERSION) .
	echo "Pushing $(IMAGE_PATH):$(VERSION) and $(IMAGE_PATH):latest"
	docker push $(IMAGE_PATH)

dockerbuild:
	docker build $(DOCKER_BUILD_ARGS) -f Dockerfile -t $(IMAGE_PATH):latest -t $(IMAGE_PATH):$(VERSION) .
