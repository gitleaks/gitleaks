.PHONY: test build-all build-deps build-os deploy

test:
	go get golang.org/x/lint/golint
	go fmt
	golint
	go test --race --cover github.com/zricethezav/gitleaks/src -v

deploy:
	@echo "$(DOCKER_PASSWORD)" | docker login -u "$(DOCKER_USERNAME)" --password-stdin
	docker build -f Dockerfile -t $(REPO):$(TAG) .
	echo "Pushing $(REPO):$(COMMIT) $(REPO):$(TAG)"
	docker push $(REPO)

build-deps:
	rm -rf build
	mkdir build

GOOS ?= linux
GOARCH ?= amd64
build-os: build-deps
	env GOOS="$(GOOS)" GOARCH="$(GOARCH)" go build -o "build/gitleaks-$(GOOS)-$(GOARCH)"

build-all: build-deps
	env GOOS="windows" GOARCH="amd64" go build -o "build/gitleaks-windows-amd64.exe"
	env GOOS="windows" GOARCH="386" go build -o "build/gitleaks-windows-386.exe"
	env GOOS="linux" GOARCH="amd64" go build -o "build/gitleaks-linux-amd64"
	env GOOS="linux" GOARCH="arm" go build -o "build/gitleaks-linux-arm"
	env GOOS="linux" GOARCH="mips" go build -o "build/gitleaks-linux-mips"
	env GOOS="linux" GOARCH="mips" go build -o "build/gitleaks-linux-mips"
	env GOOS="darwin" GOARCH="amd64" go build -o "build/gitleaks-darwin-amd64"
