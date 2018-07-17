.PHONY: test build-all release

test:
	go fmt
	golint
	go test --race -cover
deploy:
	echo "$(DOCKER_PASSWORD)" | docker login -u "$(DOCKER_USERNAME)" --password-stdin
	export REPO=zricethezav/gitleaks
	export TAG=`if [ "$(TRAVIS_BRANCH)" == "master" ]; then echo "latest"; else echo $(TRAVIS_BRANCH) ; fi`
	docker build -f Dockerfile -t $(REPO):$(COMMIT) .
	docker tag $(REPO):$(COMMIT) $(REPO):$(TAG)
	echo "Pushing $(REPO):$(COMMIT) $(REPO):$(TAG)"
	docker push $(REPO)

build-all:
	env GOOS="windows" GOARCH="amd64" go build -o "gitleaks-windows-amd64.exe"
	env GOOS="windows" GOARCH="386" go build -o "gitleaks-windows-386.exe"
	env GOOS="linux" GOARCH="amd64" go build -o "gitleaks-linux-amd64"
	env GOOS="linux" GOARCH="arm" go build -o "gitleaks-linux-arm"
	env GOOS="linux" GOARCH="mips" go build -o "gitleaks-linux-mips"
	env GOOS="linux" GOARCH="mips" go build -o "gitleaks-linux-mips"