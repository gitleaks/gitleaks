FROM golang:1.23 AS build
WORKDIR /go/src/github.com/zricethezav/gitleaks
COPY . .
RUN VERSION=$(git describe --tags --abbrev=0) && \
CGO_ENABLED=0 go build -o bin/gitleaks -ldflags "-X=github.com/zricethezav/gitleaks/v8/cmd.Version=${VERSION}"

FROM alpine:3.19
RUN apk add --no-cache bash git openssh-client
COPY --from=build /go/src/github.com/zricethezav/gitleaks/bin/* /usr/bin/

RUN git config --global --add safe.directory '*'

ENTRYPOINT ["gitleaks"]
