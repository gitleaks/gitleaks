FROM golang:1.17 AS build
WORKDIR /go/src/github.com/zricethezav/gitleaks
COPY . .
RUN VERSION=$(git describe --tags --abbrev=0) && \
CGO_ENABLED=0 go build -o bin/gitleaks -ldflags "-X="github.com/zricethezav/gitleaks/v8/cmd.Version=${VERSION}

FROM alpine:3.14.2
RUN adduser -D gitleaks && \
    apk add --no-cache bash git openssh-client
COPY --from=build /go/src/github.com/zricethezav/gitleaks/bin/* /usr/bin/
USER gitleaks
ENTRYPOINT ["gitleaks"]
