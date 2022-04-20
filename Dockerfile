FROM golang:1.18 AS build
WORKDIR /go/src/github.com/zricethezav/gitleaks
COPY . .
RUN VERSION=$(git describe --tags --abbrev=0) && \
CGO_ENABLED=0 go build -o bin/gitleaks -ldflags "-X="github.com/zricethezav/gitleaks/v8/cmd.Version=${VERSION}

FROM alpine:3.15.4
RUN adduser -D gitleaks && \
    apk add --no-cache bash git openssh-client
COPY --from=build /go/src/github.com/zricethezav/gitleaks/bin/* /usr/bin/
USER gitleaks

# default to avoid the follow error:
# 11:09PM ERR fatal: unsafe repository ('/path' is owned by someone else)
# 11:09PM ERR To add an exception for this directory, call:
# 11:09PM ERR 
# 11:09PM ERR     git config --global --add safe.directory /path
# This means that when you run gitleaks from docker you must mount to /path
# in order to avoid this error.

# TODO waiting to push this until I've thought a bit more about it
# RUN git config --global --add safe.directory /path

ENTRYPOINT ["gitleaks"]
