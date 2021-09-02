FROM golang:1.15.5 AS build
WORKDIR /go/src/github.com/zricethezav/gitleaks
ARG ldflags
COPY . .
RUN GO111MODULE=on CGO_ENABLED=0 go build -o bin/gitleaks -ldflags "-X="${ldflags} *.go 

FROM alpine:3.14.1
# RUN apk add --no-cache bash git openssh
RUN adduser -D gitleaks && \
    apk add --no-cache bash git openssh-client
COPY --from=build /go/src/github.com/zricethezav/gitleaks/bin/* /usr/bin/
USER gitleaks
ENTRYPOINT ["gitleaks"]

# How to use me :

# docker build -t gitleaks .
# docker run --rm --name=gitleaks gitleaks --repo-url=https://github.com/zricethezav/gitleaks

# This will check for secrets in https://github.com/zricethezav/gitleaks
