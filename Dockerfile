ARG ALPINE_IMAGE_VERSION=3.14.1
ARG GOLANG_IMAGE_VERSION=1.17.0
FROM golang:$GOLANG_IMAGE_VERSION AS build
WORKDIR /go/src/github.com/zricethezav/gitleaks
ARG ldflags
COPY . .
RUN GO111MODULE=on CGO_ENABLED=0 go build -o bin/gitleaks -ldflags "-X="${ldflags} *.go 

FROM alpine:$ALPINE_IMAGE_VERSION
RUN adduser -D gitleaks && \
    apk add --no-cache bash git openssh-client
COPY --from=build /go/src/github.com/zricethezav/gitleaks/bin/* /usr/bin/
USER gitleaks
ENTRYPOINT ["gitleaks"]

# How to use me :

# docker build -t gitleaks .
# docker run --rm --name=gitleaks gitleaks --repo-url=https://github.com/zricethezav/gitleaks

# This will check for secrets in https://github.com/zricethezav/gitleaks

# To scan the current local directory, no git
# docker run --rm -v $(pwd):/tmp --name=gitleaks zricethezav/gitleaks --path=/tmp --no-git