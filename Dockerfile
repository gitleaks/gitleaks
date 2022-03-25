FROM golang:1.18-alpine  AS build

WORKDIR /go/src/github.com/zricethezav/gitleaks
COPY . .
RUN apk add --no-cache bash git openssh-client && \
    VERSION="$(git describe --tags --abbrev=0)" && \
    CGO_ENABLED=0 go build -o bin/gitleaks -ldflags "-X="github.com/zricethezav/gitleaks/v8/cmd.Version="${VERSION}"

FROM gcr.io/distroless/base-debian11

USER nonroot:nonroot
COPY --from=build --chown=nonroot:nonroot /go/src/github.com/zricethezav/gitleaks/bin/* /usr/bin/
ENTRYPOINT ["gitleaks"]

