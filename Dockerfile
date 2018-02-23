FROM golang:1.10.0 AS build

ENV PROJECT /go/src/github.com/zricethezav/gitleaks

RUN mkdir -p $PROJECT

WORKDIR ${PROJECT}

RUN git clone https://github.com/zricethezav/gitleaks.git . \
  && CGO_ENABLED=0 go build -o bin/gitleaks *.go

FROM alpine:3.7

ENV PROJECT /go/src/github.com/zricethezav/gitleaks

WORKDIR /app

RUN apk update && apk upgrade && apk add --no-cache bash git openssh

COPY --from=build $PROJECT/bin/* /usr/bin/

ENTRYPOINT ["gitleaks"]

# How to use me :

# docker build -t gitleaks .
# docker run --rm --name=gitleaks gitleaks https://github.com/zricethezav/gitleaks

# This will check for secrets in https://github.com/zricethezav/gitleaks
