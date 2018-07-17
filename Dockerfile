FROM golang:1.10.0 AS build
WORKDIR /go/src/github.com/zricethezav/gitleaks
COPY . .
RUN CGO_ENABLED=0 go build -o bin/gitleaks *.go

FROM alpine:3.7
RUN apk add --no-cache bash git openssh
COPY --from=build /go/src/github.com/zricethezav/gitleaks/bin/* /usr/bin/
ENTRYPOINT ["gitleaks"]

# How to use me :

# docker build -t gitleaks .
# docker run --rm --name=gitleaks gitleaks https://github.com/zricethezav/gitleaks

# This will check for secrets in https://github.com/zricethezav/gitleaks
