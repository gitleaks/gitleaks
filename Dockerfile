FROM golang:1.17 AS build
WORKDIR /go/src/github.com/zricethezav/gitleaks
COPY . .
RUN GO111MODULE=on CGO_ENABLED=0 go build -o bin/gitleaks *.go 

FROM alpine:3.14.1
RUN adduser -D gitleaks && \
    apk add --no-cache bash git openssh-client
COPY --from=build /go/src/github.com/zricethezav/gitleaks/bin/* /usr/bin/
USER gitleaks
ENTRYPOINT ["gitleaks"]
