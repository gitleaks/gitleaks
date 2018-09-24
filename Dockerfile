FROM golang:1.11.0 AS build
WORKDIR /go/src/github.com/mahirrudin/gitleaks
COPY . .
RUN CGO_ENABLED=0 go build -o bin/gitleaks *.go

FROM alpine:3.7
RUN apk add --no-cache bash git openssh
COPY --from=build /go/src/github.com/mahirrudin/gitleaks/bin/* /usr/bin/
ENTRYPOINT ["gitleaks"]

# How to use me :

# docker build -t gitleaks .
# docker run --rm --name=gitleaks gitleaks https://github.com/mahirrudin/gitleaks

# This will check for secrets in https://github.com/mahirrudin/gitleaks
