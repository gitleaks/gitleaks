FROM golang:1.10.0-alpine3.7

WORKDIR /app

RUN apk update && apk upgrade && apk add --no-cache bash git openssh

COPY . ./

RUN go get -u github.com/zricethezav/gitleaks
RUN go build

ENTRYPOINT ["gitleaks"]


# How to use me :

# docker build -t gitleaks .
# docker run --rm --name=gitleaks gitleaks https://github.com/zricethezav/gitleaks

# This will check for secrets in https://github.com/zricethezav/gitleaks
