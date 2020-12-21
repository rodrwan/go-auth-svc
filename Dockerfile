FROM golang:1.13-alpine3.11 AS build
RUN apk --no-cache add clang gcc g++ make git ca-certificates

WORKDIR /go/src/github.com/rodrwan/go-auth-svc
COPY go.mod go.sum main.go ./
COPY cmd cmd
RUN go build -o /go/bin/app ./cmd/server

FROM alpine:3.11
WORKDIR /usr/bin
COPY --from=build /go/bin .
EXPOSE 8080
CMD ["app"]