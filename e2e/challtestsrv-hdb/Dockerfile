FROM golang:1.23-alpine AS builder

WORKDIR /go/challtestsrv-hdb

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
RUN go build -o challtestsrv-hdb .

FROM scratch
COPY --from=builder /go/challtestsrv-hdb/challtestsrv-hdb /usr/bin/challtestsrv-hdb
ENV PORT=8080
ENV GIN_MODE=release
EXPOSE 8080/tcp
ENTRYPOINT ["/usr/bin/challtestsrv-hdb"]
