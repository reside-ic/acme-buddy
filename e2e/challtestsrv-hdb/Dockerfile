FROM golang:1.27-alpine AS builder

WORKDIR /go/challtestsrv-hdb

RUN apk add --no-cache openssl

RUN mkdir -p /certs \
    && openssl req -x509 -newkey rsa:2048 -nodes \
       -keyout /certs/server.key \
       -out /certs/server.crt \
       -days 3650 \
       -subj "/CN=challtestsrv" \
       -addext "subjectAltName=DNS:challtestsrv"

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
RUN go build -o challtestsrv-hdb .

FROM scratch

COPY --from=builder /go/challtestsrv-hdb/challtestsrv-hdb /usr/bin/challtestsrv-hdb
COPY --from=builder /certs/server.crt /certs/server.crt
COPY --from=builder /certs/server.key /certs/server.key

ENV PORT=8080
ENV GIN_MODE=release
EXPOSE 8080/tcp

ENTRYPOINT ["/usr/bin/challtestsrv-hdb"]
