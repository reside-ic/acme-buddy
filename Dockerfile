FROM golang:1.27-alpine AS builder

WORKDIR /go/acme-buddy

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
COPY patches/ ./patches/

RUN go mod vendor
RUN sh patches/fix-docker-archive.sh

RUN go build -o acme-buddy
RUN go test -v

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /go/acme-buddy/acme-buddy /usr/bin/acme-buddy
ENTRYPOINT [ "/usr/bin/acme-buddy" ]
