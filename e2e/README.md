# End-to-end tests
## Usage

From the top of the repository, run:

```sh
go test ./e2e -v
```

## Structure

The end-to-end tests run a local instance [pebble][pebble], as a small and
standalone implementation of an ACME Certificate Authority.

Rather than use the system's DNS resolver, pebble is configured to use a mock
DNS server based on [challtestsrv][challtestsrv]. This allows us to run
integration tests without the need to have access to real-world DNS records.

The [challtestsrv-hdb](./challtestsrv-hdb) directory implements an HTTP API
that wraps challtestsrv and which mimicks Imperial ICT's HDB API. The same Lego
DNS provider implementation used to target the HDB API can be used in our
tests.

The tests are implemented in Go and run all of the needed services as Docker
containers. The [testcontainers][testcontainers] project is used to setup and
control the containers from the tests themselves. There are external
dependencies required other than Docker itself.

By default, the tests build a Docker image of acme-buddy from the local
directory. You can also run the tests against an existing image using the
`--image` flag:

```sh
go test -v ./e2e --image=ghcr.io/reside-ic/acme-buddy
```

[pebble]: https://github.com/letsencrypt/pebble
[challtestsrv]: https://github.com/letsencrypt/challtestsrv
[testcontainers]: https://testcontainers.com/
