# acme-buddy

This repository implements an ACME client for requesting certificates from
Let's Encrypt. Unlike other implementations such as certbot and lego, this
client is a long-running process, that will automatically renew certificates
when they approach expiry.

After renewing the certificate, it can send a signal to a Docker container,
instructing it to reload its certificates.

## Usage

The most basic usage is show below. `<FQDN>` and `<PROVIDER>` should be
replaced by their appropriate values. The provider should match the service
used to register `<FQDN>`.

```sh
docker run \
    --env-file credentials \
    ghcr.io/reside-ic/acme-buddy \
    --domain "<FQDN>" \
    --email reside@imperial.ac.uk \
    --dns-provider "<PROVIDER>"
```

Credentials used by the DNS provider are passed as environment variables. In
the example above, that is done via the use of a `credentials` file.

In practice, the command above is not very useful as it does not store the
certificate or private key anywhere. The `--certificate-path` and `--key-path`
options should be used in conjunction with a Docker volume to make them
accessible to the application. Additionally the `--account-path` can be used to
store and cache account details across invocations.

```sh
docker run
    --env-file credentials \
    --volume tls:/tls \
    ghcr.io/reside-ic/acme-buddy \
    --certificate-path /tls/cert.pem \
    --key-path /tls/key.pem \
    --account-path /tls/account.json \
    <other options...>
```

During development, the `--staging` flag should be used to target Let's Encrypt
staging environment. This prevents us from reaching Let's Encrypt's rate limits
and also avoids issuing read-world certificates.

If the `--oneshot` flag is provided, the client will obtain a new certificate
and exit immediately, instead of waiting to renew it. This can be used during
the initial deployment stage to avoid races between acme-buddy and the web
server container starting up.

## DNS Providers

Only two DNS providers are currently supported, Cloudflare and HDB. HDB is the
internal API used by Imperial ICT. The provider is suitable for any
`dide.ic.ac.uk` sub-domains managed by the RESIDE team. Cloudflare is used for
Montagu's production instance.

Lego, the underlying ACME implementation, supports [dozens of providers][lego-dns].
Should the need arise, adding these providers to acme-buddy is an easy and
straightforward change.

[lego-dns]: https://go-acme.github.io/lego/dns/index.html

### HDB ACME

You should create a `credentials` file containing the credentials provided to
you by ICT:
```
HDB_ACME_USERNAME=xxx
HDB_ACME_PASSWORD=yyy
```

Additionally the `HDB_ACME_URL` variable is supported. This is needed for
integration tests only. In practice the default value should be sufficient.

### Cloudflare

See the [lego documentation][lego-cloudflare].

[lego-cloudflare]: https://go-acme.github.io/lego/dns/cloudflare/

## Reloading a container

acme-buddy is designed to run alongside a container that acts as an HTTP
server. The two containers should share a Docker volume, which will be used by
acme-buddy to write the certificate and private key, and from which the HTTP
will read them.

Whenever the certificate is renewed, acme-buddy can send a Unix signal (SIGHUP
by default) to the HTTP server container, instructing it to reload its
certificate. The most common usecase is to run nginx, but any service with an
HTTP interface that needs a certificate and which supports reload on signal can
benefit from this (eg. Vault).

To allow acme-buddy to send signals to other containers, the Docker Unix socket
should be bind-mounted into its container. Additionally, the
`--reload-container` option is used to specify the name or ID of the container
that needs to be reloaded.

```sh
docker run
    --volume /var/run/docker.sock:/var/run/docker.sock \
    --volume tls:/tls \
    ghcr.io/reside-ic/acme-buddy \
    --certificate-path /tls/cert.pem \
    --key-path /tls/key.pem \
    --account-path /tls/account.json \
    --reload-container proxy \
    <other options...>
```

It is assumed that the `tls` volume used to store keys and certificates in
shared with the HTTP service container, allowing the later to read the files
upon reception of the signal.

# Testing

The package has both unit and integration tests. They can be run as follows:
```
go test       # Unit tests
go test ./e2e # Integration tests
```

The integration tests use Docker. They start and stop all containers as needed,
without the need for any external setup.

# Implementation details

Let's Encrypt and the ACME protocol allow automatic provisioning of TLS
certificates. Before being issued a certificate for a domain, we must prove
ownership of it.

To prove ownership, the ACME service hands us a random token which we must host
on our domain. There are at least two ways to host this token:

- Host a special file accessible as an endpoint under the `http://DOMAIN/.well-known/acme-challenge` URL.
- Install a TXT DNS record under the `_acme-challenge.DOMAIN` name.

The first option only works for publicly available domains, since it needs to
be accessible from Let's Encrypt's infrastructure. For many of our domains and
services, this is not possible.

The second option works even for internal-only services, but requires
coordination with the DNS provider. The lego ACME client implements dozens of
3rd party providers already, but Imperial's ICT team operates a custom system
that is incompatible with any of the providers implemented out of the box by
lego.

This repository provides an implementation of ICT's API allowing us to create
and delete `_acme-challenge` DNS records as required.
