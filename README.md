# lego-hdb

This repository implements an DNS provider for Imperial's HDB system. The
provider is suitable for any `foo.dide.ic.ac.uk` domains managed by the
RESIDE team.

## Usage

You should create an `hdb-credentials` file containing the credentials
provided to you by ICT.

The file should have the following format:
```
HDB_ACME_USERNAME=xxx
HDB_ACME_PASSWORD=yyy
```

Then run the Docker images as such, replacing `NAME.dide.ic.ac.uk` by the
domain name of your choice:

```sh
docker run \
    --env-file hdb-credentials \
    --volume $PWD/.lego:/.lego \
    ghcr.io/reside-ic/lego-hdb \
    --domains "NAME.dide.ic.ac.uk" \
    --email reside@imperial.ac.uk \
    --dns exec \
    --accept-tos run
```

See the [lego documentation](https://go-acme.github.io/lego/usage/cli/options/index.html)
for more explanation about each of these options.

When prototyping, use the `--server https://acme-staging-v02.api.letsencrypt.org/directory`
flag to avoid issuing real-world certificates as well as hitting Let's
Encrypt's rate limits.

Assuming this succeeds, it will create a `.lego/certificates` directory
containing the newly obtained certs. Additionally, the `.lego/accounts`
directory will contains the account details used to renew or revoke the
certificate. 

## Automatic renewal

Once the above command has been run once, you should be able to run it again
using `renew` instead of `run` as the final argument.

You should configure your system to do this daily. As long as the certificates
are still valid, the command will do nothing and succeed.

# Implementation

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

This repository provides an implementation of ICT's protocol allowing us to
create and delete `_acme-challenge` DNS records.

Lego is configured to delegate the DNS configuration to an external script,
`lego-hdb-plugin.py`. This script makes an HTTP request to the appropriate
ICT-managed endpoint.
