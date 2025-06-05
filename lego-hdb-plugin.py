#!/usr/bin/env python3

# This script is invoked by lego, as is not intended to be called directly.
# See https://go-acme.github.io/lego/dns/exec/index.html for the expected interface.

import os
import sys

import requests
from requests.auth import HTTPBasicAuth


def die(msg):
    print(msg, file=sys.stderr)
    sys.exit(1)


username = os.getenv("HDB_ACME_USERNAME")
password = os.getenv("HDB_ACME_PASSWORD")

if username is None or password is None:
    die(
        "HDB credentials missing. Set the HDB_ACME_USERNAME and HDB_ACME_PASSWORD environment variables."
    )

if len(sys.argv) != 4:
    die("Invalid usage")

action = sys.argv[1]
fqdn = sys.argv[2]
value = sys.argv[3]

if action == "present":
    method = "PUT"
elif action == "cleanup":
    method = "DELETE"
else:
    die(f"Invalid action {action}")

auth = HTTPBasicAuth(username, password)

# Lego passes a trailing dot in the FQDN, which the HDB API refuses, hence the
# rstrip.
url = f"https://hdb.ic.ac.uk/api/acme/v0/{fqdn.rstrip('.')}/auth_token"

# For some reason, the HDB API requires the token to be wrapped in an extra
# layer of quotes.
payload = {"token": f'"{value}"'}

r = requests.request(method, url, json=payload, auth=auth)
r.raise_for_status()
