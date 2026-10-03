# Testing

This directory contains the test harness for testing `acme_poly.py`
against different account key and server key types against the Pebble
server.

The supported key types are: `P-256`, `P-384`, `P-521` elliptic curves
(recommended) and `RSA 4096` (deprecated).

For each key type:

* `account.*.pem` is the account private key.
* `server.*.pem` is the server private key.  It generates all `test_case.*.csr`

Each test case will end up creating:

* `test_case.*.csr` is the certificate signing request for the test case.
* `test_case.*.crt` is the certificate issued by ACME.
* `test_case.*.log` is the debug log.

The test cases are:

* Local tests: these tests do not publish challenge tokens so they run
  locally without external network access.

  * `pebble_*` will use a local development pebble server; domain
    validation must be disabled by setting `PEBBLE_VA_ALWAYS_VALID=1`
    in the environment variable.

    * `pebble_http_01.*` covers the HTTP-01 challenge method.
    * `pebble_dns_01.*` covers the DNS-01 challenge method.
    * `pebble_dns_persist_01.*` covers the DNS-PERSIST-01 challenge method.

* Cloudflare tests: these tests publish DNS challenges to Cloudflare.
  They require the Cloudflare config in `config.mk`.  Run `make
  config.mk` to create a template.  Get a Cloudflare API token and put
  it in a file named `cloudflare_token`.

  * `cloudflare_pebble_*` still uses a local pebble server, but domain
    validation should be enabled.

    * `cloudflare_pebble_dns_01.*` covers the DNS-01 challenge method.
    * `cloudflare_pebble_dns_persist_01.*` covers the DNS-PERSIST-01
      challenge method.

  * `cloudflare_staging_*` uses the Let's Encrypt staging environment.

    * `cloudflare_staging_dns_01.*` covers the DNS-01 challenge method.
    * `cloudflare_staging_dns_persist_01.*` covers the DNS-PERSIST-01
      challenge method.

The `Makefile` provides the following targets:

* `make` or `make all` generates all keys and runs all local tests for
  the supported key types.
* `make clean` removes the certificates but keeps the keys.
* `make distclean` additionally removes all the keys.

More specifically:

* `make all-keys` generates all keys.
* `make pebble_http_01` runs the pebble HTTP-01 tests for all supported key
  types.
* `make pebble_dns_01` runs the pebble DNS-01 tests for all supported
  key types.
* `make pebble_dns_persist_01` runs the pebble DNS-PERSIST-01 tests
  for all supported key types.
* `make cloudflare_pebble` and `make cloudflare_staging` runs selected
  cloudflare pebble and staging tests with P-256 and P-384 keys.

All pebble tests assume that a pebble server is already running
locally.  If not already:

One time setup:

```shell
git clone https://github.com/letsencrypt/pebble.git
```

Start pebble:

```shell
cd pebble

# Set PEBBLE_VA_ALWAYS_VALID=1 for local tests, 0 for DNS validation tests.
PEBBLE_VA_ALWAYS_VALID=1 \
  go run ./cmd/pebble -config ./test/config/pebble-config.json
```
