# acme-poly

This is a not-so-tiny but still auditable script that you can throw on
your server to issue and renew [Let's
Encrypt](https://letsencrypt.org/) certificates. The only
prerequisites are Python (3.9 or later) and OpenSSL, and optionally
dnspython for dns challenge methods.

This is a fork combining:

  * The original diafygi/acme-tiny: <https://github.com/diafygi/acme-tiny>
  * The nuxi/acme-dns fork: <https://github.com/nuxi/acme-dns>
  * The thusoy/acme-tiny-dns01 fork: <https://github.com/thusoy/acme-tiny-dns01>

This fork additionally supports both RSA and EC keys for account keys.
It supports the ACME challenge methods HTTP-01, DNS-01 and
DNS-PERSIST-01.  The script currently has < 500 lines.

## Trust Notice

**PLEASE READ THE SOURCE CODE! YOU MUST TRUST IT WITH YOUR PRIVATE
ACCOUNT KEY!**

The account private key is used by this script to represent you when
proving to ACME that you have control over the domains you want the
certificate issued.  For HTTP-01, this script also writes to the
/.well-known/acme-challenge directory locally, though it can run as an
unprivileged user owning the directory.  For DNS-01 and
DNS-PERSIST-01, this script uses the TSIG secret or the API token you
provided to update the DNS TXT record.

## Donate

If this script is useful to you, please donate to the EFF. I don't work there,
but they do fantastic work.

[https://eff.org/donate/](https://eff.org/donate/)

## How to use this script

If you already have a Let's Encrypt issued certificate and just want to renew,
you should only have to do Steps 3 and 6.

### Step 1: Create a Let's Encrypt account private key (if you haven't already)

You can create any number of account keys to issue new or renew
existing Let's Encrypt certificates.  The account key proves to ACME
that you have control over the domain during the ACME challenge domain
validation.  It is not needed to keep the certificate valid, though
you must save it for certificate revocation.

This script supports EC (recommended) and RSA (deprecated) account
keys.  Choose one of the following commands to create the account key:

* EC P-256: `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out account.pem`
* EC P-384: `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out account.pem`
* EC P-521: `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 -out account.pem`
* RSA 4096: `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out account.pem`

Registration for a newly created account key is handled by the script.

#### Do not use an existing JWK

As mentioned above, Let's Encrypt allows you to use multiple account
keys to renew an existing certificate, so it makes no sense to use an
existing JWK key from e.g. certbot.

### Step 2: Create a certificate signing request (CSR) for your domains.

The ACME protocol (what Let's Encrypt uses) requires a CSR file to be
submitted to it, even for renewals. You can use the same CSR for
multiple renewals. NOTE: you can't use your account private key as
your domain private key!

This script does not need the server private key, but needs the CSR to
already be created using one, possibly by a separate user on a
different machine.  Assuming the server key has already been created
by one of the following commands:

* EC P-256: `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out server.pem`
* EC P-384: `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out server.pem`
* EC P-521: `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 -out server.pem`
* RSA 4096: `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out server.pem`

For a single domain:

```
openssl req -key server.pem -new -out server.csr \
  -subj '/CN=example.test'
```

For multiple domains: the `-subj` is optional, but the subject
alternative names must contain all the subject names.  Setting it to
critical is recommended.

```
openssl req -key server.pem -new -out server.csr \
  -subj '/CN=example.test' \
  -addext 'subjectAltName=critical,DNS:example.test,DNS:alice.example.test,DNS:bob.example.test'
```

For a wildcard certificate (DNS-01 and DNS-PERSIST-01 only, not
supported by HTTP-01):

```
openssl req -key server.pem -new -out server.csr \
  -subj '/CN=example.test' \
  -addext 'subjectAltName=critical,DNS:example.test,DNS:*.example.test'
```

[RFC 9525 section 6.3] restricts TLS wildcard to a single left-most level.

[RFC 9525 section 6.3]: https://www.rfc-editor.org/info/rfc9525/#section-6.3

### Step 3: Publish the challenge token

You must prove you own the domains you want a certificate for.  This
script supports several methods:

* HTTP-01: the challenge is fetched over HTTP port 80.
* DNS-01: the challenge is fetched from a DNS TXT record.
* DNS-PERSIST-01: the account ID is fetched from a DNS TXT record
  (still experimental).

#### HTTP-01

The `--method http-01` is the default and can be omitted.  This script
will generate and write the challenge files in the `--acme-dir` folder
you specify, so all you need to do is make sure that this folder is
served under the ".well-known/acme-challenge/" url path. NOTE: Let's
Encrypt will perform a plain HTTP request to port 80 on your server,
so you must serve the challenge files via HTTP.

```
# Make some challenge folder (modify to suit your needs)
mkdir -p /var/www/challenges/
```

```nginx
# Example for nginx
server {
    listen 80;
    server_name yoursite.com www.yoursite.com;

    location /.well-known/acme-challenge/ {
        alias /var/www/challenges/;
        try_files $uri =404;
    }

    ...the rest of your config
}
```

#### DNS-01

**Status: tested with Cloudflare, help wanted for testing TSIG.**

The `--method dns-01` publishes the challenge token as a DNS TXT
record using either TSIG or the Cloudflare API.

* `--dnsupdate null` is the default and does not update DNS.
* `--dnsupdate tsig` requires the `--tsig-server` and
  `--tsig-keyring-file` which should contain a JSON formatted object
  mapping from a key name to the secret or a list of `["algorithm",
  "secret"]`.
* `--dnsupdate cloudflare` requires the `--api-token-file` and
  `--zone-id`, both of which can be obtained from the dashboard.

#### DNS-PERSIST-01

**Status: experimental, tested with Staging and Pebble only.**

The `--method dns-persist-01` does not use a challenge.  Instead, you
prove ownership of the domain by publishing the account URI to the
correct DNS TXT record.  The script will add one if missing but will
not remove it after verification.  It will be the same as long as you
use the same account key.

### Step 4: Get a signed certificate!

Now that you have setup your server and generated all the needed files, run this
script on your server with the permissions needed to write to the above folder
and read your private account key and CSR.

```
# Run the script on your server
python3 acme_poly.py \
  --account-key-file account_key.pem --csr-file server.csr \
  --acme-dir /var/www/challenges --output server.crt
```

### Step 5: Install the certificate

The signed https certificate chain that is output by this script can
be used along with your private key to run an https server. You need
to include them in the https settings in your web server's
configuration. Here's an example on how to configure an nginx server:

```nginx
server {
    listen 443 ssl;
    server_name example.test, www.example.test;

    ssl_certificate /path/to/server.crt;
    ssl_certificate_key /path/to/server.pem;
    ssl_session_timeout 5m;
    ssl_protocols TLSv1.2;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_session_cache shared:SSL:50m;
    ssl_dhparam /path/to/server.dhparam;
    ssl_prefer_server_ciphers on;

    ...the rest of your config
}

server {
    listen 80;
    server_name yoursite.com www.yoursite.com;

    location /.well-known/acme-challenge/ {
        alias /var/www/challenges/;
        try_files $uri =404;
    }

    ...the rest of your config
}
```

### Step 6: Setup an auto-renew cronjob

Congrats! Your website is now using https! Unfortunately, Let's Encrypt
certificates only last for 90 days, so you need to renew them often. No worries!
It's automated! Just make a bash script and add it to your crontab (see below
for example script).

Example of a `renew_cert.sh`:

```sh
#!/usr/bin/sh
python /path/to/acme_poly.py \
  --account-key-file /path/to/account.pem \
  --csr-file /path/to/server.csr \
  --acme-dir /var/www/challenges/ \
  --output /path/to/server.crt
service nginx reload
```

And the crontab:

```
# Example line in your crontab (runs once per month)
0 0 1 * * /path/to/renew_cert.sh 2>> /var/log/acme_poly.log
```

**NOTE:** Since Let's Encrypt's ACME v2 release (acme-tiny 4.0.0+), the intermediate
certificate is included in the issued certificate download, so you no longer have
to independently download the intermediate certificate and concatenate it to your
signed certificate. If you have an shell script or Makefile using acme-tiny &lt;4.0 (e.g. before
2018-03-17) with acme-tiny 4.0.0+, then you may be adding the intermediate
certificate to your server.crt twice (which
[causes issues with at least GnuTLS 3.7.0](https://gitlab.com/gnutls/gnutls/-/issues/1131)
besides making the certificate slightly larger than it needs to be). To fix,
simply remove the bash code where you're downloading the intermediate and adding
it to the acme-tiny certificate output.

## Permissions

The biggest problem you'll likely come across while setting up and running this
script is permissions. You want to limit access to your account private key and
challenge web folder as much as possible. I'd recommend creating a user
specifically for handling this script, the account private key, and the
challenge folder. Then add the ability for that user to write to your installed
certificate file (e.g. `/path/to/server.crt`) and reload your webserver. That
way, the cron script will do its thing, overwrite your old certificate, and
reload your webserver without having permission to do anything else.

**BE SURE TO:**
* Backup your account private key (e.g. `account.pem`)
* Don't allow this script to be able to read your domain private key!
* Don't allow this script to be run as root!

## Staging Environment

Let's Encrypt recommends testing new configurations against their staging servers,
so when testing out your new setup, you can use `--instance staging`
to issue fake test certificates instead of real ones from Let's Encrypt's production servers.
See [https://letsencrypt.org/docs/staging-environment/](https://letsencrypt.org/docs/staging-environment/)
for more details.

## Feedback/Contributing

This project was forked from acme-tiny to support more features, but
this script must still stay under 500 lines of code to ensure it can
be easily audited by anyone who wants to run it.

If you want to add features for your own setup to make things easier for you,
please do! It's open source, so feel free to fork it and modify as necessary.
