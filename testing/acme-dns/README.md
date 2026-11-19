# README

ACME DNS registrations `*.json` files are populated here by the
`Makefile`, but the DNS delegations still need to be configured
manually before the tests can pass.

  * First, create an NS record from `acme.example.com` to the A or
    AAAA record of the ACME DNS server.
  * For each `*.json` registered by the `Makefile`, manually create a
    `CNAME` from `_acme-challenge.foo.example.com` to
    `<subdomain>.acme.example.com`.  The `<subdomain>` should come
    from the "subdomain" field in the JSON.

## Debugging

Make sure the API is reachable:

```
curl --json '{}' "${ACMEDNS_API}"/register
```

Make sure the DNS server is reachable:

```
dig -t txt <subdomain>.acme.example.com
```

Make sure the CNAME is configured correctly:

```
dig -t txt _acme-challenge.foo.example.com
```

If the ACME DNS server is locally hosted via WAN port forwarding, also
test the local port:

```
dig @localhost -p 5300 -t txt <subdomain>.acme.example.com
```
