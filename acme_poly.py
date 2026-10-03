#!/usr/bin/env python3
"""Polymorphed ACME script supporting various challenges with EC account keys.

The account private key is used by this script to represent you when
proving to ACME that you have control over the domains you want the
certificate issued.  For HTTP-01, this script also writes to the
/.well-known/acme-challenge directory locally, though it can run as an
unprivileged user owning the directory.  For DNS-01 and
DNS-PERSIST-01, this script uses the TSIG secret or the API token you
provided to update the DNS TXT record.

Please read through the code carefully.

Example:
  python3 acme_poly.py \\
    --account-key-file account_key.pem --csr-file server.csr \\
    --acme-dir /var/www/challenges --output server.crt
"""

__author__ = ['Likai Liu (acme-poly fork)', 'Daniel Roesler (original acme-tiny)', 'Jon DeVree (acme-dns fork)', 'Tarjei Husøy (acme-tiny-dns01 fork)']
__license__ = 'MIT'
__version__ = '0.dev0'  # In development.

import argparse, base64, binascii, contextlib, functools, hashlib, json, logging, os, re, ssl, subprocess, sys, time, urllib.parse as up, urllib.request as ur

instances = {
  'production': 'https://acme-v02.api.letsencrypt.org/directory',
  'staging': 'https://acme-staging-v02.api.letsencrypt.org/directory',
  'pebble': 'https://0.0.0.0:14000/dir',
}

def flags_parser():
  ba = argparse.BooleanOptionalAction
  class Formatter(argparse.RawDescriptionHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
    pass
  p = argparse.ArgumentParser(description=__doc__, formatter_class=Formatter)
  p.add_argument('--verbose', '-v', action=ba, default=False, help='log will show debugging messages')
  p.add_argument('--quiet', '-q', action=ba, default=False, help='console log will show only warnings and errors')
  p.add_argument('--log-file', metavar='FILE', help='additionally log to file')
  p.add_argument('--insecure', action=ba, default=False, help='supress TLS certificate verification, useful for testing against a local ACME server')
  p.add_argument('--check', action=ba, default=True, help='check that ACME challenge is publicly accessible before polling the ACME server')
  p.add_argument('--method', '-m', type=str.lower, choices=('http-01', 'dns-01', 'dns-persist-01'), default='http-01', help='select the ACME challenge method')
  p.add_argument('--instance', type=str.lower, choices=instances.keys(), default='production', help='select the Let\'s Encrypt CA instance')
  p.add_argument('--ca-dir', type=str, metavar='DIR', help='specify the ACME directory URL for the CA in lieu of --instance')
  p.add_argument('--profile', type=str, metavar='PROFILE', help='specify the ACME profile for the new order; see https://letsencrypt.org/docs/profiles/')
  p.add_argument('--account-key-file', type=str, required=True, metavar='FILE', help='specify the account private key in OpenSSL format')
  p.add_argument('--csr-file', type=str, required=True, metavar='FILE', help='specify the certificate signing request in OpenSSL format')
  p.add_argument('--contact', type=str, help='if set, update the account contact email')
  p.add_argument('--acme-dir', type=str, metavar='DIR', help='specify the local well-known directory for writing the ACME challenge')
  p.add_argument('--dnsupdate', type=str.lower, choices=('null', 'tsig', 'cloudflare'), default='null', help='specify the DNS update method for DNS based ACME challenges')
  p.add_argument('--tsig-server', type=str, metavar='SERVER', help='specify the DNS server for --dnsupdate tsig')
  p.add_argument('--tsig-keyring-file', type=str, metavar='FILE', help='specify the JSON keyring file for --dnsupdate tsig; the JSON is an object {"keyname": "secret", or "keyname": ["algorithm", "secret"]}')
  p.add_argument('--api-token-file', type=str, metavar='FILE', help='specify the API token for --dnsupdate cloudflare')
  p.add_argument('--zone-id', type=str, metavar='ID', help='specify the DNS zone ID for --dnsupdate cloudflare')
  p.add_argument('--cloudflare-api', type=str, metavar='URL', default='https://api.cloudflare.com', help='specify the API endpoint for --dnsupdate cloudflare')
  p.add_argument('--output', '-o', type=str, help='specify the output file for writing the TLS certificate')
  return p

log = logging.getLogger(__name__)
ssl_ctx = ssl.create_default_context()

class Error(Exception):
  pass

@contextlib.contextmanager
def add_error(reason):
  try:
    yield
  except Exception as e:
    raise Error(reason) from e

class Piping:
  __ror__ = __call__ = lambda self, value: self.func(value)
  def __init__(self, func):
    self.func = func

_cmd = subprocess.check_output
_atob = Piping(lambda a: a.encode('ascii'))
_btoa = Piping(lambda b: b.decode('ascii'))
_hextob = Piping(lambda s: binascii.unhexlify(re.sub(r'[\s:]', '', s)))
_b64 = Piping(lambda b: base64.urlsafe_b64encode(b).rstrip(b'=') | _btoa)
_jsons = Piping(lambda obj: json.dumps(obj, separators=(',', ':'), sort_keys=True))
_sha256 = Piping(lambda b: hashlib.sha256(b).digest())

def jwk_from_pem(pempath):
  outs = _cmd(['openssl', 'pkey', '-in', pempath, '-text', '-noout']) | _btoa
  kv = dict(re.findall(r'^([^:]+):\s*(.*(?:\r?\n[\t ]+.*)*)', outs, re.MULTILINE))
  if 'ASN1 OID' in kv:
    b = _hextob(kv['pub'])[1:]
    ksz = lambda n: {528: 512}.get(n, n)
    alg = f"ES{ksz(len(b)*4)}{'K' if 'k1' in kv['ASN1 OID'] else ''}"
    return alg, {'kty': 'EC', 'crv': kv.get('NIST CURVE', kv['ASN1 OID']), 'x': _b64(b[:len(b)//2]), 'y': _b64(b[len(b)//2:])}
  if 'publicExponent' in kv:
    e = int(kv['publicExponent'].split(' ', 1)[0])
    return 'RS256', {'kty': 'RSA', 'n': kv['modulus'] | _hextob | _b64, 'e': e.to_bytes(3, byteorder='big') | _b64}
  raise Error('unknown PEM key type: must be either EC (preferred) or RSA (deprecated)')

def domains_from_csr(csrpath):
  outs = _cmd(['openssl', 'req', '-in', csrpath, '-text', '-noout']) | _btoa
  cn = re.search(r'(?:CN=)((?:\*\.)?[-.\w]+)', outs)
  cn = cn and cn.group(1)
  sans = re.findall(r'(?:DNS:)((?:\*\.)?[-.\w]+)', outs)
  if cn and sans and cn not in sans:
    raise Error(f'bad CSR: subject {cn} must also appear in the Subject Alternative Names: {sans!r}')
  return sans or ([cn] if cn else [])

def p1363_from_der(der, n):
  outs = _cmd(['openssl', 'asn1parse', '-inform', 'der'], input=der) | _btoa
  prims = re.findall(r'prim: INTEGER\s+:(\w+)$', outs, re.MULTILINE)
  log.debug(f'Parsed primitives: {prims!r}')
  return b''.join(int(prim, 16).to_bytes(n, byteorder='big') for prim in prims)

def urlopen_read(url, data=None, method=None, headers=None):
  headers = dict(headers) if headers else {}
  headers.setdefault('User-Agent', 'acme_poly.py')
  try:
    resp = ur.urlopen(ur.Request(url, data=data, method=method, headers=headers), context=ssl_ctx)
  except ur.HTTPError as e:
    resp = e
  with contextlib.closing(resp):
    resp.data = resp.read()
  return resp  # resp.data, resp.status, resp.headers

def urlopen_json(url, request=None, method=None, headers=None):
  log.debug(f'>> urlopen_json: {method or "*"} {url}\n>> request: {request!r}')
  headers = dict(headers) if headers else {}
  headers.setdefault('Content-Type', 'application/json')
  resp = urlopen_read(url, data=None if request is None else request | _jsons | _atob, method=method, headers=headers)
  resp.json = {}
  with contextlib.suppress(ValueError):
    resp.json = json.loads(_btoa(resp.data))
  log.debug(f'<< response {resp.status}: {resp.json!r}')
  return resp  # resp.json, resp.status, resp.headers

TOS = {'termsOfServiceAgreed': True}

def acme_request_certificate(flags, challenge_context):
  log.info('Parsing account key and CSR...')
  alg, jwk = jwk_from_pem(flags.account_key_file)
  domains = domains_from_csr(flags.csr_file)
  log.info(f'Requesting a certificate for domains: {domains!r}')

  log.info('Getting directory...')
  directory = urlopen_json(flags.ca_dir).json
  if flags.profile and flags.profile not in directory['meta']['profiles']:
    raise Error(f'--profile {flags.profile} is not supported by the server; valid profiles: {directory["meta"]["profiles"]}')

  kid = {'jwk': jwk}

  def signed_urlopen_noretry(url, request=None):
    payload64 = '' if request is None else request | _jsons | _atob | _b64
    new_nonce = urlopen_json(directory['newNonce']).getheader('Replay-Nonce')
    log.debug(f'new_nonce: {new_nonce}')
    protected = kid | {'url': url, 'alg': alg, 'nonce': new_nonce}
    protected64 = protected | _jsons | _atob | _b64
    digest_input = (protected64 + '.' + payload64) | _atob
    out = _cmd(['openssl', 'dgst', '-sha' + alg[2:], '-sign', flags.account_key_file], input=digest_input)
    if jwk['kty'] == 'EC':
      out = p1363_from_der(out, len(jwk['x']) * 3 // 4)  # jwk['x'] is in b64
    request = {'protected': protected64, 'payload': payload64, 'signature': _b64(out)}
    return urlopen_json(url, request, headers={'Content-Type': 'application/jose+json'})

  def signed_urlopen_json(url, request=None, status=(200, 201)):
    log.debug(f'>> signed_urlopen_json: {url}\n>> request: {request!r}')
    for _ in range(20):
      resp = signed_urlopen_noretry(url, request)
      if resp.status == 400 and resp.json.get('type') == 'urn:ietf:params:acme:error:badNonce':
        delay = 1
      elif resp.status == 503 and resp.json.get('type') == 'urn:ietf:params:acme:error:rateLimited':
        delay = 10
      else:
        break
      log.warning(f'Retrying in {delay} secs: {resp.json["detail"]}')
      time.sleep(delay)

    if resp.status not in status:
      if 'detail' in resp.json:
        raise Error(f'server error {resp.json.get("type", "unknown")}: {resp.json["detail"]}')
      raise RuntimeError(f'unexpected status {resp.status}, want one of {status!r}')
    return resp

  def poll_while(url, status=('pending',), deadline=None):
    deadline = deadline or time.time() + 300
    while time.time() < deadline:
      resp = signed_urlopen_json(url)
      got = resp.json.get('status')
      if got not in status:
        return resp
      log.warning(f'Still {got!r}, polling until it changes...')
      time.sleep(3)
    raise Error('polling timeout')

  log.info('Registering account...')

  new_account = signed_urlopen_json(directory['newAccount'], TOS | ({'contact': flags.contact} if flags.contact else {}), status=(200, 201))
  accounturi = new_account.getheader('Location')
  kid = {'kid': accounturi}
  args = argparse.Namespace(thumbprint=jwk | _jsons | _atob | _sha256 | _b64, accounturi=accounturi, caa_identity=directory['meta']['caaIdentities'][0])
  how = 'Created account' if new_account.status == 201 else 'Existing account'
  log.info(f'{how}: {accounturi}')

  log.info('Creating new order...')
  # See: https://datatracker.ietf.org/doc/draft-ietf-acme-profiles/
  order = signed_urlopen_json(directory['newOrder'], {'identifiers': [{'type': 'dns', 'value': d} for d in domains]} | ({'profile': flags.profile} if flags.profile else {}))
  log.info('Order created!')

  with contextlib.ExitStack() as stack:
    for auth_url in order.json.get('authorizations', ()):
      with add_error(f'fetching authorization: {auth_url}'):
        authorization = signed_urlopen_json(auth_url).json
      domain = authorization['identifier']['value']
      if authorization['status'] == 'valid':
        log.info(f'Already verified: {domain}, skipping...')
        continue

      log.info(f'Verifying {domain}...')

      challenge = stack.enter_context(challenge_context(authorization, args))
      with add_error(f'waiting for {domain} challenge {challenge["type"]}'):
        signed_urlopen_json(challenge['url'], {})
        authorization = poll_while(auth_url).json
        if authorization['status'] != 'valid':
          raise Error(f'bad authorization status: {authorization["status"]}: {authorization["challenges"][0]["error"]["detail"]}')

      log.info(f'Verified {domain}!')

  log.info('Signing certificate...')
  csr_der = _cmd(['openssl', 'req', '-in', flags.csr_file, '-outform', 'DER'])
  with add_error('finalizing order'):
    signed_urlopen_json(order.json['finalize'], {"csr": _b64(csr_der)})
  with add_error('checking order status'):
    order_resp = poll_while(order.getheader('Location'), status=('pending', 'processing'))
  if order_resp.json['status'] != 'valid':
    raise Error('order failed')
  with add_error('downloading certificate'):
    certificate_resp = signed_urlopen_json(order_resp.json['certificate'])
  log.info('Certificate signed!')
  return certificate_resp.data

def challenge_http_01(flags):
  if not flags.acme_dir:
    raise Error('missing --acme-dir DIR for --method http-01')

  @contextlib.contextmanager
  def context(authorization, args):
    challenge = [c for c in authorization['challenges'] if c['type'] == "http-01"][0]
    domain, token = authorization['identifier']['value'], challenge['token']
    if '*' in domain:
      raise Error('http-01 challenge does not support wildcard: {domain}')
    content = token + '.' + args.thumbprint
    wellknown_path = os.path.join(flags.acme_dir, token)
    with open(wellknown_path, "w", encoding='ascii') as wellknown_file:
      log.debug(f'Writing {wellknown_path}: {content}')
      wellknown_file.write(content)

    wellknown_url = f'http://{domain}/.well-known/acme-challenge/{token}'
    if flags.check:
      resp_data = urlopen_read(wellknown_url).data
      if resp_data != content:
        raise Error(f'unexpected challenge at {wellknown_url}: got {resp_data}, want {content}')

    try:
      yield challenge
    finally:
      os.remove(wellknown_path)

  return context

try:
  import dns.exception, dns.query, dns.resolver, dns.tsigkeyring, dns.update
except ImportError:
  dns = None

txts_repr = Piping(lambda txts: ' '.join(json.dumps(txt) for txt in txts))
rdata_repr = Piping(lambda rdata: ' '.join(json.dumps(b | _btoa) for b in rdata.strings))

def dnsupdate_null(flags):
  del flags  # unused

  def update_or_delete(name, txts=None):
    if txts:
      log.warning(f'Please update DNS manually: {name}. 60 IN TXT {txts | txts_repr}')
      time.sleep(5)

  return update_or_delete

def dnsupdate_tsig(flags):
  for name in 'tsig_server', 'tsig_keyring_file':
    if not getattr(flags, name):
      raise Error(f'missing --{name.replace("_", "-")} for --dnsupdate tsig')

  with open(flags.tsig_keyring_file, encoding='ascii') as f:
    keyring = dns.tsigkeyring.from_text(json.load(f))

  def update_or_delete(name, txts=None):
    update = dns.update.Update(name, keyring=keyring)
    if txts:
      update.replace(name + '.', 60, 'TXT', *txts)
    else:
      update.delete(name + '.', 'TXT')
    response = dns.query.tcp(update, flags.tsig_server, timeout=10)
    if response.rcode() != 0:
      raise Error(f'DNS zone update failed: {response!r}')
    return name

  return update_or_delete

def dnsupdate_cloudflare(flags):
  for name in 'api_token_file', 'zone_id':
    if not getattr(flags, name):
      raise Error(f'missing --{name.replace("_", "-")} for --dnsupdate cloudflare')

  with open(flags.api_token_file, encoding='ascii') as f:
    api_token = f.readline().strip()

  def call(method, rel, req=None):
    resp = urlopen_json(up.urljoin(flags.cloudflare_api, rel), req, headers={'Authorization': f'Bearer {api_token}'}, method=method)
    if resp.json.get('messages'):
      log.info(f'Cloudflare: {resp.json["messages"]!r}')
    if resp.json.get('errors'):
      log.error(f'Cloudflare: {resp.json["errors"]!r}')
    if resp.status != 200 or not resp.json.get('success'):
      raise Error('Cloudflare request failed')
    return resp

  def update_or_delete(name_or_id, txts=None):
    if txts:  # update and name_or_id is name
      resp = call('POST', f'/client/v4/zones/{flags.zone_id}/dns_records', {'name': name_or_id, 'ttl': 60, 'type': 'TXT', 'content': txts_repr(txts)})
      return resp.json['result']['id']  # returns id
    else:  # delete and name_or_id is id
      resp = call('DELETE', f'/client/v4/zones/{flags.zone_id}/dns_records/{name_or_id}')
      return None

  return update_or_delete

@functools.cache
def lookup_addrs(domain):
  return set((
    str(addr)
    for af in ('A', 'AAAA')
    for addr in dns.resolver.resolve(domain, af, raise_on_no_answer=False) ))

@functools.cache
def nameserver_addrs(domain):
  return set((
    (str(ns), addr)
    for ns in dns.resolver.resolve(dns.resolver.zone_for_name(domain), 'NS')
    for addr in lookup_addrs(str(ns)) ))

def wait_nsaddrs(nsaddrs, name, txts, quick=False):
  txtrec = txts_repr(txts)

  def poll(ns, addr):
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [addr]
    deadline = time.time() + 300
    while time.time() < deadline:
      logged = Piping(lambda rec: log.debug(f'{ns} {addr} has {name} TXT {rec}') or rec)
      recs = [rdata | rdata_repr | logged for rdata in r.resolve(name, 'TXT')]
      if any(txtrec == rec for rec in recs):
        return True
      if quick:
        return False
      log.warning(f'Stale record from {ns} at {addr}, want: {txtrec}')
      time.sleep(15)
    return False

  for ns, addr in nsaddrs:
    with contextlib.suppress(dns.exception.DNSException):
      if poll(ns, addr):
        if quick:
          return True
        continue
    log.error(f'Nameserver {ns} at {addr} has not updated {name} before deadline')

GLOBAL_RESOLVERS = {('one.one.one.one', '1.1.1.1'), ('dns.google', '8.8.8.8'), ('dns9.quad9.net', '9.9.9.9')}

def challenge_dns_01_or_dns_persist_01(flags):
  assert flags.method in ('dns-01', 'dns-persist-01')
  update_or_delete = None
  if flags.dnsupdate == 'tsig' or flags.tsig_server:
    update_or_delete = dnsupdate_tsig(flags)
  elif flags.dnsupdate == 'cloudflare':
    update_or_delete = dnsupdate_cloudflare(flags)
  elif flags.dnsupdate == 'null':
    update_or_delete = dnsupdate_null(flags)

  @contextlib.contextmanager
  def context(authorization, args):
    domain = authorization['identifier']['value']
    challenge = [c for c in authorization['challenges'] if c['type'] == flags.method][0]
    if flags.method == 'dns-01':
      name, token = f'_acme-challenge.{domain}', challenge['token']
      log.debug(f'token: {token}, thumbprint: {args.thumbprint}')
      txts = [(token + '.' + args.thumbprint) | _atob | _sha256 | _b64]
    elif flags.method == 'dns-persist-01':
      # See: https://letsencrypt.org/2026/02/18/dns-persist-01
      name, wildcard = f'_validation-persist.{domain}', authorization.get('wildcard', False)
      txts = [f'{args.caa_identity};', f' accounturi={args.accounturi};'] + ([' policy=wildcard;'] if wildcard else [])
      txts[-1] = txts[-1].rstrip(';')  # no trailing semicolon.

    nsaddrs = nameserver_addrs(name)
    if flags.method != 'dns-persist-01' or not flags.check or not wait_nsaddrs(nsaddrs, name, txts, quick=True):
      log.info(f'Updating DNS record: {name}. 60 IN TXT {txts | txts_repr}')
      record_id = update_or_delete(name, txts)
    if flags.check:
      wait_nsaddrs(nsaddrs, name, txts)
      wait_nsaddrs(GLOBAL_RESOLVERS, name, txts)

    try:
      yield challenge
    finally:
      if flags.method != 'dns-persist-01':
        update_or_delete(record_id)

  return context

def main():
  flags = flags_parser().parse_args()
  log.setLevel(logging.DEBUG if flags.verbose else logging.INFO)  # entry gate
  handler = logging.StreamHandler()
  handler.setLevel(logging.WARN if flags.quiet else logging.DEBUG)
  log.addHandler(handler)
  if flags.log_file:
    handler = logging.FileHandler(flags.log_file, mode="a", encoding="utf-8")
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter(fmt='%(asctime)s.%(msecs)03d %(levelname).1s: %(message)s', datefmt='%m%d %H:%M:%S'))
    log.addHandler(handler)
  if flags.insecure:
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
  if not flags.ca_dir:
    flags.ca_dir = instances[flags.instance]
  if 'dns-' in flags.method and not dns:
    raise Error(f'method {flags.method} requires dnspython: python3 -m pip -q install --upgrade dnspython')
  challenge_context = None
  if flags.method == 'http-01':
    challenge_context = challenge_http_01(flags)
  elif flags.method in ('dns-01', 'dns-persist-01'):
    challenge_context = challenge_dns_01_or_dns_persist_01(flags)
  else:
    raise Error(f'unknown --method {flags.method}')
  cert_data = acme_request_certificate(flags, challenge_context)
  if flags.output:
    with open(flags.output, 'w') as out:
      out.write(cert_data | _btoa)
  else:
    sys.stdout.write(cert_data)

if __name__ == '__main__':
  try:
    main()
  except (Error, IOError) as e:
    log.error('Error: %s', e)
    while e.__cause__:
      log.error('Cause: %s', e.__cause__)
      e = e.__cause__
    sys.exit(1)
