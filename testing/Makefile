.PHONY: all clean distclean

all:: all-keys pebble_http_01 pebble_dns_01 pebble_dns_persist_01
clean::
	rm -f *.csr *.crt *.log
distclean:: clean
	rm -f *.pem

SUPPORTED_KEYTYPES := rsa4096 p256 p384 p521
TODO_KEYTYPES :=
ALL_KEYTYPES := $(SUPPORTED_KEYTYPES) $(TODO_KEYTYPES)

define DEFAULT_CONFIG_MK
CLOUDFLARE_CSR_SUBJECT = $$(error config.mk: missing CLOUDFLARE_CSR_SUBJECT)
CLOUDFLARE_CSR_SAN = $$(error config.mk: missing CLOUDFLARE_CSR_SAN)
CLOUDFLARE_ZONE_ID = $$(error config.mk: missing CLOUDFLARE_ZONE_ID)

ACMEDNS_CSR_SUBJECT = $$(error config.mk: missing ACMEDNS_CSR_SUBJECT)
ACMEDNS_CSR_SAN = $$(error config.mk: missing ACMEDNS_CSR_SAN)
ACMEDNS_DIR = $$(error config.mk: missing ACMEDNS_DIR)
ACMEDNS_API = $$(error config.mk: missing ACMEDNS_API)
endef

export DEFAULT_CONFIG_MK
config.mk:
	echo "$${DEFAULT_CONFIG_MK}" > $@

-include config.mk

.PHONY: all-keys server-keys account-keys
all-keys:: server-keys account-keys
server-keys:: $(patsubst %,server.%.pem,$(ALL_KEYTYPES))
account-keys:: $(patsubst %,account.%.pem,$(ALL_KEYTYPES))

.PHONY: acme_tiny_debug
acme_tiny_debug:: acme_tiny_debug.rsa4096.crt

.PHONY: pebble_http_01
pebble_http_01:: $(patsubst %,pebble_http_01.%.crt,$(SUPPORTED_KEYTYPES))

.PHONY: pebble_dns_01
pebble_dns_01:: $(patsubst %,pebble_dns_01.%.crt,$(SUPPORTED_KEYTYPES))

.PHONY: pebble_dns_persist_01
pebble_dns_persist_01:: $(patsubst %,pebble_dns_persist_01.%.crt,$(SUPPORTED_KEYTYPES))

.PHONY: cloudflare_pebble cloudflare_staging
cloudflare_pebble:: cloudflare_pebble_dns_01.p256.crt cloudflare_pebble_dns_persist_01.p384.crt
cloudflare_staging:: cloudflare_staging_dns_01.p256.crt cloudflare_staging_dns_persist_01.p384.crt

.PHONY: acmedns_pebble acmedns_staging
acmedns_pebble:: acmedns_pebble_dns_01.p256.crt acmedns_pebble_dns_persist_01.p384.crt
acmedns_staging:: acmedns_staging_dns_01.p256.crt acmedns_staging_dns_persist_01.p384.crt

%.p256.pem:
	openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $@
%.p384.pem:
	openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out $@
%.p521.pem:
	openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 -out $@
%.rsa4096.pem:
	openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out $@

CSR_SUBJECT := example.test
CSR_SAN := critical,DNS:example.test,DNS:alice.example.test,DNS:bob.example.test

.PRECIOUS: %.csr
.SECONDEXPANSION:
%.csr: server$$(suffix $$*).pem
	openssl req -key $< -new -out $@ \
		-subj '/CN=$(CSR_SUBJECT)' \
		-addext 'subjectAltName=$(CSR_SAN)'

acme_tiny_debug.%.crt: server.%.csr account.%.pem
	python3 ../attic/acme_tiny_debug.py \
		--account-key account.$*.pem \
		--csr server.$*.csr \
		--acme-dir ./acme-challenge \
		--disable-check > $@ || { rm -f $@; false; }

VERBOSITY := --quiet --verbose
INSTANCE = $(error must set for $@: INSTANCE := --instance INSTANCE)
METHOD_FLAGS = $(error must set for $@: METHOD_FLAGS := --method METHOD)
UPDATE_FLAGS = $(error must set for $@: UPDATE_FLAGS := --dnsupdate UPDATER)

.SECONDEXPANSION:
%.crt %.log: %.csr account$$(suffix $$*).pem
	rm -f $*.log
	python3 ../acme_poly.py --output $*.crt \
		--log-file $*.log $(VERBOSITY) \
		--account-key-file $(filter %.pem,$^) \
		--csr-file $(filter %.csr,$^) \
		$(INSTANCE) \
		$(METHOD_FLAGS) \
		$(UPDATE_FLAGS)

pebble_%.crt: INSTANCE := --instance pebble --insecure --profile shortlived
pebble_http_01.%.crt: METHOD_FLAGS := --method http-01
pebble_http_01.%.crt: UPDATE_FLAGS := --acme-dir ./acme-challenge --no-check
pebble_dns_%.crt: CSR_SAN := critical,DNS:example.test,DNS:*.example.test
pebble_dns_%.crt: UPDATE_FLAGS := --dnsupdate null --no-check
pebble_dns_01.%.crt: METHOD_FLAGS := --method dns-01
pebble_dns_persist_01.%.crt: METHOD_FLAGS := --method dns-persist-01

cloudflare_token:
	$(error test requires a Cloudflare token in the cloudflare_token file)

cloudflare_%.crt: cloudflare_token  # TODO: wishful thinking
cloudflare_%.crt: CSR_SUBJECT := $(CLOUDFLARE_CSR_SUBJECT)
cloudflare_%.crt: CSR_SAN := $(CLOUDFLARE_CSR_SAN)
cloudflare_%.crt: UPDATE_FLAGS := --dnsupdate cloudflare --api-token-file cloudflare_token --zone-id $(CLOUDFLARE_ZONE_ID)

cloudflare_pebble_%.crt: INSTANCE := --instance pebble --insecure --profile shortlived
cloudflare_pebble_dns_01.%.crt: METHOD_FLAGS := --method dns-01
cloudflare_pebble_dns_persist_01.%.crt: METHOD_FLAGS := --method dns-persist-01

cloudflare_staging_%.crt: INSTANCE := --instance staging --profile shortlived
cloudflare_staging_dns_01.%.crt: METHOD_FLAGS := --method dns-01
cloudflare_staging_dns_persist_01.%.crt: METHOD_FLAGS := --method dns-persist-01

acmedns_%.crt: $(ACMEDNS_DIR)
acmedns_%.crt: CSR_SUBJECT := $(ACMEDNS_CSR_SUBJECT)
acmedns_%.crt: CSR_SAN := $(ACMEDNS_CSR_SAN)
acmedns_%.crt: UPDATE_FLAGS := --dnsupdate acmedns --acmedns-dir $(ACMEDNS_DIR) --acmedns-api $(ACMEDNS_API)

acmedns_pebble_%.crt: INSTANCE := --instance pebble --insecure --profile shortlived
acmedns_pebble_dns_01.%.crt: METHOD_FLAGS := --method dns-01
acmedns_pebble_dns_persist_01.%.crt: METHOD_FLAGS := --method dns-persist-01

acmedns_staging_%.crt: INSTANCE := --instance staging --profile shortlived
acmedns_staging_dns_01.%.crt: METHOD_FLAGS := --method dns-01
acmedns_staging_dns_persist_01.%.crt: METHOD_FLAGS := --method dns-persist-01

comma := ,
empty :=
space := $(empty) $(empty)

acmedns_san_spaced = $(subst $(comma),$(space),$(ACMEDNS_CSR_SAN))
acmedns_san_filtered = $(filter-out critical,$(acmedns_san_spaced))
acmedns_san_trimdns = $(patsubst DNS:%,%,$(acmedns_san_filtered))
acmedns_san_trimwild = $(patsubst *.%,%,$(acmedns_san_trimdns))
acmedns_hosts = $(sort $(ACMEDNS_CSR_SUBJECT) $(acmedns_san_trimwild))

ACMEDNS_JSON = $(addprefix $(ACMEDNS_DIR)/,$(addsuffix .json,$(acmedns_hosts)))

$(ACMEDNS_DIR):: $(ACMEDNS_JSON)

%.json:
	curl --json '{}' -o $@ $(ACMEDNS_API)/register
