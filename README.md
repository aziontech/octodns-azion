## Azion DNS provider for octoDNS

An [octoDNS](https://github.com/octodns/octodns/) provider that targets [DNS](https://api.azion.com/).

### Installation

#### Command line

```
pip install octodns-azion
```

#### requirements.txt/setup.py

Pinning specific versions or SHAs is recommended to avoid unplanned upgrades.

##### Versions

```
# Start with the latest versions and don't just copy what's here
octodns==1.19.0
octodns-azion==1.2.0
```

##### SHAs

```
# Start with the latest/specific versions and don't just copy what's here
-e git+https://git@github.com/octodns/octodns.git@07c72e5a2f52a87b94fecf5c18697b16832253b0#egg=octodns
-e git+https://git@github.com/aziontech/octodns-azion.git@29197e11e2f2b8783b13863986fae86ec78347a4#egg=octodns_azion
```

## Configuration

```yaml
providers:
  azion:
    class: octodns_azion.AzionProvider
    # Your Azion API token (required)
    token: env/AZION_TOKEN
    # Seconds to wait for each API request (optional, default 30)
    timeout: 30
    # Retries for rate limited (HTTP 429) requests, honoring the
    # Retry-After/X-RateLimit-Reset headers (optional, default 5)
    max_retries: 5
```

AzionProvider uses the Azion API v3 (`https://api.azionapi.net/intelligent_dns`).
The v3 API is deprecated and accounts created or migrated to API v4 can't
access it.

## Support Information

### Records

AzionProvider supports A, AAAA, ALIAS (ANAME), CAA, CNAME, MX, NS, PTR, TXT, and SRV record types.

AzionProvider manages one octoDNS record per name/type. If Azion holds several
records for the same name and type their values are merged, and they are
consolidated into a single record when octoDNS updates it.

ALIAS records map to Azion ANAME records. octoDNS ALIAS records hold a single
value, so for ANAME records with several values only the first one is managed
and a warning is logged. Azion requires ANAME records to use a TTL of 20 and to
point to azioncdn.net, azionedge.net or azionedge.com. ANAME records outside
the zone root can't be represented as ALIAS records, they are skipped with a
warning and left alone.

Records the Azion API would reject fail while planning with
`AzionUnsupportedRecord`, before any change is applied:

* null MX records (`0 .`);
* more than 10 values in A, AAAA, MX and NS records;
* TTLs below 1;
* TXT values with newlines or tabs, or longer than 1000 characters in total;
* AAAA addresses ending in `::`;
* CAA flags other than 0 and 128, or values with characters other than
  letters, digits, `_ ; = @ : . - /` and whitespace;
* descriptions longer than 45 characters.

TXT values stored with quotes (e.g. through the Azion console) are read with
escaped quotes (`\"`), because Azion serves the quotes as part of the value.

### Root NS Records

AzionProvider does not support root NS record management.

### Dynamic

AzionProvider supports dynamic A, AAAA and CNAME records as Azion weighted
records, one Azion record per pool value:

```yaml
lb:
  type: A
  ttl: 300
  values:
    - 1.1.1.1
    - 2.2.2.2
  dynamic:
    pools:
      weighted:
        values:
          - value: 1.1.1.1
            weight: 10
          - value: 2.2.2.2
            weight: 5
            # down values are kept with Azion weight 0, never answered
            status: down
    rules:
      - pool: weighted
  octodns:
    azion:
      # optional, per value descriptions of up to 45 characters
      descriptions:
        1.1.1.1: primary
```

* Weights are written as-is, octoDNS weights (1-100) fit Azion's range
  (0-255). Azion weights above 100 are scaled down keeping their proportions,
  and planning compares the traffic split, so 200/100 matches 100/50.
* `status: down` maps to Azion weight 0. Azion has no health checks, so `up`
  is treated as `obey`.
* Only a single pool with a single catch-all rule is supported. Geo or subnet
  rules, multiple pools and fallbacks raise an error, or with
  `strict_supports: false` only the pool of the catch-all rule is used.
* Azion answers exclusively from the pool, so the record `values` are set to
  the pool values.
* An Azion weighted record holding several values answers them together.
  octoDNS reads them as independent values, a warning is logged and the
  record is split into one record per value.
* Values that answer are written before others are turned down or deleted,
  so the name keeps answering if an update fails part way through.

Azion also supports weighted MX and ANAME records, which octoDNS can't express.
They are read as simple records with a warning, and their weights are dropped
if octoDNS updates them.

### Descriptions

`octodns.azion.description` sets the description of simple records, but the
Azion API v3 currently stores simple records with an empty description.
Descriptions of weighted records are set per value with
`octodns.azion.descriptions` and changes to them are planned and applied.

### Development

Python 3.10 or newer is required.

See the [/script/](/script/) directory for some tools to help with the development process. They generally follow the [Script to rule them all](https://github.com/github/scripts-to-rule-them-all) pattern. Most useful is `./script/bootstrap` which will create a venv and install both the runtime and development related requirements. It will also hook up a pre-commit hook that covers most of what's run by CI.
