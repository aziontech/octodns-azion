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
octodns==1.12.0
octodns-azion==1.0.1
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
```

## Support Information

### Records

AzionProvider supports A, AAAA, ALIAS (ANAME), CAA, CNAME, MX, NS, PTR, TXT, and SRV record types.

### Root NS Records

AzionProvider does not support root NS record management.

### Dynamic

AzionProvider does not support dynamic records.

### Development

See the [/script/](/script/) directory for some tools to help with the development process. They generally follow the [Script to rule them all](https://github.com/github/scripts-to-rule-them-all) pattern. Most useful is `./script/bootstrap` which will create a venv and install both the runtime and development related requirements. It will also hook up a pre-commit hook that covers most of what's run by CI.