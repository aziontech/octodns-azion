# CHANGELOG

## Unreleased

### Fixes
* Dynamic records now converge instead of planning an update on every sync:
  weights are written as-is (octoDNS uses 1-100, not 1-15), the pool and
  status are read the way octoDNS expects, and pool values/`values` are
  normalized during planning
* Azion weight 0 (record kept but never answered) is read as `status: down` and
  written back as weight 0 instead of reactivating the record with weight 17
* Geo/subnet rules, multiple pools and fallbacks are no longer silently dropped,
  they raise `SupportsException` (or fall back to the catch-all pool with
  `strict_supports: false`)
* Weighted MX and ANAME records no longer break `populate()` for the whole zone,
  they are read as simple records with a warning. `SUPPORTS_DYNAMIC_TYPES` is
  now A, AAAA and CNAME, the only types octoDNS can make dynamic
* A single weighted record no longer fails strict validation
  (`pool has single value with weight!=1`), and weighted records without a
  weight use the Azion default instead of raising `TypeError`
* Updates reuse the existing API records in place and leave unchanged values
  alone, instead of deleting every record before recreating them
* Values that answer are written before others are turned down or deleted, so
  a name keeps answering if an update fails part way through
* Legacy data with several simple records for a name/type can be converted to
  weighted records, and is no longer read as a dynamic record
* Updates always send `policy`, which the API otherwise resets to `simple`
* Multiple API records for the same name/type are merged instead of reading
  only the first one, and consolidated when updated
* Record names and zone domains are compared case-insensitively
* A 404 while listing the records of an existing zone is raised instead of
  being treated as a missing zone
* The id of a newly created zone is used instead of listing zones again
* Caches are cleared even when an apply fails part way through
* Configured descriptions take precedence over stored ones
* Planning compares the API records themselves, so changes octoDNS can't see
  are planned too: descriptions of weighted records, the traffic split of
  weights above 100, per-record TTLs, weighted records answering several
  values together and duplicate records
* Azion weights above 100 are scaled down keeping their proportions instead of
  being clamped to 100
* Records the Azion API rejects fail while planning with
  `AzionUnsupportedRecord`, instead of part way through an apply: null MX,
  more than 10 values, TTLs below 1, TXT values with newlines or tabs or
  longer than 1000 characters in total, AAAA addresses ending in `::`, CAA
  flags other than 0/128 or unsupported characters, ANAME targets outside
  azioncdn.net, azionedge.net and azionedge.com, and descriptions longer than
  45 characters
* ALIAS records with a TTL other than 20, which Azion requires for ANAME
  records, raise `SupportsException` (or use 20 with `strict_supports: false`)
* ANAME records outside the zone root, which octoDNS ALIAS records can't
  represent, are skipped with a warning instead of breaking `populate()` or
  being planned for deletion
* TXT answers stored with quotes are read with escaped quotes. They were
  parsed as octoDNS chunks, so a stored `"foo" "bar"` matched `foobar`
* `;` after an escaped backslash in a stored TXT answer is escaped
* Zones created for domains longer than 50 characters get a name the API
  accepts

### Added
* `timeout` (default 30s) for API requests and `max_retries` (default 5) for
  rate limited (HTTP 429) requests, honoring `Retry-After` and
  `X-RateLimit-Reset`; `AzionClientRateLimited` is raised when retries run out
* End-to-end plan/apply/plan tests against a stateful fake of the v3 API

## v1.2.0 - 2026-06-08

### Changed
* Updated runtime dependencies to current stable releases, including `octodns==1.19.0`, `requests==2.34.2`, and `urllib3==2.7.0`
* Updated development tooling to current stable releases, including `black==26.5.1`, `pytest==9.0.3`, and `isort==8.0.1`
* Raised the supported Python baseline to Python 3.10 or newer so patched dependency versions can be used
* Updated GitHub Actions artifact actions and aligned publish/security workflows with Python 3.14

### Security
* Resolved known dependency vulnerabilities reported by `pip-audit`

## v1.1.0 - 2025-12-08

### Features
* **Dynamic Records**: Added full support for weighted/dynamic DNS records (`SUPPORTS_DYNAMIC = True`)
  - Supported types: A, AAAA, ALIAS, CNAME, MX
  - Weight normalization between Azion (0-255) and octoDNS (1-15) scales
  - Automatic conversion between multiple API records and single octoDNS dynamic record
* **Custom Descriptions**: Added support for `octodns.azion.description` and `octodns.azion.descriptions` in YAML
* **New Exceptions**: Added `AzionClientForbidden` (403) and `AzionClientBadRequest` (400) with detailed error info
* **Improved Logging**: Better error messages with request data for debugging

### Fixes
* Fixed TXT record handling - removed incorrect double-quoting of values
* Fixed NS record values - strip trailing dots to match Azion API requirements
* Fixed CAA record updates to use array format
* Fixed multiple values consolidation into single record payload for updates
* Changed record updates to use `record_update` instead of delete/create pattern
* Fixed bare `except` clause to use `except ValueError`

### Internal
* Simplified code for handling multiple record values
* Added comprehensive test coverage (136 tests, 100% coverage)
* Added tests for all dynamic record scenarios
* Updated mock responses to match actual API structure (`id` vs `record_id`)

## v1.0.1 - 2025-07-06

* **BREAKING**: Fixed PTR record support by implementing missing `_params_for_PTR` method
* **BREAKING**: Fixed DNS record name handling to avoid domain duplication (e.g., `test.example.com.example.com`)
* **BREAKING**: Fixed zone creation API calls to use correct field names (`domain` + `name` instead of just `name`)
* Added support for NS records with proper FQDN handling
* Added `requests` as explicit dependency in setup.py
* Fixed record name handling: root records now use `@` in API calls, regular records use only the record name without zone suffix
* Removed unused zone management methods (`zone`, `zone_delete`) that are not used by octoDNS core
* Updated tests to reflect new record name handling behavior
* Change API pagination with smaller page sizes (100 instead of 200)

## v1.0.0 - 2025-07-05 - First version

* Initial version of AzionProvider
