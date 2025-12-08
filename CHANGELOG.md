# CHANGELOG

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
