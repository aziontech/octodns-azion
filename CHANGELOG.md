# CHANGELOG

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
