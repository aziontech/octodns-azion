import logging
import re
from collections import defaultdict

from requests import Session

from octodns import __VERSION__ as octodns_version
from octodns.provider import ProviderException
from octodns.provider.base import BaseProvider
from octodns.record import Record

__version__ = __VERSION__ = '1.0.4'


class AzionClientException(ProviderException):
    pass


class AzionClientNotFound(AzionClientException):
    def __init__(self, message='Not Found'):
        super().__init__(message)


class AzionClientUnauthorized(AzionClientException):
    def __init__(self, message='Unauthorized'):
        super().__init__(message)


class AzionClientForbidden(AzionClientException):
    def __init__(self, message='Forbidden'):
        super().__init__(message)


class AzionClientBadRequest(AzionClientException):
    def __init__(self, message='Bad Request', details=None, request_data=None):
        self.details = details
        self.request_data = request_data
        full_message = f'{message}: {details}' if details else message
        if request_data:
            full_message += f'. Request data: {request_data}'
        super().__init__(full_message)


class AzionClient(object):
    BASE = 'https://api.azionapi.net'

    def __init__(self, token):
        sess = Session()
        sess.headers.update(
            {
                'Authorization': f'Token {token}',
                'Accept': 'application/json; version=3',
                'Content-Type': 'application/json',
                'User-Agent': f'octodns/{octodns_version} '
                f'octodns-azion/{__VERSION__}',
            }
        )
        self._sess = sess

    def _request(self, method, path, params=None, data=None):
        url = f'{self.BASE}{path}'
        resp = self._sess.request(method, url, params=params, json=data)
        if resp.status_code == 401:
            raise AzionClientUnauthorized()
        if resp.status_code == 403:
            raise AzionClientForbidden()
        if resp.status_code == 404:
            raise AzionClientNotFound()
        if resp.status_code == 400:
            try:
                error_details = resp.json()
            except ValueError:
                error_details = resp.text
            raise AzionClientBadRequest(
                details=error_details, request_data=data
            )
        resp.raise_for_status()
        return resp

    def zones(self):
        '''Get all zones'''
        path = '/intelligent_dns'
        ret = []

        page = 1
        page_size = 100

        # Continue fetching pages until no more data or no next link
        while page:
            params = {'page': page, 'page_size': page_size}
            data = self._request('GET', path, params=params).json()

            # If no results, stop pagination
            if 'results' not in data:
                break

            ret.extend(data['results'])

            # Check if there are more pages
            if data.get('links', {}).get('next'):
                page += 1
            else:
                page = None  # Stop pagination

        return ret

    def zone_create(self, name):
        '''Create a new zone'''
        path = '/intelligent_dns'
        data = {'name': name, 'domain': name, 'is_active': True}
        return self._request('POST', path, data=data).json()

    def records(self, zone_id):
        '''Get all records for a zone'''
        path = f'/intelligent_dns/{zone_id}/records'
        ret = []

        page = 1
        page_size = 100

        # Continue fetching pages until no more data or no next link
        while page:
            params = {'page': page, 'page_size': page_size}
            data = self._request('GET', path, params=params).json()

            # If no results or no records, stop pagination
            if 'results' not in data or 'records' not in data['results']:
                break

            ret.extend(data['results']['records'])

            # Check if there are more pages
            if data.get('links', {}).get('next'):
                page += 1
            else:
                page = None  # Stop pagination

        return ret

    def record_create(self, zone_id, params):
        '''Create a new record'''
        path = f'/intelligent_dns/{zone_id}/records'
        return self._request('POST', path, data=params).json()

    def record_update(self, zone_id, record_id, params):
        '''Update an existing record'''
        path = f'/intelligent_dns/{zone_id}/records/{record_id}'
        return self._request('PUT', path, data=params).json()

    def record_delete(self, zone_id, record_id):
        '''Delete a record'''
        path = f'/intelligent_dns/{zone_id}/records/{record_id}'
        self._request('DELETE', path)


class AzionProvider(BaseProvider):
    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = True
    SUPPORTS_ROOT_NS = False
    SUPPORTS = set(
        ('A', 'AAAA', 'ALIAS', 'CAA', 'CNAME', 'MX', 'NS', 'PTR', 'TXT', 'SRV')
    )
    # Record types that support weighted policy in Azion
    # (A, AAAA, CNAME, ANAME/ALIAS, MX according to Azion docs)
    SUPPORTS_DYNAMIC_TYPES = set(('A', 'AAAA', 'ALIAS', 'CNAME', 'MX'))

    def __init__(self, id, token, *args, **kwargs):
        self.log = logging.getLogger(f'AzionProvider[{id}]')
        self.log.debug('__init__: id=%s, token=***', id)
        super().__init__(id, *args, **kwargs)
        self._client = AzionClient(token)

        self._zone_records = {}
        self._zone_cache = {}
        # Cache for raw API records (preserves weighted record info)
        # Key: zone_name -> list of raw API records with full metadata
        self._zone_raw_records = {}

    def _get_zone_id_by_name(self, zone_name):
        '''Get zone ID by zone name'''
        # Remove trailing dot for comparison
        zone_name_clean = zone_name.rstrip('.')

        if zone_name not in self._zone_cache:
            zones = self._client.zones()
            for zone in zones:
                zone_domain = zone.get('domain', zone.get('name', ''))
                if zone_domain == zone_name_clean:
                    self._zone_cache[zone_name] = zone['id']
                    break
            else:
                raise AzionClientNotFound()

        return self._zone_cache[zone_name]

    def _get_record_answers(self, records):
        """Helper to extract answers from a consolidated record."""
        record = records[0]
        return (
            record.get('answers_list', [record.get('value', '')]),
            record['ttl'],
        )

    def _ensure_trailing_dot(self, value):
        """Helper to ensure domain names have trailing dots."""
        return value if value.endswith('.') else f'{value}.'

    def _parse_structured_answer(self, answer, parts_count, parser_func):
        """Helper to parse structured DNS record answers."""
        parts = answer.split(' ', parts_count - 1)
        return parser_func(parts) if len(parts) >= parts_count else None

    def _data_for_multiple(self, _type, records):
        """Handle simple multiple value records (A, AAAA, NS)."""
        answers, ttl = self._get_record_answers(records)
        # For NS records, ensure trailing dots
        if _type == 'NS':
            answers = [self._ensure_trailing_dot(answer) for answer in answers]
        return {'ttl': ttl, 'type': _type, 'values': answers}

    _data_for_A = _data_for_multiple
    _data_for_AAAA = _data_for_multiple
    _data_for_NS = _data_for_multiple

    def _data_for_CAA(self, _type, records):
        values = []
        record = records[0]
        answers = record.get('answers_list', [record.get('value', '')])
        for answer in answers:
            # CAA format: 'flags tag value'
            parts = answer.split(' ', 2)
            if len(parts) >= 3:
                values.append(
                    {
                        'flags': int(parts[0]),
                        'tag': parts[1],
                        'value': parts[2].strip('"'),
                    }
                )
        return {'ttl': record['ttl'], 'type': _type, 'values': values}

    def _data_for_CNAME(self, _type, records):
        record = records[0]
        value = record.get('answers_list', [record.get('value', '')])[0]
        if not value.endswith('.'):
            value += '.'
        return {'ttl': record['ttl'], 'type': _type, 'value': value}

    def _data_for_ALIAS(self, _type, records):
        '''Handle ALIAS records (converted from ANAME).

        ALIAS is the octoDNS representation of Azion's ANAME record type.
        '''
        record = records[0]
        value = record.get('answers_list', [record.get('value', '')])[0]
        if not value.endswith('.'):
            value += '.'
        return {'ttl': record['ttl'], 'type': _type, 'value': value}

    def _data_for_PTR(self, _type, records):
        '''Handle PTR records (reverse DNS lookups)'''
        record = records[0]
        value = record.get('answers_list', [record.get('value', '')])[0]
        if not value.endswith('.'):
            value += '.'
        return {'ttl': record['ttl'], 'type': _type, 'value': value}

    def _data_for_MX(self, _type, records):
        values = []
        record = records[0]
        answers = record.get('answers_list', [record.get('value', '')])
        for answer in answers:
            # MX format: 'priority exchange'
            parts = answer.split(' ', 1)
            if len(parts) >= 2:
                exchange = parts[1]
                if not exchange.endswith('.'):
                    exchange += '.'
                values.append(
                    {'preference': int(parts[0]), 'exchange': exchange}
                )
        return {'ttl': record['ttl'], 'type': _type, 'values': values}

    def _data_for_SRV(self, _type, records):
        values = []
        record = records[0]
        answers = record.get('answers_list', [record.get('value', '')])
        for answer in answers:
            # SRV format: 'priority weight port target'
            parts = answer.split(' ', 3)
            if len(parts) >= 4:
                target = parts[3]
                if target != '.' and not target.endswith('.'):
                    target += '.'
                values.append(
                    {
                        'priority': int(parts[0]),
                        'weight': int(parts[1]),
                        'port': int(parts[2]),
                        'target': target,
                    }
                )
        return {'type': _type, 'ttl': record['ttl'], 'values': values}

    def _data_for_TXT(self, _type, records):
        """Handle TXT records with proper quote and semicolon handling."""
        # Get all answers from the answers_list array
        answers, ttl = self._get_record_answers(records)

        values = []
        for answer in answers:
            if answer:  # Skip empty answers
                answer = re.sub(r'(?<!\\);', r'\\;', answer)
                values.append(answer)

        return_data = {'ttl': ttl, 'type': _type, 'values': values}
        self.log.debug(f'_data_for_TXT: {return_data}')
        return return_data

    def _is_weighted_record(self, record):
        """Check if a record uses weighted policy."""
        return record.get('policy') == 'weighted'

    def zone_records(self, zone):
        """Get all records for a zone, preserving weighted record info."""
        if zone.name not in self._zone_records:
            try:
                zone_id = self._get_zone_id_by_name(zone.name)
                records = self._client.records(zone_id)

                # Store raw records for later use in apply operations
                self._zone_raw_records[zone.name] = records

                # Transform records to match expected format
                transformed_records = []
                for record in records:
                    # Convert record name (entry field)
                    name = record.get('entry', '')

                    # Handle @ as root record
                    if name == '@':
                        name = ''

                    # Convert ANAME from API to ALIAS for octoDNS
                    record_type = record['record_type']
                    if record_type == 'ANAME':
                        record_type = 'ALIAS'

                    transformed_record = {
                        'id': record['record_id'],
                        'name': name,
                        'type': record_type,
                        'ttl': record.get('ttl', 3600),
                        'answers_list': record.get('answers_list', []),
                        'value': (
                            record.get('answers_list', [''])[0]
                            if record.get('answers_list')
                            else ''
                        ),
                        # Preserve weighted policy info
                        'policy': record.get('policy', 'simple'),
                        'weight': record.get('weight'),
                        'description': record.get('description', ''),
                    }
                    transformed_records.append(transformed_record)

                self._zone_records[zone.name] = transformed_records
            except AzionClientNotFound:
                return []

        return self._zone_records[zone.name]

    def _get_raw_records_for(self, zone_name, record_name, record_type):
        """Get raw API records matching name and type."""
        raw_records = self._zone_raw_records.get(zone_name, [])
        # Convert record_name for comparison (empty string = @)
        api_entry = '@' if not record_name else record_name
        # Convert type for comparison (ALIAS = ANAME in API)
        api_type = 'ANAME' if record_type == 'ALIAS' else record_type
        return [
            r
            for r in raw_records
            if r.get('entry') == api_entry and r.get('record_type') == api_type
        ]

    def list_zones(self):
        self.log.debug('list_zones:')
        zones = self._client.zones()
        domains = []
        for zone in zones:
            domain = zone.get('domain', zone.get('name', ''))
            if domain:
                if not domain.endswith('.'):
                    domain += '.'
                domains.append(domain)
        return sorted(domains)

    def _is_dynamic_records(self, records):
        """Check if records should be treated as dynamic (weighted)."""
        if not records:
            return False
        # If any record has weighted policy, treat as dynamic
        # Also if multiple records exist for same name/type (weighted scenario)
        has_weighted = any(r.get('policy') == 'weighted' for r in records)
        has_multiple = len(records) > 1
        return has_weighted or has_multiple

    def _data_for_dynamic(self, _type, records):
        """Convert weighted API records to octoDNS dynamic format."""
        # Get first record for base ttl
        ttl = records[0]['ttl']

        # Build pool values from weighted records
        pool_values = []
        all_values = []

        for record in records:
            weight = record.get('weight', 1)
            # Azion uses 0-255, octoDNS uses 1-15
            # Normalize: weight of 0 means disabled, map to weight 1
            # Scale 1-255 to 1-15
            if weight == 0:
                normalized_weight = 1
            else:
                normalized_weight = max(1, min(15, (weight * 15) // 255 + 1))

            answers = record.get('answers_list', [])
            for answer in answers:
                # For types that need trailing dot
                value = answer
                if _type in ('CNAME', 'ALIAS', 'MX'):
                    if _type == 'MX':
                        # MX format: "priority exchange"
                        parts = answer.split(' ', 1)
                        if len(parts) >= 2:
                            value = answer  # Keep as-is for now
                    elif not value.endswith('.'):
                        value += '.'

                pool_values.append(
                    {
                        'value': value,
                        'weight': normalized_weight,
                        'status': 'up',  # Azion has no health checks
                    }
                )
                all_values.append(value)

        # Build dynamic structure
        data = {
            'ttl': ttl,
            'type': _type,
            'dynamic': {
                'pools': {'weighted': {'values': pool_values}},
                'rules': [{'pool': 'weighted'}],
            },
        }

        # Add values/value based on record type
        if _type in ('CNAME', 'ALIAS'):
            data['value'] = all_values[0] if all_values else ''
        else:
            data['values'] = all_values

        self.log.debug(f'_data_for_dynamic ({_type}): {data}')
        return data

    def populate(self, zone, target=False, lenient=False):
        self.log.debug(
            'populate: name=%s, target=%s, lenient=%s',
            zone.name,
            target,
            lenient,
        )

        values = defaultdict(lambda: defaultdict(list))
        for record in self.zone_records(zone):
            _type = record['type']
            if _type not in self.SUPPORTS:
                self.log.warning(
                    'populate: skipping unsupported %s record', _type
                )
                continue
            values[record['name']][record['type']].append(record)

        before = len(zone.records)
        for name, types in values.items():
            for _type, records in types.items():
                # Check if this should be a dynamic record
                if (
                    _type in self.SUPPORTS_DYNAMIC_TYPES
                    and self._is_dynamic_records(records)
                ):
                    data = self._data_for_dynamic(_type, records)
                else:
                    data_for = getattr(self, f'_data_for_{_type}')
                    data = data_for(_type, records)

                record = Record.new(
                    zone, name, data, source=self, lenient=lenient
                )
                zone.add_record(record, lenient=lenient)

        exists = zone.name in self._zone_records
        self.log.info(
            'populate:   found %s records, exists=%s',
            len(zone.records) - before,
            exists,
        )
        return exists

    def _get_azion_config(self, record):
        """Get Azion-specific config from record's octodns field.

        Supports YAML like:
            octodns:
              azion:
                description: "My description"
                descriptions:
                  1.1.1.1: "Server 1"
                  2.2.2.2: "Server 2"
        """
        octodns = getattr(record, 'octodns', None) or {}
        return octodns.get('azion', {})

    def _get_description_for_value(self, record, value):
        """Get description for a specific value from octodns.azion.descriptions."""
        azion_config = self._get_azion_config(record)
        descriptions = azion_config.get('descriptions', {})
        return descriptions.get(value, '')

    def _get_description(self, record):
        """Get description from octodns.azion.description for simple records."""
        azion_config = self._get_azion_config(record)
        return azion_config.get('description', '')

    def _build_params(
        self, record, answers_list, record_type=None, metadata=None
    ):
        """Build API params dict with optional metadata fields."""
        params = {
            'entry': '@' if not record.name else record.name,
            'record_type': record_type or record._type,
            'ttl': record.ttl,
            'answers_list': answers_list,
        }
        # Add metadata fields if provided
        if metadata:
            if metadata.get('policy'):
                params['policy'] = metadata['policy']
            if metadata.get('weight') is not None:
                params['weight'] = metadata['weight']
            if metadata.get('description'):
                params['description'] = metadata['description']

        # Check for description from octodns.azion config (for new records)
        if not params.get('description'):
            description = self._get_description(record)
            if description:
                params['description'] = description

        return params

    def _params_for_multiple(self, record, metadata=None):
        yield self._build_params(record, list(record.values), metadata=metadata)

    _params_for_A = _params_for_multiple
    _params_for_AAAA = _params_for_multiple

    def _params_for_NS(self, record, metadata=None):
        """Handle NS records by removing trailing dots for Azion API."""
        ns_values = [value.rstrip('.') for value in record.values]
        yield self._build_params(record, ns_values, metadata=metadata)

    def _params_for_CAA(self, record, metadata=None):
        answers = [
            f'{value.flags} {value.tag} "{value.value}"'
            for value in record.values
        ]
        yield self._build_params(record, answers, metadata=metadata)

    def _params_for_single(self, record, metadata=None):
        yield self._build_params(
            record, [record.value.rstrip('.')], metadata=metadata
        )

    _params_for_CNAME = _params_for_single

    def _params_for_ALIAS(self, record, metadata=None):
        '''Convert ALIAS records to ANAME for Azion API'''
        yield self._build_params(
            record,
            [record.value.rstrip('.')],
            record_type='ANAME',
            metadata=metadata,
        )

    def _params_for_MX(self, record, metadata=None):
        answers = [
            f'{value.preference} {value.exchange.rstrip(".")}'
            for value in record.values
        ]
        yield self._build_params(record, answers, metadata=metadata)

    def _params_for_SRV(self, record, metadata=None):
        answers = []
        for value in record.values:
            target = value.target.rstrip('.') if value.target != '.' else '.'
            answer = f'{value.priority} {value.weight} {value.port} {target}'
            answers.append(answer)
        yield self._build_params(record, answers, metadata=metadata)

    def _params_for_PTR(self, record, metadata=None):
        '''Handle PTR records (reverse DNS lookups)'''
        yield self._build_params(
            record,
            [record.value.rstrip('.')],
            record_type='PTR',
            metadata=metadata,
        )

    def _params_for_TXT(self, record, metadata=None):
        answers = list(record.values)
        yield self._build_params(record, answers, metadata=metadata)

    def _is_dynamic_record(self, record):
        """Check if an octoDNS record is dynamic."""
        return getattr(record, 'dynamic', False)

    def _params_for_dynamic(self, record):
        """Generate weighted record params from dynamic octoDNS record."""
        dynamic = record.dynamic
        record_type = 'ANAME' if record._type == 'ALIAS' else record._type

        # Get all values from pools with their weights
        for pool_name, pool_data in dynamic.pools.items():
            for pool_value in pool_data.data['values']:
                value = pool_value['value']
                weight = pool_value.get('weight', 1)
                # Convert octoDNS weight (1-15) to Azion weight (0-255)
                azion_weight = min(255, max(0, (weight * 255) // 15))

                # Format value based on record type
                if record._type in ('CNAME', 'ALIAS'):
                    answers = [value.rstrip('.')]
                elif record._type == 'MX':
                    # MX values in dynamic are just the exchange
                    # Need to get preference from somewhere - use default 10
                    answers = [f'10 {value.rstrip(".")}']
                else:
                    answers = [value]

                params = {
                    'entry': '@' if not record.name else record.name,
                    'record_type': record_type,
                    'ttl': record.ttl,
                    'answers_list': answers,
                    'policy': 'weighted',
                    'weight': azion_weight,
                }

                # Add description only if provided via octodns.azion.descriptions
                description = self._get_description_for_value(record, value)
                if description:
                    params['description'] = description

                yield params

    def _apply_Create(self, change):
        new = change.new
        zone_id = self._get_zone_id_by_name(new.zone.name)

        if self._is_dynamic_record(new):
            # Create multiple weighted records
            for params in self._params_for_dynamic(new):
                self.log.debug(
                    '_apply_Create: creating weighted record %s', params
                )
                self._client.record_create(zone_id, params)
        else:
            # Create simple record
            params_for = getattr(self, f'_params_for_{new._type}')
            for params in params_for(new):
                self._client.record_create(zone_id, params)

    def _apply_Update(self, change):
        existing = change.existing
        new = change.new
        zone = existing.zone
        zone_id = self._get_zone_id_by_name(zone.name)

        self.log.debug(
            '_apply_Update: updating %s %s', existing.fqdn, existing._type
        )

        # For dynamic records or when changing between simple/dynamic,
        # delete all existing and create new
        if self._is_dynamic_record(new) or self._is_dynamic_record(existing):
            # Delete all existing records with this name/type
            for record in self.zone_records(zone):
                if (
                    existing.name == record['name']
                    and existing._type == record['type']
                ):
                    self.log.debug(
                        '_apply_Update: deleting existing record %s',
                        record['id'],
                    )
                    self._client.record_delete(zone_id, record['id'])

            # Create new records
            if self._is_dynamic_record(new):
                for params in self._params_for_dynamic(new):
                    self.log.debug(
                        '_apply_Update: creating weighted record %s', params
                    )
                    self._client.record_create(zone_id, params)
            else:
                params_for = getattr(self, f'_params_for_{new._type}')
                for params in params_for(new):
                    self._client.record_create(zone_id, params)
        else:
            # Simple record update - find and update the single record
            record_found = False
            for record in self.zone_records(zone):
                if (
                    existing.name == record['name']
                    and existing._type == record['type']
                ):
                    params_for = getattr(self, f'_params_for_{new._type}')
                    # Preserve existing metadata for simple records
                    metadata = {
                        'policy': record.get('policy', 'simple'),
                        'weight': record.get('weight'),
                        'description': record.get('description', ''),
                    }
                    params = next(params_for(new, metadata=metadata))
                    self.log.debug(
                        '_apply_Update: updating record %s with params %s',
                        record['id'],
                        params,
                    )
                    self._client.record_update(zone_id, record['id'], params)
                    record_found = True
                    break

            if not record_found:
                self.log.warning(
                    '_apply_Update: no matching record found for %s %s',
                    existing.fqdn,
                    existing._type,
                )

    def _apply_Delete(self, change):
        existing = change.existing
        zone = existing.zone
        zone_id = self._get_zone_id_by_name(zone.name)

        # Delete all records matching name/type (handles both simple and dynamic)
        for record in self.zone_records(zone):
            if (
                existing.name == record['name']
                and existing._type == record['type']
            ):
                self.log.debug(
                    '_apply_Delete: deleting record %s', record['id']
                )
                self._client.record_delete(zone_id, record['id'])

    def _apply(self, plan):
        desired = plan.desired
        changes = plan.changes
        self.log.debug(
            '_apply: zone=%s, len(changes)=%d', desired.name, len(changes)
        )

        # Check if zone exists, create if it doesn't
        try:
            self._get_zone_id_by_name(desired.name)
        except AzionClientNotFound:
            self.log.debug('_apply:   no matching zone, creating zone')
            zone_name = desired.name.rstrip('.')
            self._client.zone_create(zone_name)
            # Clear cache to force refresh
            self._zone_cache.pop(desired.name, None)

        for change in changes:
            class_name = change.__class__.__name__
            getattr(self, f'_apply_{class_name}')(change)

        # Clear out the caches to force refresh on next sync
        self._zone_records.pop(desired.name, None)
        self._zone_raw_records.pop(desired.name, None)
