import logging
from collections import defaultdict

from requests import Session

from octodns import __VERSION__ as octodns_version
from octodns.provider import ProviderException
from octodns.provider.base import BaseProvider
from octodns.record import Record

__version__ = __VERSION__ = '1.0.0'


class AzionClientException(ProviderException):
    pass


class AzionClientNotFound(AzionClientException):
    def __init__(self):
        super().__init__('Not Found')


class AzionClientUnauthorized(AzionClientException):
    def __init__(self):
        super().__init__('Unauthorized')


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
        if resp.status_code == 404:
            raise AzionClientNotFound()
        resp.raise_for_status()
        return resp

    def zones(self):
        '''Get all zones'''
        path = '/intelligent_dns'
        ret = []

        page = 1
        page_size = 200

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

    def zone(self, zone_id):
        '''Get a specific zone by ID'''
        path = f'/intelligent_dns/{zone_id}'
        return self._request('GET', path).json()

    def zone_create(self, name):
        '''Create a new zone'''
        path = '/intelligent_dns'
        data = {'name': name, 'is_active': True}
        return self._request('POST', path, data=data).json()

    def zone_delete(self, zone_id):
        '''Delete a zone'''
        path = f'/intelligent_dns/{zone_id}'
        self._request('DELETE', path)

    def records(self, zone_id):
        '''Get all records for a zone'''
        path = f'/intelligent_dns/{zone_id}/records'
        ret = []

        page = 1
        page_size = 200

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
    SUPPORTS_DYNAMIC = False
    SUPPORTS_ROOT_NS = False
    SUPPORTS = set(
        ('A', 'AAAA', 'ALIAS', 'CAA', 'CNAME', 'MX', 'NS', 'PTR', 'TXT', 'SRV')
    )

    def __init__(self, id, token, *args, **kwargs):
        self.log = logging.getLogger(f'AzionProvider[{id}]')
        self.log.debug('__init__: id=%s, token=***', id)
        super().__init__(id, *args, **kwargs)
        self._client = AzionClient(token)

        self._zone_records = {}
        self._zone_cache = {}

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

    def _data_for_multiple(self, _type, records):
        values = []
        for record in records:
            answers = record.get('answers_list', [record.get('value', '')])
            values.extend(answers)
        return {'ttl': records[0]['ttl'], 'type': _type, 'values': values}

    _data_for_A = _data_for_multiple
    _data_for_AAAA = _data_for_multiple

    def _data_for_CAA(self, _type, records):
        values = []
        for record in records:
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
        return {'ttl': records[0]['ttl'], 'type': _type, 'values': values}

    def _data_for_CNAME(self, _type, records):
        record = records[0]
        value = record.get('answers_list', [record.get('value', '')])[0]
        if not value.endswith('.'):
            value += '.'
        return {'ttl': record['ttl'], 'type': _type, 'value': value}

    def _data_for_ANAME(self, _type, records):
        '''Handle ANAME records from API (will be converted to ALIAS).

        Azion-specific record type, like CNAME but for azioncdn.net and
        azionedge.net domains.
        '''
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
        for record in records:
            answers = record.get('answers_list', [record.get('value', '')])
            # Process all MX answers in the list
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
        return {'ttl': records[0]['ttl'], 'type': _type, 'values': values}

    def _data_for_NS(self, _type, records):
        values = []
        for record in records:
            answers = record.get('answers_list', [record.get('value', '')])
            for answer in answers:
                if not answer.endswith('.'):
                    answer += '.'
                values.append(answer)
        return {'ttl': records[0]['ttl'], 'type': _type, 'values': values}

    def _data_for_SRV(self, _type, records):
        values = []
        for record in records:
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
        return {'type': _type, 'ttl': records[0]['ttl'], 'values': values}

    def _data_for_TXT(self, _type, records):
        values = []
        for record in records:
            answers = record.get('answers_list', [record.get('value', '')])
            for answer in answers:
                # Remove quotes if present
                if (
                    answer.startswith('"')
                    and answer.endswith('"')
                    and len(answer) > 2
                ):
                    answer = answer[1:-1]
                # Escape semicolons for octoDNS compatibility
                answer = answer.replace(';', '\\;')
                values.append(answer)
        return {'ttl': records[0]['ttl'], 'type': _type, 'values': values}

    def zone_records(self, zone):
        if zone.name not in self._zone_records:
            try:
                zone_id = self._get_zone_id_by_name(zone.name)
                records = self._client.records(zone_id)

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
                        'id': record['record_id'],  # Correct field name
                        'name': name,
                        'type': record_type,
                        'ttl': record.get('ttl', 3600),
                        'answers_list': record.get('answers_list', []),
                        'value': (
                            record.get('answers_list', [''])[0]
                            if record.get('answers_list')
                            else ''
                        ),
                    }
                    transformed_records.append(transformed_record)

                self._zone_records[zone.name] = transformed_records
            except AzionClientNotFound:
                return []

        return self._zone_records[zone.name]

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
                data_for = getattr(self, f'_data_for_{_type}')
                record = Record.new(
                    zone,
                    name,
                    data_for(_type, records),
                    source=self,
                    lenient=lenient,
                )
                zone.add_record(record, lenient=lenient)

        exists = zone.name in self._zone_records
        self.log.info(
            'populate:   found %s records, exists=%s',
            len(zone.records) - before,
            exists,
        )
        return exists

    def _params_for_multiple(self, record):
        for value in record.values:
            yield {
                'entry': '@' if not record.name else record.name,
                'record_type': record._type,
                'ttl': record.ttl,
                'answers_list': [value],
            }

    _params_for_A = _params_for_multiple
    _params_for_AAAA = _params_for_multiple
    _params_for_NS = _params_for_multiple

    def _params_for_CAA(self, record):
        for value in record.values:
            answer = f'{value.flags} {value.tag} "{value.value}"'
            yield {
                'entry': '@' if not record.name else record.name,
                'record_type': record._type,
                'ttl': record.ttl,
                'answers_list': [answer],
            }

    def _params_for_single(self, record):
        yield {
            'entry': '@' if not record.name else record.name,
            'record_type': record._type,
            'ttl': record.ttl,
            'answers_list': [record.value.rstrip('.')],
        }

    _params_for_CNAME = _params_for_single

    def _params_for_ALIAS(self, record):
        '''Convert ALIAS records to ANAME for Azion API'''
        yield {
            'entry': '@' if not record.name else record.name,
            'record_type': 'ANAME',
            'ttl': record.ttl,
            'answers_list': [record.value.rstrip('.')],
        }

    def _params_for_MX(self, record):
        for value in record.values:
            answer = f'{value.preference} {value.exchange.rstrip(".")}'
            yield {
                'entry': '@' if not record.name else record.name,
                'record_type': record._type,
                'ttl': record.ttl,
                'answers_list': [answer],
            }

    def _params_for_SRV(self, record):
        for value in record.values:
            target = value.target.rstrip('.') if value.target != '.' else '.'
            answer = f'{value.priority} {value.weight} {value.port} {target}'
            yield {
                'entry': '@' if not record.name else record.name,
                'record_type': record._type,
                'ttl': record.ttl,
                'answers_list': [answer],
            }

    def _params_for_PTR(self, record):
        '''Handle PTR records (reverse DNS lookups)'''
        yield {
            'entry': '@' if not record.name else record.name,
            'record_type': 'PTR',
            'ttl': record.ttl,
            'answers_list': [record.value.rstrip('.')],
        }

    def _params_for_TXT(self, record):
        for value in record.values:
            # Ensure TXT values are quoted
            quoted_value = (
                f'"{value}"'
                if not (value.startswith('"') and value.endswith('"'))
                else value
            )
            yield {
                'entry': '@' if not record.name else record.name,
                'record_type': record._type,
                'ttl': record.ttl,
                'answers_list': [quoted_value],
            }

    def _apply_Create(self, change):
        new = change.new
        zone_id = self._get_zone_id_by_name(new.zone.name)
        params_for = getattr(self, f'_params_for_{new._type}')
        for params in params_for(new):
            self._client.record_create(zone_id, params)

    def _apply_Update(self, change):
        self._apply_Delete(change)
        self._apply_Create(change)

    def _apply_Delete(self, change):
        existing = change.existing
        zone = existing.zone
        zone_id = self._get_zone_id_by_name(zone.name)

        for record in self.zone_records(zone):
            if (
                existing.name == record['name']
                and existing._type == record['type']
            ):
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

        # Clear out the cache if any
        self._zone_records.pop(desired.name, None)
