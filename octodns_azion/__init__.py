import logging
import re
import time
from collections import defaultdict
from datetime import datetime, timezone

from requests import Session

from octodns import __VERSION__ as octodns_version
from octodns.provider import ProviderException
from octodns.provider.base import BaseProvider
from octodns.record import Record, Update

__version__ = __VERSION__ = '1.2.0'


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


class AzionClientRateLimited(AzionClientException):
    def __init__(self, message='Too Many Requests'):
        super().__init__(message)


class AzionUnsupportedRecord(ProviderException):
    '''A desired record that the Azion API would reject.'''

    pass


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
    DEFAULT_TIMEOUT = 30
    DEFAULT_MAX_RETRIES = 5
    # Bounds, in seconds, for waiting on a rate limited (429) response
    MIN_RETRY_WAIT = 1
    MAX_RETRY_WAIT = 60
    MAX_ZONE_NAME_LENGTH = 50

    def __init__(
        self, token, timeout=DEFAULT_TIMEOUT, max_retries=DEFAULT_MAX_RETRIES
    ):
        self.log = logging.getLogger('AzionClient')
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
        self.timeout = timeout
        self.max_retries = max_retries

    def _retry_wait(self, resp, attempt):
        '''Seconds to wait before retrying a rate limited request.

        Honors Retry-After (seconds) and X-RateLimit-Reset (ISO-8601, as
        returned by the v3 API), falling back to exponential backoff.
        '''
        headers = getattr(resp, 'headers', None) or {}
        wait = None
        retry_after = headers.get('Retry-After')
        if retry_after:
            try:
                wait = float(retry_after)
            except ValueError:
                pass
        reset = headers.get('X-RateLimit-Reset')
        if wait is None and reset:
            try:
                reset_at = datetime.fromisoformat(reset)
                if reset_at.tzinfo is None:
                    reset_at = reset_at.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                wait = (reset_at - now).total_seconds()
            except ValueError:
                pass
        if wait is None:
            wait = 2**attempt
        return min(max(wait, self.MIN_RETRY_WAIT), self.MAX_RETRY_WAIT)

    def _request(self, method, path, params=None, data=None):
        url = f'{self.BASE}{path}'
        attempt = 0
        while True:
            resp = self._sess.request(
                method, url, params=params, json=data, timeout=self.timeout
            )
            if resp.status_code != 429:
                break
            # A 429 means the request was rejected without being processed,
            # so it is safe to retry writes as well as reads
            if attempt >= self.max_retries:
                raise AzionClientRateLimited()
            wait = self._retry_wait(resp, attempt)
            self.log.warning(
                '_request: rate limited on %s %s, retrying in %.1fs',
                method,
                path,
                wait,
            )
            time.sleep(wait)
            attempt += 1

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
        '''Create a new zone, returning the created zone'''
        path = '/intelligent_dns'
        # name is a display name limited to 50 characters, domain isn't
        data = {
            'name': name[: self.MAX_ZONE_NAME_LENGTH],
            'domain': name,
            'is_active': True,
        }
        resp = self._request('POST', path, data=data).json()
        # v3 wraps the created zone in a single item list under results
        zone = resp.get('results', resp) if isinstance(resp, dict) else resp
        if isinstance(zone, list):
            zone = zone[0] if zone else {}
        return zone

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

            # Empty zones are returned as `results: {}`
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
    # Azion weight 0 keeps a record but never answers it, which maps to the
    # octoDNS "down" status
    SUPPORTS_POOL_VALUE_STATUS = True
    SUPPORTS_ROOT_NS = False
    SUPPORTS = set(
        ('A', 'AAAA', 'ALIAS', 'CAA', 'CNAME', 'MX', 'NS', 'PTR', 'TXT', 'SRV')
    )
    # Record types that can be represented as weighted records in both Azion
    # and octoDNS. Azion also supports weighted MX and ANAME, but octoDNS has
    # no dynamic support for MX or ALIAS.
    SUPPORTS_DYNAMIC_TYPES = set(('A', 'AAAA', 'CNAME'))
    # Name of the single pool used to represent Azion weighted records
    DYNAMIC_POOL = 'weighted'
    # octoDNS pool value weights are 1-100, Azion's are 0-255
    MAX_WEIGHT = 100
    # Weight Azion assumes for weighted records that don't specify one
    DEFAULT_API_WEIGHT = 255
    # Limits enforced by the Azion API. They're checked while planning so that
    # a record the API would reject doesn't fail an apply part way through.
    MAX_ANSWERS = 10
    MAX_ANSWERS_TYPES = set(('A', 'AAAA', 'MX', 'NS'))
    MAX_TXT_LENGTH = 1000
    MAX_DESCRIPTION_LENGTH = 45
    ANAME_TTL = 20
    ANAME_TARGET_SUFFIXES = (
        '.azioncdn.net',
        '.azionedge.net',
        '.azionedge.com',
    )
    CAA_FLAGS = (0, 128)
    CAA_VALUE_RE = re.compile(r'[\w;=@:.\-\s/]+')
    # ; and " that aren't escaped, i.e. preceded by an even number of \
    TXT_UNESCAPED_RE = re.compile(r'(?<!\\)((?:\\\\)*)([;"])')

    def __init__(
        self,
        id,
        token,
        timeout=AzionClient.DEFAULT_TIMEOUT,
        max_retries=AzionClient.DEFAULT_MAX_RETRIES,
        *args,
        **kwargs,
    ):
        self.log = logging.getLogger(f'AzionProvider[{id}]')
        self.log.debug(
            '__init__: id=%s, token=***, timeout=%s, max_retries=%s',
            id,
            timeout,
            max_retries,
        )
        super().__init__(id, *args, **kwargs)
        self._client = AzionClient(
            token, timeout=timeout, max_retries=max_retries
        )

        self._zone_records = {}
        self._zone_cache = {}
        # Cache for raw API records (preserves weighted record info)
        # Key: zone_name -> list of raw API records with full metadata
        self._zone_raw_records = {}

    @staticmethod
    def _normalize_domain(name):
        return (name or '').rstrip('.').lower()

    @staticmethod
    def _entry_to_name(entry):
        '''Convert an Azion entry into an octoDNS record name.'''
        entry = (entry or '').lower()
        return '' if entry == '@' else entry

    @staticmethod
    def _api_type(_type):
        return 'ANAME' if _type == 'ALIAS' else _type

    def _get_zone_id_by_name(self, zone_name):
        '''Get zone ID by zone name'''
        if zone_name not in self._zone_cache:
            wanted = self._normalize_domain(zone_name)
            zones = self._client.zones()
            for zone in zones:
                zone_domain = zone.get('domain') or zone.get('name') or ''
                if self._normalize_domain(zone_domain) == wanted:
                    self._zone_cache[zone_name] = zone['id']
                    break
            else:
                raise AzionClientNotFound()

        return self._zone_cache[zone_name]

    def _answers(self, records):
        '''All distinct answers across the API records for a name/type.'''
        answers = []
        for record in records:
            for answer in record.get('answers_list') or []:
                if answer not in answers:
                    answers.append(answer)
        return answers

    def _get_record_answers(self, records):
        """Helper to extract answers and ttl for a name/type."""
        return self._answers(records), records[0]['ttl']

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
        answers, ttl = self._get_record_answers(records)
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
        return {'ttl': ttl, 'type': _type, 'values': values}

    def _data_for_single(self, _type, records):
        '''Handle single value records (CNAME, ALIAS, PTR).'''
        answers, ttl = self._get_record_answers(records)
        if len(answers) > 1:
            self.log.warning(
                '_data_for_single: %s record "%s" has %d values in Azion but '
                'octoDNS supports one, only %s is managed and the others '
                '(%s) will be removed if octoDNS updates this record',
                _type,
                records[0].get('name', ''),
                len(answers),
                answers[0],
                ', '.join(answers[1:]),
            )
        value = answers[0] if answers else ''
        return {
            'ttl': ttl,
            'type': _type,
            'value': self._ensure_trailing_dot(value),
        }

    _data_for_CNAME = _data_for_single
    # ALIAS is the octoDNS representation of Azion's ANAME record type.
    _data_for_ALIAS = _data_for_single
    _data_for_PTR = _data_for_single

    def _data_for_MX(self, _type, records):
        values = []
        answers, ttl = self._get_record_answers(records)
        for answer in answers:
            # MX format: 'priority exchange'
            parts = answer.split(' ', 1)
            if len(parts) >= 2:
                exchange = self._ensure_trailing_dot(parts[1].strip())
                values.append(
                    {'preference': int(parts[0]), 'exchange': exchange}
                )
        return {'ttl': ttl, 'type': _type, 'values': values}

    def _data_for_SRV(self, _type, records):
        values = []
        answers, ttl = self._get_record_answers(records)
        for answer in answers:
            # SRV format: 'priority weight port target'
            parts = answer.split(' ', 3)
            if len(parts) >= 4:
                target = self._ensure_trailing_dot(parts[3])
                values.append(
                    {
                        'priority': int(parts[0]),
                        'weight': int(parts[1]),
                        'port': int(parts[2]),
                        'target': target,
                    }
                )
        return {'type': _type, 'ttl': ttl, 'values': values}

    def _txt_value(self, answer):
        '''octoDNS form of a stored TXT answer.

        Azion serves TXT answers unescaped, so ; and " that aren't escaped
        are escaped. A quoted answer is served
        with its quotes, it mustn't be parsed as octoDNS chunks.
        '''
        return self.TXT_UNESCAPED_RE.sub(r'\1\\\2', answer)

    def _data_for_TXT(self, _type, records):
        """Handle TXT records with proper quote and semicolon handling."""
        answers, ttl = self._get_record_answers(records)

        values = []
        for answer in answers:
            if answer:  # Skip empty answers
                values.append(self._txt_value(answer))

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
            except AzionClientNotFound:
                # The zone doesn't exist yet. Errors fetching the records of
                # an existing zone are not swallowed, they'd otherwise look
                # like an empty zone.
                return []
            records = self._client.records(zone_id)

            # Store raw records for later use in apply operations
            self._zone_raw_records[zone.name] = records

            # Transform records to match expected format
            transformed_records = []
            for record in records:
                # Convert ANAME from API to ALIAS for octoDNS
                record_type = record['record_type'].upper()
                if record_type == 'ANAME':
                    record_type = 'ALIAS'

                answers_list = record.get('answers_list') or []
                transformed_record = {
                    'id': record['record_id'],
                    'name': self._entry_to_name(record.get('entry')),
                    'type': record_type,
                    'ttl': record.get('ttl', 3600),
                    'answers_list': answers_list,
                    'value': answers_list[0] if answers_list else '',
                    # Preserve weighted policy info
                    'policy': record.get('policy', 'simple'),
                    'weight': record.get('weight'),
                    'description': record.get('description', ''),
                }
                transformed_records.append(transformed_record)

            self._zone_records[zone.name] = transformed_records

        return self._zone_records[zone.name]

    def _get_raw_records_for(self, zone_name, record_name, record_type):
        """Get raw API records matching name and type."""
        raw_records = self._zone_raw_records.get(zone_name, [])
        api_type = self._api_type(record_type)
        return [
            r
            for r in raw_records
            if self._entry_to_name(r.get('entry')) == record_name
            and (r.get('record_type') or '').upper() == api_type
        ]

    def _raw_records(self, zone, record_name, record_type):
        '''Raw API records for a name/type, loading the zone if needed.'''
        self.zone_records(zone)
        return self._get_raw_records_for(zone.name, record_name, record_type)

    def list_zones(self):
        self.log.debug('list_zones:')
        zones = self._client.zones()
        domains = []
        for zone in zones:
            domain = self._normalize_domain(
                zone.get('domain') or zone.get('name')
            )
            if domain:
                domains.append(f'{domain}.')
        return sorted(domains)

    def _is_dynamic_records(self, records):
        """Check if records should be treated as dynamic (weighted)."""
        # Several simple records for a name/type are legacy duplicates, not
        # a weighted set
        return any(self._is_weighted_record(r) for r in records)

    def _api_weight(self, record):
        '''The weight of a weighted API record, 0-255.'''
        weight = record.get('weight')
        return self.DEFAULT_API_WEIGHT if weight is None else weight

    def _is_live(self, record):
        '''Whether Azion answers with an API record.'''
        if not self._is_weighted_record(record):
            return True
        # Azion keeps weight 0 records but never answers them
        return self._api_weight(record) > 0

    def _data_for_dynamic(self, _type, records):
        """Convert weighted API records to octoDNS dynamic format."""
        ttl = records[0]['ttl']
        name = records[0].get('name', '')

        top = max(self._api_weight(r) for r in records)
        scale = 1
        if top > self.MAX_WEIGHT:
            # Scale down instead of clamping so the traffic split is kept
            scale = self.MAX_WEIGHT / top
            self.log.warning(
                '_data_for_dynamic: weights of %s record "%s" are above the '
                'octoDNS maximum of %d, scaling them down',
                _type,
                name,
                self.MAX_WEIGHT,
            )
        if len(set(r['ttl'] for r in records)) > 1:
            self.log.warning(
                '_data_for_dynamic: weighted %s records for "%s" have '
                'different TTLs, using %d',
                _type,
                name,
                ttl,
            )

        pool_values = []
        for record in records:
            answers = record.get('answers_list') or []
            if len(answers) > 1:
                self.log.warning(
                    '_data_for_dynamic: weighted %s record "%s" answers %s '
                    'together, octoDNS reads them as independent values and '
                    'splits them into one record each if it updates them',
                    _type,
                    name,
                    ', '.join(answers),
                )
            if self._is_live(record):
                weight = max(1, round(self._api_weight(record) * scale))
                status = 'obey'
            else:
                weight, status = 1, 'down'
            for answer in answers:
                value = answer
                if _type == 'CNAME':
                    value = self._ensure_trailing_dot(value)
                pool_values.append(
                    {'value': value, 'weight': weight, 'status': status}
                )

        # octoDNS requires single value pools to have weight 1
        if len(pool_values) == 1:
            pool_values[0]['weight'] = 1

        values = sorted(set(v['value'] for v in pool_values))

        data = {
            'ttl': ttl,
            'type': _type,
            'dynamic': {
                'pools': {self.DYNAMIC_POOL: {'values': pool_values}},
                'rules': [{'pool': self.DYNAMIC_POOL}],
            },
        }

        if _type == 'CNAME':
            data['value'] = values[0] if values else ''
        else:
            data['values'] = values

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
            if _type == 'ALIAS' and record['name']:
                # Azion allows ANAME records anywhere, octoDNS ALIAS records
                # only at the root
                self.log.warning(
                    'populate: skipping ANAME record "%s", octoDNS only '
                    'supports ALIAS records at the zone root',
                    record['name'],
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
                    if any(self._is_weighted_record(r) for r in records):
                        self.log.warning(
                            'populate: weighted %s records for "%s" cannot '
                            'be represented in octoDNS, reading them as a '
                            'simple record; weights will be dropped if '
                            'octoDNS updates this record',
                            _type,
                            name,
                        )
                    elif len(records) > 1:
                        self.log.warning(
                            'populate: merging %d %s records for "%s"',
                            len(records),
                            _type,
                            name,
                        )
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

    def _normalize_dynamic(self, desired, record):
        '''Reduce a dynamic record to what Azion weighted records can express:
        a single pool, a single catch-all rule, no fallback and no health
        checks.'''
        dynamic = record.dynamic
        rules = [rule.data for rule in dynamic.rules]
        default_rule = next(
            (r for r in rules if not r.get('geos') and not r.get('subnets')),
            rules[-1],
        )
        pool_name = default_rule['pool']
        pool = dynamic.pools[pool_name]

        if (
            len(dynamic.pools) > 1
            or len(rules) > 1
            or default_rule.get('geos')
            or default_rule.get('subnets')
            or pool.data.get('fallback')
        ):
            msg = (
                f'{record.fqdn}: Azion only supports a single weighted pool '
                'without geo/subnet rules or fallbacks'
            )
            self.supports_warn_or_except(
                msg, f'using only pool "{pool_name}" for all traffic'
            )

        values = []
        for value in pool.data['values']:
            weight = value.get('weight', 1)
            status = value.get('status', 'obey')
            if status == 'up':
                # Azion has no health checks so "up" and "obey" are the same
                status = 'obey'
            elif status == 'down':
                # down values are stored with weight 0, the weight is lost
                weight = 1
            values.append(
                {
                    'value': str(value['value']),
                    'weight': weight,
                    'status': status,
                }
            )

        data = record.data
        data['type'] = record._type
        data['dynamic'] = {
            'pools': {self.DYNAMIC_POOL: {'values': values}},
            'rules': [{'pool': self.DYNAMIC_POOL}],
        }
        # Azion answers exclusively from the pool, there are no default
        # values to fall back on
        answers = sorted(set(v['value'] for v in values))
        if record._type == 'CNAME':
            data.pop('values', None)
            data['value'] = answers[0]
        else:
            data.pop('value', None)
            data['values'] = answers

        return Record.new(
            desired, record.name, data, source=record.source, lenient=True
        )

    def _with_ttl(self, desired, record, ttl):
        data = record.data
        data['type'] = record._type
        data['ttl'] = ttl
        return Record.new(
            desired, record.name, data, source=record.source, lenient=True
        )

    def _validate_record(self, record):
        '''Raise AzionUnsupportedRecord if the API would reject a record.'''
        problems = []
        _type = record._type
        if record.ttl < 1:
            problems.append('ttl must be at least 1')
        if (
            _type in self.MAX_ANSWERS_TYPES
            and not self._is_dynamic_record(record)
            and len(record.values) > self.MAX_ANSWERS
        ):
            problems.append(f'at most {self.MAX_ANSWERS} values are supported')
        if _type == 'AAAA':
            for value in record.values:
                if value.endswith('::'):
                    problems.append(f'address {value} ends in "::"')
        elif _type == 'ALIAS':
            target = record.value.rstrip('.')
            if not target.endswith(self.ANAME_TARGET_SUFFIXES):
                problems.append(
                    f'ANAME target {record.value} must be in '
                    + ', '.join(s[1:] for s in self.ANAME_TARGET_SUFFIXES)
                )
        elif _type == 'CAA':
            for value in record.values:
                if value.flags not in self.CAA_FLAGS:
                    problems.append('CAA flags must be 0 or 128')
                if not self.CAA_VALUE_RE.fullmatch(value.value):
                    problems.append(
                        f'CAA value "{value.value}" has unsupported characters'
                    )
        elif _type == 'MX':
            for value in record.values:
                if value.exchange == '.':
                    problems.append('null MX (exchange ".") is not supported')
        elif _type == 'TXT':
            for value in record.values:
                if any(c in value for c in '\n\r\t'):
                    problems.append(
                        'values with newlines or tabs are not supported'
                    )
            length = sum(len(v) for v in record.values)
            if length > self.MAX_TXT_LENGTH:
                problems.append(
                    f'values are {length} characters long in total, at most '
                    f'{self.MAX_TXT_LENGTH} are supported'
                )
        if self._is_dynamic_record(record):
            for params in self._params_for_dynamic(record):
                description = params.get('description', '')
                if len(description) > self.MAX_DESCRIPTION_LENGTH:
                    problems.append(
                        f'description "{description}" is longer than '
                        f'{self.MAX_DESCRIPTION_LENGTH} characters'
                    )
        if problems:
            raise AzionUnsupportedRecord(
                f'{record.fqdn} {_type}: ' + '; '.join(problems)
            )

    def _process_desired_zone(self, desired):
        for record in desired.records:
            # Only A, AAAA and CNAME can be dynamic in octoDNS
            if getattr(record, 'dynamic', False):
                record = self._normalize_dynamic(desired, record)
                desired.add_record(record, replace=True)
            if record._type == 'ALIAS' and record.ttl != self.ANAME_TTL:
                self.supports_warn_or_except(
                    f'{record.fqdn}: Azion requires ANAME records to have a '
                    f'ttl of {self.ANAME_TTL}',
                    f'using a ttl of {self.ANAME_TTL}',
                )
                record = self._with_ttl(desired, record, self.ANAME_TTL)
                desired.add_record(record, replace=True)
            self._validate_record(record)

        return super()._process_desired_zone(desired)

    def _is_lossy_read(self, record, raws):
        '''Whether the API records hold more than octoDNS could read.'''
        if self._is_dynamic_record(record):
            return False
        if any(self._is_weighted_record(r) for r in raws):
            # weighted MX and ANAME records are read as simple records
            return True
        # only the first of several values is read for these types
        return (
            record._type in ('ALIAS', 'CNAME', 'PTR')
            and len(self._answers(raws)) > 1
        )

    def _extra_changes(self, existing, desired, changes):
        '''Plan updates for records whose API records differ in ways octoDNS
        doesn't see: per-value descriptions, weights above 100, per-record
        TTLs, how values are grouped into records and duplicates.'''
        changed = set((c.record.name, c.record._type) for c in changes)
        current = {(r.name, r._type): r for r in existing.records}
        extra = []
        for record in desired.records:
            key = (record.name, record._type)
            if key in changed or key not in current:
                continue
            raws = self._get_raw_records_for(
                existing.name, record.name, record._type
            )
            if self._is_lossy_read(record, raws):
                # don't force what octoDNS can't represent, it's only
                # rewritten along with a change octoDNS sees
                continue
            if not self._converged(raws, self._desired_params(record)):
                extra.append(Update(current[key], record))
        return extra

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
        description = descriptions.get(value)
        if description is None and value.endswith('.'):
            description = descriptions.get(value.rstrip('.'))
        return description or ''

    def _get_description(self, record):
        """Get description from octodns.azion.description for simple records."""
        azion_config = self._get_azion_config(record)
        return azion_config.get('description', '')

    def _build_params(self, record, answers_list, record_type=None):
        """Build API params dict for a simple policy record."""
        params = {
            'entry': '@' if not record.name else record.name,
            'record_type': record_type or record._type,
            'ttl': record.ttl,
            'answers_list': answers_list,
            # Always explicit, the API's PUT resets omitted policies to simple
            'policy': 'simple',
        }

        # Note that Azion currently discards descriptions of simple records
        description = self._get_description(record)
        if description:
            params['description'] = description

        return params

    def _params_for_multiple(self, record):
        yield self._build_params(record, list(record.values))

    _params_for_A = _params_for_multiple
    _params_for_AAAA = _params_for_multiple

    def _params_for_NS(self, record):
        """Handle NS records by removing trailing dots for Azion API."""
        ns_values = [value.rstrip('.') for value in record.values]
        yield self._build_params(record, ns_values)

    def _params_for_CAA(self, record):
        answers = [
            f'{value.flags} {value.tag} "{value.value}"'
            for value in record.values
        ]
        yield self._build_params(record, answers)

    def _params_for_single(self, record):
        yield self._build_params(record, [record.value.rstrip('.')])

    _params_for_CNAME = _params_for_single

    def _params_for_ALIAS(self, record):
        '''Convert ALIAS records to ANAME for Azion API'''
        yield self._build_params(
            record, [record.value.rstrip('.')], record_type='ANAME'
        )

    def _params_for_MX(self, record):
        answers = []
        for value in record.values:
            exchange = value.exchange.rstrip('.')
            answers.append(f'{value.preference} {exchange}')
        yield self._build_params(record, answers)

    def _params_for_SRV(self, record):
        answers = []
        for value in record.values:
            target = value.target.rstrip('.') if value.target != '.' else '.'
            answer = f'{value.priority} {value.weight} {value.port} {target}'
            answers.append(answer)
        yield self._build_params(record, answers)

    def _params_for_PTR(self, record):
        '''Handle PTR records (reverse DNS lookups)'''
        yield self._build_params(
            record, [record.value.rstrip('.')], record_type='PTR'
        )

    def _params_for_TXT(self, record):
        answers = list(record.values)
        yield self._build_params(record, answers)

    def _is_dynamic_record(self, record):
        """Check if an octoDNS record is dynamic."""
        return bool(getattr(record, 'dynamic', False))

    def _params_for_dynamic(self, record):
        """Generate weighted record params from dynamic octoDNS record."""
        dynamic = record.dynamic
        record_type = self._api_type(record._type)

        for pool_data in dynamic.pools.values():
            for pool_value in pool_data.data['values']:
                value = str(pool_value['value'])
                if pool_value.get('status') == 'down':
                    # weight 0 keeps the record without ever answering it
                    azion_weight = 0
                else:
                    # octoDNS weights (1-100) fit Azion's range (0-255)
                    azion_weight = pool_value.get('weight', 1)

                if record._type == 'CNAME':
                    answers = [value.rstrip('.')]
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

    def _desired_params(self, record):
        '''The API records that should exist for an octoDNS record.'''
        if self._is_dynamic_record(record):
            return list(self._params_for_dynamic(record))
        return list(getattr(self, f'_params_for_{record._type}')(record))

    def _raw_answers(self, raw):
        '''The sorted answers of an API record, in the form params use.'''
        answers = raw.get('answers_list') or []
        if (raw.get('record_type') or '').upper() == 'TXT':
            answers = [self._txt_value(a) for a in answers]
        return sorted(answers)

    def _raw_matches(self, raw, params, weight=True):
        '''Whether an API record already holds the given params.'''
        if raw.get('ttl') != params['ttl']:
            return False
        if self._raw_answers(raw) != sorted(params['answers_list']):
            return False
        if (raw.get('policy') or 'simple') != params['policy']:
            return False
        if params['policy'] != 'simple':
            if weight and self._api_weight(raw) != params['weight']:
                return False
            if (raw.get('description') or '') != params.get('description', ''):
                return False
        return True

    def _converged(self, raws, desired_params):
        '''Whether the API records are equivalent to desired_params: the same
        records and, for weighted ones, the same traffic split.'''
        if len(raws) != len(desired_params):
            return False
        remaining = list(raws)
        weights = []
        for params in desired_params:
            match = next(
                (r for r in remaining if self._raw_matches(r, params, False)),
                None,
            )
            if match is None:
                return False
            remaining.remove(match)
            if params['policy'] != 'simple':
                weights.append((self._api_weight(match), params['weight']))
        # weights are relative, 200/100 splits traffic like 100/50
        have = sum(h for h, _ in weights)
        want = sum(w for _, w in weights)
        return all(
            (h > 0) == (w > 0) and h * want == w * have for h, w in weights
        )

    def _pair(self, raws, desired_params):
        '''Pair desired params with the API records to update, preferring
        records that already hold the same answers. Returns the pairs, the
        params to create and the records to delete.'''
        remaining = list(raws)
        pairs = []
        unpaired = []
        for params in desired_params:
            answers = sorted(params['answers_list'])
            match = next(
                (r for r in remaining if self._raw_answers(r) == answers), None
            )
            if match is None:
                unpaired.append(params)
            else:
                remaining.remove(match)
                pairs.append((match, params))
        # Reuse leftover records for the rest
        while unpaired and remaining:
            pairs.append((remaining.pop(0), unpaired.pop(0)))
        return pairs, unpaired, remaining

    def _simple_operations(self, raws, params):
        if not raws:
            return [('create', params)]

        # Keep, in order of preference, a record that already matches, one
        # Azion answers with and one holding the same answers
        def rank(raw):
            return (
                not self._raw_matches(raw, params),
                not self._is_live(raw),
                self._raw_answers(raw) != sorted(params['answers_list']),
            )

        keep = min(raws, key=rank)
        # A simple record can't coexist with others of the same name and type,
        # so the others go first while the kept record keeps answering
        ops = [('delete', raw) for raw in raws if raw is not keep]
        if not self._raw_matches(keep, params):
            ops.append(('update', keep, params))
        return ops

    def _weighted_operations(self, raws, desired_params):
        ops = []
        params_left = list(desired_params)
        simples = [r for r in raws if not self._is_weighted_record(r)]
        weighted = [r for r in raws if self._is_weighted_record(r)]
        if simples:
            # Weighted records can't be created while a simple record exists,
            # so one simple record is converted first. It gets a value that
            # answers, keeping the name answering. Any other simple records
            # (legacy data only) are deleted before the conversion.
            live = [p for p in desired_params if p['weight'] > 0]
            live = live or desired_params
            keep, target = next(
                (
                    (raw, params)
                    for params in live
                    for raw in simples
                    if self._raw_answers(raw) == sorted(params['answers_list'])
                ),
                (simples[0], live[0]),
            )
            ops.extend(('delete', raw) for raw in simples if raw is not keep)
            ops.append(('update', keep, target))
            params_left.remove(target)

        pairs, creates, deletes = self._pair(weighted, params_left)
        updates = [(r, p) for r, p in pairs if not self._raw_matches(r, p)]
        # Values that answer go before the ones that stop answering, and
        # deletes go last, so the name keeps answering if an operation fails
        for live in (True, False):
            ops.extend(
                ('update', raw, params)
                for raw, params in updates
                if (params['weight'] > 0) == live
            )
            ops.extend(
                ('create', params)
                for params in creates
                if (params['weight'] > 0) == live
            )
        ops.extend(('delete', raw) for raw in deletes)
        return ops

    def _sync_operations(self, raws, desired_params):
        '''The ordered API operations that turn raws into desired_params.'''
        if not desired_params:
            return [('delete', raw) for raw in raws]
        if desired_params[0]['policy'] == 'simple':
            return self._simple_operations(raws, desired_params[0])
        return self._weighted_operations(raws, desired_params)

    def _sync_records(self, zone, name, _type, desired_params):
        '''Reconcile the API records of a name/type with desired_params.

        Existing records are reused through updates where possible, unchanged
        records are left alone and operations are ordered so that the name
        keeps answering throughout, even if one of them fails.
        '''
        zone_id = self._get_zone_id_by_name(zone.name)
        raws = sorted(
            self._raw_records(zone, name, _type), key=lambda r: r['record_id']
        )
        for op in self._sync_operations(raws, desired_params):
            if op[0] == 'create':
                self.log.debug('_sync_records: creating record %s', op[1])
                self._client.record_create(zone_id, op[1])
            elif op[0] == 'update':
                self.log.debug(
                    '_sync_records: updating record %s with params %s',
                    op[1]['record_id'],
                    op[2],
                )
                self._client.record_update(zone_id, op[1]['record_id'], op[2])
            else:
                self.log.debug(
                    '_sync_records: deleting record %s', op[1]['record_id']
                )
                self._client.record_delete(zone_id, op[1]['record_id'])

    def _apply_Create(self, change):
        new = change.new
        self._sync_records(
            new.zone, new.name, new._type, self._desired_params(new)
        )

    def _apply_Update(self, change):
        existing = change.existing
        new = change.new
        self.log.debug(
            '_apply_Update: updating %s %s', existing.fqdn, existing._type
        )
        self._sync_records(
            existing.zone,
            existing.name,
            existing._type,
            self._desired_params(new),
        )

    def _apply_Delete(self, change):
        existing = change.existing
        self._sync_records(existing.zone, existing.name, existing._type, [])

    def _apply(self, plan):
        desired = plan.desired
        changes = plan.changes
        self.log.debug(
            '_apply: zone=%s, len(changes)=%d', desired.name, len(changes)
        )

        try:
            # Check if zone exists, create if it doesn't
            try:
                self._get_zone_id_by_name(desired.name)
            except AzionClientNotFound:
                self.log.debug('_apply:   no matching zone, creating zone')
                zone_name = desired.name.rstrip('.')
                zone = self._client.zone_create(zone_name)
                zone_id = zone.get('id') if isinstance(zone, dict) else None
                if zone_id is not None:
                    self._zone_cache[desired.name] = zone_id
                # A brand new zone has no records
                self._zone_records[desired.name] = []
                self._zone_raw_records[desired.name] = []

            for change in changes:
                class_name = change.__class__.__name__
                getattr(self, f'_apply_{class_name}')(change)
        finally:
            # Clear out the caches to force refresh on next sync, also when
            # the apply failed part way through
            self._zone_records.pop(desired.name, None)
            self._zone_raw_records.pop(desired.name, None)
