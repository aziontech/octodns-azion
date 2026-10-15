'''End-to-end plan -> apply -> plan tests against a stateful fake of the
Azion v3 Intelligent DNS API.

The fake mirrors the behaviour of the v3 API:

* entries are lower-cased on write;
* descriptions of ``simple`` records are always stored empty;
* ``PUT`` defaults ``policy`` to ``simple`` when it is omitted;
* ``weight`` is required for weighted records and only returned for them;
* a ``simple`` record cannot coexist with another record with the same
  name/type, conflicts are 400s with a text error;
* answers are validated like the API does: TTL, ANAME TTL and targets,
  number of answers, hostnames without a trailing dot (so no null MX) and
  the total length of TXT answers;
* TXT answers lose CR and tabs and are split on newlines;
* an empty zone lists as ``results: {}``.
'''

import re
import unittest
from unittest.mock import Mock, patch

from octodns.provider import SupportsException
from octodns.record import Record
from octodns.zone import Zone

from octodns_azion import (
    AzionClient,
    AzionClientBadRequest,
    AzionClientNotFound,
    AzionClientRateLimited,
    AzionProvider,
    AzionUnsupportedRecord,
)

# Hostnames the API accepts
HOSTNAME_RE = re.compile(
    r'(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-_]{0,62}[a-zA-Z0-9]\.)+[a-zA-Z]{2,63}$)'
)
MAX_ANSWERS = {
    'A': 10,
    'AAAA': 10,
    'ANAME': 10,
    'MX': 10,
    'NS': 10,
    'CNAME': 1,
    'PTR': 1,
}
ANAME_SUFFIXES = ('.azioncdn.net', '.azionedge.net', '.azionedge.com')


class FakeAzionClient(object):
    def __init__(self):
        self.zones_data = []
        self.records_data = {}
        self.calls = []
        self.fail_on = {}
        self._next_id = 1000

    # helpers

    def _id(self):
        self._next_id += 1
        return self._next_id

    def add_zone(self, domain):
        zone_id = self._id()
        self.zones_data.append(
            {'id': zone_id, 'name': domain, 'domain': domain, 'is_active': True}
        )
        self.records_data[zone_id] = []
        return zone_id

    def add_raw(self, zone_id, **record):
        '''Store a record as is, e.g. legacy or v4 data the v3 API rejects.'''
        record.setdefault('record_id', self._id())
        record.setdefault('policy', 'simple')
        record.setdefault('description', '')
        self.records_data[zone_id].append(record)
        return record

    def _maybe_fail(self, op):
        remaining = self.fail_on.get(op)
        if remaining is not None:
            if remaining <= 0:
                del self.fail_on[op]
                raise AzionClientBadRequest(details='injected failure')
            self.fail_on[op] = remaining - 1

    def _error(self, message):
        raise AzionClientBadRequest(details={'errors': [message]})

    def _validate(self, params):
        _type = params['record_type']
        ttl = params['ttl']
        answers = params['answers_list']
        if ttl < 1:
            self._error('Invalid TTL')
        if _type == 'ANAME' and ttl != 20:
            self._error('ANAME records must have a TTL of 20')
        if len(answers) > MAX_ANSWERS.get(_type, len(answers)):
            self._error(f'Too many answers for {_type}')
        for answer in answers:
            if _type == 'MX':
                parts = answer.split(' ')
                if (
                    len(parts) != 2
                    or not parts[0].isdigit()
                    or not HOSTNAME_RE.match(parts[1])
                ):
                    self._error('mx_value_validation')
            elif _type in ('ANAME', 'CNAME', 'NS', 'PTR'):
                if not HOSTNAME_RE.match(answer):
                    self._error(f'Invalid {_type} answer')
                if _type == 'ANAME' and not answer.endswith(ANAME_SUFFIXES):
                    self._error('Invalid ANAME target')
        if _type == 'TXT' and not 1 <= len(''.join(answers)) <= 1000:
            self._error('Invalid TXT length')
        if params.get('policy') == 'weighted' and 'weight' not in params:
            self._error('weight is required for weighted records')

    def _store(self, params, record_id):
        self._validate(params)
        policy = params.get('policy', 'simple')
        answers = list(params['answers_list'])
        if params['record_type'] == 'TXT':
            # the API drops CR and tabs and splits on newlines
            answers = [
                part
                for answer in answers
                for part in answer.replace('\r', '')
                .replace('\t', '')
                .split('\n')
                if part
            ]
        record = {
            'record_id': record_id,
            'entry': params.get('entry', '@').lower(),
            'record_type': params['record_type'],
            'ttl': params['ttl'],
            'answers_list': answers,
            'policy': policy,
            'description': (
                '' if policy == 'simple' else params.get('description', '')
            ),
        }
        if policy != 'simple':
            record['weight'] = params['weight']
        return record

    def _check_conflict(self, zone_id, record, ignore_id=None):
        for other in self.records_data[zone_id]:
            if other['record_id'] == ignore_id:
                continue
            if (
                other['entry'].lower() != record['entry']
                or other['record_type'] != record['record_type']
            ):
                continue
            if record['policy'] == 'simple':
                self._error(
                    'There is already another record matching those data.'
                )
            if other['policy'] == 'simple':
                self._error(
                    'There is already a simple policy record matching those '
                    'data.'
                )

    # AzionClient interface

    def zones(self):
        self.calls.append(('zones',))
        return [dict(z) for z in self.zones_data]

    def zone_create(self, name):
        self.calls.append(('zone_create', name))
        zone_id = self.add_zone(name)
        return {'id': zone_id, 'name': name, 'domain': name, 'is_active': True}

    def records(self, zone_id):
        self.calls.append(('records', zone_id))
        if zone_id not in self.records_data:
            raise AzionClientNotFound()
        return [dict(r) for r in self.records_data[zone_id]]

    def _response(self, record):
        response = dict(record)
        response['id'] = response.pop('record_id')
        return {'results': response}

    def record_create(self, zone_id, params):
        self.calls.append(('create', params))
        self._maybe_fail('create')
        record = self._store(params, self._id())
        self._check_conflict(zone_id, record)
        self.records_data[zone_id].append(record)
        return self._response(record)

    def record_update(self, zone_id, record_id, params):
        self.calls.append(('update', record_id, params))
        self._maybe_fail('update')
        record = self._store(params, record_id)
        self._check_conflict(zone_id, record, ignore_id=record_id)
        rows = self.records_data[zone_id]
        for i, row in enumerate(rows):
            if row['record_id'] == record_id:
                rows[i] = record
                return self._response(record)
        raise AzionClientNotFound()

    def record_delete(self, zone_id, record_id):
        self.calls.append(('delete', record_id))
        self._maybe_fail('delete')
        rows = self.records_data[zone_id]
        for i, row in enumerate(rows):
            if row['record_id'] == record_id:
                del rows[i]
                return
        raise AzionClientNotFound()

    def writes(self):
        return [c for c in self.calls if c[0] in ('create', 'update', 'delete')]


ZONE = 'unit.tests.'


class LifecycleTestCase(unittest.TestCase):
    def setUp(self):
        self.fake = FakeAzionClient()
        self.zone_id = self.fake.add_zone('unit.tests')
        self.provider = self.make_provider()

    def make_provider(self, **kwargs):
        provider = AzionProvider('azion', 'token', **kwargs)
        provider._client = self.fake
        return provider

    def desired(self, records):
        zone = Zone(ZONE, [])
        for name, data in records.items():
            for item in data if isinstance(data, list) else [data]:
                zone.add_record(Record.new(zone, name, item))
        return zone

    def sync(self, desired, provider=None):
        provider = provider or self.provider
        plan = provider.plan(desired)
        if plan:
            provider.apply(plan)
        return plan

    def assertConverges(self, desired):
        self.sync(desired)
        # a fresh provider so nothing is served from caches
        plan = self.make_provider().plan(desired)
        self.assertIsNone(plan, plan and plan.changes)

    def raw(self, entry=None, record_type=None):
        return [
            r
            for r in self.fake.records_data[self.zone_id]
            if (entry is None or r['entry'] == entry)
            and (record_type is None or r['record_type'] == record_type)
        ]

    def populate(self, lenient=False, provider=None):
        zone = Zone(ZONE, [])
        (provider or self.make_provider()).populate(zone, lenient=lenient)
        return {(r.name, r._type): r for r in zone.records}


def weighted(values, **extra):
    data = {
        'type': 'A',
        'ttl': 300,
        'values': sorted(v for v, _ in values),
        'dynamic': {
            'pools': {
                'servers': {
                    'values': [{'value': v, 'weight': w} for v, w in values]
                }
            },
            'rules': [{'pool': 'servers'}],
        },
    }
    data.update(extra)
    return data


class TestSimpleRecordsConverge(LifecycleTestCase):
    def test_all_simple_types_converge(self):
        desired = self.desired(
            {
                '': {
                    'type': 'MX',
                    'ttl': 300,
                    'values': [
                        {'preference': 10, 'exchange': 'mx1.unit.tests.'},
                        {'preference': 20, 'exchange': 'mx2.unit.tests.'},
                    ],
                },
                'www': {'type': 'A', 'ttl': 300, 'values': ['1.2.3.4']},
                'v6': {'type': 'AAAA', 'ttl': 300, 'value': '2001:db8::1'},
                'alias': {
                    'type': 'CNAME',
                    'ttl': 300,
                    'value': 'www.unit.tests.',
                },
                'txt': {
                    'type': 'TXT',
                    'ttl': 300,
                    'values': ['v=DMARC1\\; p=reject', 'plain'],
                },
                '_sip._tcp': {
                    'type': 'SRV',
                    'ttl': 300,
                    'value': {
                        'priority': 10,
                        'weight': 20,
                        'port': 5060,
                        'target': 'sip.unit.tests.',
                    },
                },
                'caa': {
                    'type': 'CAA',
                    'ttl': 300,
                    'value': {'flags': 0, 'tag': 'issue', 'value': 'ca.tld'},
                },
                'sub': {
                    'type': 'NS',
                    'ttl': 300,
                    'values': ['ns1.other.tld.', 'ns2.other.tld.'],
                },
                'ptr': {'type': 'PTR', 'ttl': 300, 'value': 'host.unit.tests.'},
            }
        )
        self.assertConverges(desired)

    def test_alias_converges(self):
        self.assertConverges(
            self.desired(
                {
                    '': {
                        'type': 'ALIAS',
                        'ttl': 20,
                        'value': 'xyz.ha.azioncdn.net.',
                    }
                }
            )
        )
        self.assertEqual(
            ['xyz.ha.azioncdn.net'], self.raw('@', 'ANAME')[0]['answers_list']
        )

    def test_update_and_delete_simple(self):
        self.sync(
            self.desired({'www': {'type': 'A', 'ttl': 300, 'value': '1.1.1.1'}})
        )
        record_id = self.raw('www')[0]['record_id']
        self.fake.calls = []

        self.sync(
            self.desired({'www': {'type': 'A', 'ttl': 600, 'value': '2.2.2.2'}})
        )
        self.assertEqual(
            [('update', record_id)], [c[:2] for c in self.fake.writes()]
        )
        self.assertEqual(600, self.raw('www')[0]['ttl'])
        self.assertEqual('simple', self.raw('www')[0]['policy'])

        self.sync(self.desired({}))
        self.assertEqual([], self.raw('www'))

    def test_mixed_case_entries_are_matched(self):
        self.fake.add_raw(
            self.zone_id,
            entry='WWW',
            record_type='A',
            ttl=300,
            answers_list=['1.1.1.1'],
        )
        self.assertConverges(
            self.desired({'www': {'type': 'A', 'ttl': 300, 'value': '2.2.2.2'}})
        )
        self.assertEqual(1, len(self.fake.records_data[self.zone_id]))

        self.sync(self.desired({}))
        self.assertEqual([], self.fake.records_data[self.zone_id])

    def test_duplicate_legacy_records_are_merged_and_cleaned(self):
        for value in ('v=spf1 -all', 'other'):
            self.fake.add_raw(
                self.zone_id,
                entry='@',
                record_type='TXT',
                ttl=300,
                answers_list=[value],
            )
        txt = self.populate()[('', 'TXT')]
        self.assertEqual(['other', 'v=spf1 -all'], sorted(txt.values))

        self.assertConverges(
            self.desired({'': {'type': 'TXT', 'ttl': 300, 'value': 'new'}})
        )
        self.assertEqual(1, len(self.raw('@', 'TXT')))


class TestDynamicRecordsConverge(LifecycleTestCase):
    def test_weighted_converges(self):
        for values in (
            [('1.1.1.1', 10), ('2.2.2.2', 5)],
            [('1.1.1.1', 16), ('2.2.2.2', 100)],
            [('1.1.1.1', 1), ('2.2.2.2', 15)],
        ):
            desired = self.desired({'lb': weighted(values)})
            self.assertConverges(desired)
            weights = {
                r['answers_list'][0]: r['weight'] for r in self.raw('lb')
            }
            self.assertEqual(dict(values), weights)

    def test_weighted_with_status_up_converges(self):
        data = weighted([('1.1.1.1', 10), ('2.2.2.2', 5)])
        for value in data['dynamic']['pools']['servers']['values']:
            value['status'] = 'up'
        self.assertConverges(self.desired({'lb': data}))

    def test_down_value_is_written_with_weight_zero(self):
        data = weighted([('1.1.1.1', 10), ('2.2.2.2', 5)])
        data['dynamic']['pools']['servers']['values'][1]['status'] = 'down'
        self.assertConverges(self.desired({'lb': data}))
        weights = {r['answers_list'][0]: r['weight'] for r in self.raw('lb')}
        self.assertEqual({'1.1.1.1': 10, '2.2.2.2': 0}, weights)

    def test_weight_zero_is_read_as_down(self):
        for answer, weight in (('1.1.1.1', 0), ('2.2.2.2', 50)):
            self.fake.add_raw(
                self.zone_id,
                entry='lb',
                record_type='A',
                ttl=300,
                answers_list=[answer],
                policy='weighted',
                weight=weight,
            )
        record = self.populate()[('lb', 'A')]
        values = {
            v['value']: (v['weight'], v['status'])
            for v in record.dynamic.pools['weighted'].data['values']
        }
        self.assertEqual(
            {'1.1.1.1': (1, 'down'), '2.2.2.2': (50, 'obey')}, values
        )

        # a populated zone can be pushed back without losing the down state
        self.fake.calls = []
        desired = Zone(ZONE, [])
        desired.add_record(record.copy(zone=desired))
        self.assertIsNone(self.make_provider().plan(desired))

    def test_single_weighted_record_populates_strictly(self):
        self.fake.add_raw(
            self.zone_id,
            entry='lb',
            record_type='A',
            ttl=300,
            answers_list=['1.1.1.1'],
            policy='weighted',
            weight=255,
        )
        record = self.populate(lenient=False)[('lb', 'A')]
        self.assertEqual(
            1, record.dynamic.pools['weighted'].data['values'][0]['weight']
        )

    def test_weight_above_octodns_range_is_scaled(self):
        for answer, weight in (('1.1.1.1', 255), ('2.2.2.2', 10)):
            self.fake.add_raw(
                self.zone_id,
                entry='lb',
                record_type='A',
                ttl=300,
                answers_list=[answer],
                policy='weighted',
                weight=weight,
            )
        record = self.populate()[('lb', 'A')]
        weights = {
            v['value']: v['weight']
            for v in record.dynamic.pools['weighted'].data['values']
        }
        # proportions are kept, 255:10 ~ 100:4
        self.assertEqual({'1.1.1.1': 100, '2.2.2.2': 4}, weights)

    def test_weighted_cname_converges(self):
        desired = self.desired(
            {
                'cdn': {
                    'type': 'CNAME',
                    'ttl': 300,
                    'value': 'z.unit.tests.',
                    'dynamic': {
                        'pools': {
                            'p': {
                                'values': [
                                    {'value': 'a.unit.tests.', 'weight': 3},
                                    {'value': 'b.unit.tests.', 'weight': 1},
                                ]
                            }
                        },
                        'rules': [{'pool': 'p'}],
                    },
                }
            }
        )
        self.assertConverges(desired)
        self.assertEqual(2, len(self.raw('cdn', 'CNAME')))

    def test_geo_rules_are_rejected_when_strict(self):
        data = weighted([('1.1.1.1', 1)])
        data['dynamic']['pools']['us'] = {
            'values': [{'value': '3.3.3.3'}],
            'fallback': 'servers',
        }
        data['dynamic']['rules'] = [
            {'geos': ['NA-US'], 'pool': 'us'},
            {'pool': 'servers'},
        ]
        desired = self.desired({'lb': data})
        with self.assertRaises(SupportsException):
            self.provider.plan(desired)

    def test_geo_rules_fall_back_to_default_pool_when_lenient(self):
        data = weighted([('1.1.1.1', 2), ('2.2.2.2', 1)])
        data['dynamic']['pools']['us'] = {
            'values': [{'value': '3.3.3.3'}],
            'fallback': 'servers',
        }
        data['dynamic']['rules'] = [
            {'geos': ['NA-US'], 'pool': 'us'},
            {'pool': 'servers'},
        ]
        desired = self.desired({'lb': data})
        provider = self.make_provider(strict_supports=False)
        self.sync(desired, provider=provider)
        self.assertIsNone(
            self.make_provider(strict_supports=False).plan(desired)
        )
        self.assertEqual(
            ['1.1.1.1', '2.2.2.2'],
            sorted(r['answers_list'][0] for r in self.raw('lb')),
        )

    def test_simple_to_weighted_and_back(self):
        self.assertConverges(
            self.desired({'lb': {'type': 'A', 'ttl': 300, 'value': '1.1.1.1'}})
        )
        self.assertConverges(
            self.desired({'lb': weighted([('1.1.1.1', 3), ('2.2.2.2', 1)])})
        )
        self.assertEqual({'weighted'}, {r['policy'] for r in self.raw('lb')})
        self.assertConverges(
            self.desired(
                {
                    'lb': {
                        'type': 'A',
                        'ttl': 300,
                        'values': ['1.1.1.1', '2.2.2.2'],
                    }
                }
            )
        )
        self.assertEqual(
            [('simple', ['1.1.1.1', '2.2.2.2'])],
            [(r['policy'], sorted(r['answers_list'])) for r in self.raw('lb')],
        )

    def test_unchanged_values_are_not_rewritten(self):
        self.sync(
            self.desired({'lb': weighted([('1.1.1.1', 3), ('2.2.2.2', 1)])})
        )
        before = {r['answers_list'][0]: r['record_id'] for r in self.raw('lb')}
        self.fake.calls = []
        self.sync(
            self.desired(
                {
                    'lb': weighted(
                        [('1.1.1.1', 3), ('2.2.2.2', 1), ('3.3.3.3', 1)]
                    )
                }
            )
        )
        self.assertEqual(['create'], [c[0] for c in self.fake.writes()])
        after = {r['answers_list'][0]: r['record_id'] for r in self.raw('lb')}
        self.assertEqual(before['1.1.1.1'], after['1.1.1.1'])
        self.assertEqual(before['2.2.2.2'], after['2.2.2.2'])

    def live(self, entry):
        return sorted(
            a
            for r in self.raw(entry)
            if r['policy'] == 'simple' or r['weight'] > 0
            for a in r['answers_list']
        )

    def test_failed_create_after_updates_keeps_answering(self):
        self.sync(
            self.desired({'lb': weighted([('1.1.1.1', 3), ('2.2.2.2', 1)])})
        )
        self.fake.calls = []
        self.fake.fail_on['create'] = 0
        with self.assertRaises(AzionClientBadRequest):
            self.sync(
                self.desired(
                    {
                        'lb': weighted(
                            [('5.5.5.5', 3), ('6.6.6.6', 1), ('7.7.7.7', 1)]
                        )
                    }
                )
            )
        # both updates went through before the create failed
        self.assertEqual(
            ['update', 'update', 'create'], [c[0] for c in self.fake.writes()]
        )
        self.assertEqual(['5.5.5.5', '6.6.6.6'], self.live('lb'))

    def test_values_are_activated_before_others_are_deactivated(self):
        for answer, weight in (('1.1.1.1', 5), ('2.2.2.2', 0)):
            self.fake.add_raw(
                self.zone_id,
                entry='lb',
                record_type='A',
                ttl=300,
                answers_list=[answer],
                policy='weighted',
                weight=weight,
            )
        data = weighted([('3.3.3.3', 1), ('4.4.4.4', 1)])
        data['dynamic']['pools']['servers']['values'][0]['status'] = 'down'
        # the second update fails
        self.fake.fail_on['update'] = 1
        with self.assertRaises(AzionClientBadRequest):
            self.sync(self.desired({'lb': data}))
        self.assertEqual(['1.1.1.1', '4.4.4.4'], self.live('lb'))

        self.assertConverges(self.desired({'lb': data}))
        self.assertEqual(['4.4.4.4'], self.live('lb'))

    def test_weighted_to_simple_keeps_an_answering_record(self):
        for answer, weight in (('1.1.1.1', 0), ('2.2.2.2', 5)):
            self.fake.add_raw(
                self.zone_id,
                entry='lb',
                record_type='A',
                ttl=300,
                answers_list=[answer],
                policy='weighted',
                weight=weight,
            )
        down, live = [r['record_id'] for r in self.raw('lb')]
        self.assertConverges(
            self.desired({'lb': {'type': 'A', 'ttl': 300, 'value': '1.1.1.1'}})
        )
        self.assertEqual(
            [('delete', down), ('update', live)],
            [c[:2] for c in self.fake.writes()],
        )

    def test_legacy_simple_records_are_converted_to_weighted(self):
        # several simple records for a name/type, the v3 API no longer allows
        # creating them
        for answer in ('1.1.1.1', '2.2.2.2'):
            self.fake.add_raw(
                self.zone_id,
                entry='lb',
                record_type='A',
                ttl=300,
                answers_list=[answer],
            )
        self.assertEqual(
            ['1.1.1.1', '2.2.2.2'], list(self.populate()[('lb', 'A')].values)
        )
        self.assertConverges(
            self.desired({'lb': weighted([('1.1.1.1', 3), ('2.2.2.2', 1)])})
        )
        self.assertEqual(
            {'1.1.1.1': 3, '2.2.2.2': 1},
            {r['answers_list'][0]: r['weight'] for r in self.raw('lb')},
        )

    def test_description_change_is_planned_for_weighted(self):
        def with_desc(desc):
            data = weighted([('1.1.1.1', 3), ('2.2.2.2', 1)])
            data['octodns'] = {'azion': {'descriptions': {'1.1.1.1': desc}}}
            return self.desired({'lb': data})

        self.assertConverges(with_desc('primary'))
        self.assertConverges(with_desc('main'))
        descs = {r['answers_list'][0]: r['description'] for r in self.raw('lb')}
        self.assertEqual({'1.1.1.1': 'main', '2.2.2.2': ''}, descs)


class TestUnrepresentableRecords(LifecycleTestCase):
    def test_weighted_mx_does_not_break_populate(self):
        for answer, weight in (
            ('10 mx1.unit.tests', 10),
            ('20 mx2.unit.tests', 5),
        ):
            self.fake.add_raw(
                self.zone_id,
                entry='@',
                record_type='MX',
                ttl=300,
                answers_list=[answer],
                policy='weighted',
                weight=weight,
            )
        self.fake.add_raw(
            self.zone_id,
            entry='www',
            record_type='A',
            ttl=300,
            answers_list=['1.1.1.1'],
        )
        for lenient in (False, True):
            records = self.populate(lenient=lenient)
            self.assertEqual(
                ['mx1.unit.tests.', 'mx2.unit.tests.'],
                sorted(v.exchange for v in records[('', 'MX')].values),
            )
            self.assertIn(('www', 'A'), records)

    def test_weighted_aname_keeps_all_targets_visible(self):
        for answer in ('a.ha.azioncdn.net', 'b.ha.azioncdn.net'):
            self.fake.add_raw(
                self.zone_id,
                entry='@',
                record_type='ANAME',
                ttl=20,
                answers_list=[answer],
                policy='weighted',
                weight=1,
            )
        with self.assertLogs('AzionProvider[azion]', 'WARNING') as logs:
            record = self.populate()[('', 'ALIAS')]
        self.assertEqual('a.ha.azioncdn.net.', record.value)
        self.assertTrue(any('b.ha.azioncdn.net' in m for m in logs.output))


class TestZoneHandling(LifecycleTestCase):
    def test_missing_zone_is_created_once(self):
        self.fake.zones_data = []
        desired = self.desired(
            {'www': {'type': 'A', 'ttl': 300, 'value': '1.1.1.1'}}
        )
        self.sync(desired)
        self.assertEqual(
            1, len([c for c in self.fake.calls if c[0] == 'zone_create'])
        )
        # the id returned on creation is used, zones aren't listed again
        ops = [c[0] for c in self.fake.calls]
        self.assertNotIn('zones', ops[ops.index('zone_create') :])
        self.assertEqual(1, len(self.fake.zones_data))
        self.assertConverges(desired)

    def test_zone_lookup_ignores_case_and_trailing_dot(self):
        self.fake.zones_data[0]['domain'] = 'UNIT.Tests.'
        self.assertEqual(self.zone_id, self.provider._get_zone_id_by_name(ZONE))
        self.assertEqual([ZONE], self.provider.list_zones())

    def test_records_404_is_not_treated_as_missing_zone(self):
        del self.fake.records_data[self.zone_id]
        with self.assertRaises(AzionClientNotFound):
            self.provider.populate(Zone(ZONE, []))

    def test_caches_are_cleared_after_failed_apply(self):
        desired = self.desired(
            {
                'a': {'type': 'A', 'ttl': 300, 'value': '1.1.1.1'},
                'b': {'type': 'A', 'ttl': 300, 'value': '2.2.2.2'},
            }
        )
        plan = self.provider.plan(desired)
        self.fake.fail_on['create'] = 1
        with self.assertRaises(AzionClientBadRequest):
            self.provider.apply(plan)
        self.assertNotIn(ZONE, self.provider._zone_records)
        self.assertNotIn(ZONE, self.provider._zone_raw_records)


class TestClientRobustness(unittest.TestCase):
    def response(self, status, headers=None, body=None):
        resp = Mock()
        resp.status_code = status
        resp.headers = headers or {}
        resp.json.return_value = body or {}
        return resp

    @patch('octodns_azion.time.sleep')
    @patch('octodns_azion.Session')
    def test_retries_rate_limited_requests(self, session, sleep):
        sess = session.return_value
        sess.request.side_effect = [
            self.response(429, {'Retry-After': '3'}),
            self.response(429, {}),
            self.response(200),
        ]
        client = AzionClient('token', timeout=7)
        self.assertEqual(200, client._request('GET', '/x').status_code)
        self.assertEqual(3, sess.request.call_count)
        self.assertEqual(7, sess.request.call_args.kwargs['timeout'])
        self.assertEqual(3, sleep.call_args_list[0].args[0])

    @patch('octodns_azion.time.sleep')
    @patch('octodns_azion.Session')
    def test_rate_limit_reset_header(self, session, sleep):
        sess = session.return_value
        sess.request.side_effect = [
            self.response(429, {'X-RateLimit-Reset': '2000-01-01T00:00:00'}),
            self.response(200),
        ]
        AzionClient('token')._request('GET', '/x')
        # a reset time in the past waits the minimum
        self.assertEqual(1, sleep.call_args.args[0])

    @patch('octodns_azion.time.sleep')
    @patch('octodns_azion.Session')
    def test_gives_up_after_max_retries(self, session, sleep):
        sess = session.return_value
        sess.request.return_value = self.response(429)
        client = AzionClient('token', max_retries=2)
        with self.assertRaises(AzionClientRateLimited):
            client._request('GET', '/x')
        self.assertEqual(3, sess.request.call_count)

    @patch('octodns_azion.Session')
    def test_zone_create_returns_zone(self, session):
        sess = session.return_value
        sess.request.return_value = self.response(
            201, body={'results': [{'id': 42, 'domain': 'unit.tests'}]}
        )
        self.assertEqual(
            42, AzionClient('token').zone_create('unit.tests')['id']
        )


class TestReconcileEdgeCases(LifecycleTestCase):
    def test_shrinking_weighted_deletes_after_updates(self):
        self.sync(
            self.desired(
                {
                    'lb': weighted(
                        [('1.1.1.1', 3), ('2.2.2.2', 1), ('3.3.3.3', 1)]
                    )
                }
            )
        )
        self.fake.calls = []
        self.assertConverges(
            self.desired({'lb': weighted([('1.1.1.1', 3), ('4.4.4.4', 1)])})
        )
        ops = [c[0] for c in self.fake.writes()]
        self.assertEqual(['update', 'delete'], ops)
        self.assertEqual(2, len(self.raw('lb')))

    def test_matching_duplicate_is_kept_and_others_deleted(self):
        for value in ('new', 'other'):
            self.fake.add_raw(
                self.zone_id,
                entry='@',
                record_type='TXT',
                ttl=300,
                answers_list=[value],
            )
        self.sync(
            self.desired({'': {'type': 'TXT', 'ttl': 300, 'value': 'new'}})
        )
        self.assertEqual(['delete'], [c[0] for c in self.fake.writes()])
        self.assertEqual(['new'], self.raw('@', 'TXT')[0]['answers_list'])

    def test_duplicate_answers_are_merged(self):
        for _ in range(2):
            self.fake.add_raw(
                self.zone_id,
                entry='@',
                record_type='TXT',
                ttl=300,
                answers_list=['same'],
            )
        self.assertEqual(['same'], self.populate()[('', 'TXT')].values)

    def test_missing_weight_uses_api_default(self):
        for answer in ('1.1.1.1', '2.2.2.2'):
            self.fake.add_raw(
                self.zone_id,
                entry='lb',
                record_type='A',
                ttl=300,
                answers_list=[answer],
                policy='weighted',
            )
        record = self.populate()[('lb', 'A')]
        weights = [
            v['weight'] for v in record.dynamic.pools['weighted'].data['values']
        ]
        self.assertEqual([100, 100], weights)

    def test_zone_create_without_id_looks_the_zone_up(self):
        self.fake.zones_data = []
        create = self.fake.zone_create

        def zone_create(name):
            create(name)
            return {}

        self.fake.zone_create = zone_create
        self.sync(
            self.desired({'www': {'type': 'A', 'ttl': 300, 'value': '1.1.1.1'}})
        )
        zone_id = self.fake.zones_data[0]['id']
        self.assertEqual(1, len(self.fake.records_data[zone_id]))


class TestRetryWait(unittest.TestCase):
    def setUp(self):
        self.client = AzionClient('token')

    def wait(self, headers, attempt=0):
        resp = Mock()
        resp.headers = headers
        return self.client._retry_wait(resp, attempt)

    def test_invalid_headers_fall_back_to_backoff(self):
        headers = {'Retry-After': 'soon', 'X-RateLimit-Reset': 'later'}
        self.assertEqual(4, self.wait(headers, attempt=2))

    def test_timezone_aware_reset_is_capped(self):
        headers = {'X-RateLimit-Reset': '2999-01-01T00:00:00+00:00'}
        self.assertEqual(AzionClient.MAX_RETRY_WAIT, self.wait(headers))


class TestPreflight(LifecycleTestCase):
    def assertRejected(self, records, message):
        desired = Zone(ZONE, [])
        for name, data in records.items():
            desired.add_record(Record.new(desired, name, data, lenient=True))
        with self.assertRaises(AzionUnsupportedRecord) as ctx:
            self.provider.plan(desired)
        self.assertIn(message, str(ctx.exception))
        self.assertEqual([], self.fake.writes())

    def test_null_mx_is_rejected(self):
        self.assertRejected(
            {
                '': {
                    'type': 'MX',
                    'ttl': 300,
                    'value': {'preference': 0, 'exchange': '.'},
                }
            },
            'null MX',
        )

    def test_limits_are_checked_while_planning(self):
        for records, message in (
            (
                {
                    'a': {
                        'type': 'A',
                        'ttl': 300,
                        'values': [f'1.1.1.{i}' for i in range(11)],
                    }
                },
                'at most 10 values',
            ),
            ({'a': {'type': 'A', 'ttl': 0, 'value': '1.1.1.1'}}, 'ttl'),
            (
                {'a': {'type': 'AAAA', 'ttl': 300, 'value': '2001:db8::'}},
                'ends in "::"',
            ),
            (
                {'t': {'type': 'TXT', 'ttl': 300, 'values': ['a' * 600] * 2}},
                '1200 characters',
            ),
            ({'t': {'type': 'TXT', 'ttl': 300, 'value': 'a\nb'}}, 'newlines'),
            (
                {
                    'c': {
                        'type': 'CAA',
                        'ttl': 300,
                        'value': {'flags': 1, 'tag': 'issue', 'value': 'ca'},
                    }
                },
                'flags',
            ),
            (
                {
                    'c': {
                        'type': 'CAA',
                        'ttl': 300,
                        'value': {'flags': 0, 'tag': 'issue', 'value': 'c,a'},
                    }
                },
                'unsupported characters',
            ),
            (
                {'': {'type': 'ALIAS', 'ttl': 20, 'value': 'other.tld.'}},
                'ANAME target',
            ),
        ):
            self.assertRejected(records, message)

    def test_long_descriptions_are_rejected(self):
        data = weighted([('1.1.1.1', 1), ('2.2.2.2', 1)])
        data['octodns'] = {'azion': {'descriptions': {'1.1.1.1': 'x' * 46}}}
        self.assertRejected({'lb': data}, 'longer than 45')

    def test_alias_ttl_must_be_20(self):
        desired = self.desired(
            {'': {'type': 'ALIAS', 'ttl': 300, 'value': 'x.azionedge.net.'}}
        )
        with self.assertRaises(SupportsException):
            self.provider.plan(desired)

        self.sync(desired, provider=self.make_provider(strict_supports=False))
        self.assertEqual(20, self.raw('@', 'ANAME')[0]['ttl'])
        self.assertIsNone(
            self.make_provider(strict_supports=False).plan(desired)
        )


class TestStoredState(LifecycleTestCase):
    '''Records whose API state differs in ways octoDNS doesn't compare.'''

    def add_weighted(self, entry, *records, record_type='A'):
        for answers, weight, ttl in records:
            self.fake.add_raw(
                self.zone_id,
                entry=entry,
                record_type=record_type,
                ttl=ttl,
                answers_list=answers,
                policy='weighted',
                weight=weight,
            )

    def test_non_root_aname_is_left_alone(self):
        self.fake.add_raw(
            self.zone_id,
            entry='www',
            record_type='ANAME',
            ttl=20,
            answers_list=['x.azionedge.net'],
        )
        for lenient in (False, True):
            self.assertEqual({}, self.populate(lenient=lenient))
        self.assertIsNone(self.provider.plan(self.desired({})))

    def test_quoted_txt_is_not_read_as_chunks(self):
        self.fake.add_raw(
            self.zone_id,
            entry='@',
            record_type='TXT',
            ttl=300,
            answers_list=['"foo" "bar"', 'a;b'],
        )
        txt = self.populate()[('', 'TXT')]
        self.assertEqual([r'\"foo\" \"bar\"', r'a\;b'], sorted(txt.values))
        # the escaped form of a stored answer is the same answer
        self.assertIsNone(
            self.provider.plan(
                self.desired(
                    {
                        '': {
                            'type': 'TXT',
                            'ttl': 300,
                            'values': [r'\"foo\" \"bar\"', r'a\;b'],
                        }
                    }
                )
            )
        )
        self.assertConverges(
            self.desired({'': {'type': 'TXT', 'ttl': 300, 'value': 'foobar'}})
        )
        self.assertEqual(['foobar'], self.raw('@', 'TXT')[0]['answers_list'])

    def test_double_escaped_backslash_is_kept(self):
        self.fake.add_raw(
            self.zone_id,
            entry='@',
            record_type='TXT',
            ttl=300,
            answers_list=[r'a\\;b'],
        )
        # an escaped backslash followed by a ; that still needs escaping
        txt = self.populate(lenient=True)[('', 'TXT')]
        self.assertEqual([r'a\\\;b'], txt.values)

    def test_traffic_split_is_compared(self):
        self.add_weighted(
            'lb', (['1.1.1.1'], 200, 300), (['2.2.2.2'], 100, 300)
        )
        # the same split, 200:100 is 100:50
        self.assertIsNone(
            self.provider.plan(
                self.desired(
                    {'lb': weighted([('1.1.1.1', 100), ('2.2.2.2', 50)])}
                )
            )
        )
        desired = self.desired(
            {'lb': weighted([('1.1.1.1', 100), ('2.2.2.2', 100)])}
        )
        self.assertIsNotNone(self.make_provider().plan(desired))
        self.assertConverges(desired)
        self.assertEqual({100}, {r['weight'] for r in self.raw('lb')})

    def test_per_record_ttls_are_compared(self):
        self.add_weighted('lb', (['1.1.1.1'], 1, 300), (['2.2.2.2'], 1, 600))
        desired = self.desired(
            {'lb': weighted([('1.1.1.1', 1), ('2.2.2.2', 1)])}
        )
        self.assertIsNotNone(self.provider.plan(desired))
        self.assertConverges(desired)
        self.assertEqual({300}, {r['ttl'] for r in self.raw('lb')})

    def test_grouped_weighted_answers_are_split(self):
        self.add_weighted('lb', (['1.1.1.1', '2.2.2.2'], 1, 300))
        with self.assertLogs('AzionProvider[azion]', 'WARNING') as logs:
            record = self.populate()[('lb', 'A')]
        self.assertTrue(any('together' in m for m in logs.output))
        self.assertEqual(['1.1.1.1', '2.2.2.2'], list(record.values))

        desired = self.desired(
            {'lb': weighted([('1.1.1.1', 1), ('2.2.2.2', 1)])}
        )
        self.assertIsNotNone(self.make_provider().plan(desired))
        self.assertConverges(desired)
        self.assertEqual(2, len(self.raw('lb')))

    def test_removed_description_is_planned(self):
        self.add_weighted(
            'cdn',
            (['A.UNIT.TESTS'], 1, 300),
            (['b.unit.tests'], 1, 300),
            record_type='CNAME',
        )
        self.fake.records_data[self.zone_id][0]['description'] = 'old'
        desired = self.desired(
            {
                'cdn': {
                    'type': 'CNAME',
                    'ttl': 300,
                    'value': 'a.unit.tests.',
                    'dynamic': {
                        'pools': {
                            'p': {
                                'values': [
                                    {'value': 'a.unit.tests.'},
                                    {'value': 'b.unit.tests.'},
                                ]
                            }
                        },
                        'rules': [{'pool': 'p'}],
                    },
                }
            }
        )
        self.assertIsNotNone(self.provider.plan(desired))
        self.assertConverges(desired)
        self.assertEqual({''}, {r['description'] for r in self.raw('cdn')})

    def test_duplicate_records_are_consolidated(self):
        for _ in range(2):
            self.fake.add_raw(
                self.zone_id,
                entry='@',
                record_type='TXT',
                ttl=300,
                answers_list=['same'],
            )
        desired = self.desired(
            {'': {'type': 'TXT', 'ttl': 300, 'value': 'same'}}
        )
        self.assertIsNotNone(self.provider.plan(desired))
        self.assertConverges(desired)
        self.assertEqual(1, len(self.raw('@', 'TXT')))

    def test_lossy_reads_are_not_forced(self):
        self.add_weighted(
            '@',
            (['10 mx1.unit.tests'], 10, 300),
            (['20 mx2.unit.tests'], 5, 300),
            record_type='MX',
        )
        self.fake.add_raw(
            self.zone_id,
            entry='@',
            record_type='ANAME',
            ttl=20,
            answers_list=['a.azionedge.net', 'b.azionedge.net'],
        )
        desired = self.desired(
            {
                '': [
                    {
                        'type': 'MX',
                        'ttl': 300,
                        'values': [
                            {'preference': 10, 'exchange': 'mx1.unit.tests.'},
                            {'preference': 20, 'exchange': 'mx2.unit.tests.'},
                        ],
                    },
                    {'type': 'ALIAS', 'ttl': 20, 'value': 'a.azionedge.net.'},
                ]
            }
        )
        self.assertIsNone(self.provider.plan(desired))


class TestZoneCreateName(unittest.TestCase):
    @patch('octodns_azion.Session')
    def test_long_domains_get_a_short_name(self, session):
        sess = session.return_value
        resp = Mock()
        resp.status_code = 201
        resp.json.return_value = {'results': [{'id': 1}]}
        sess.request.return_value = resp
        domain = f'{"a" * 48}.com'
        AzionClient('token').zone_create(domain)
        data = sess.request.call_args.kwargs['json']
        self.assertEqual(domain, data['domain'])
        self.assertEqual(domain[:50], data['name'])
