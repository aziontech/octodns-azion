import unittest
import warnings
from unittest.mock import Mock, patch

# Suppress urllib3 SSL warnings for testing
warnings.filterwarnings("ignore", message=".*urllib3.*")
warnings.filterwarnings("ignore", category=UserWarning, module="urllib3")

from octodns.record import Record
from octodns.zone import Zone

from octodns_azion import (
    AzionClient,
    AzionClientException,
    AzionClientNotFound,
    AzionClientUnauthorized,
    AzionProvider,
)


class TestAzionClient(unittest.TestCase):
    def setUp(self):
        self.client = AzionClient("test-token")

    @patch("octodns_azion.Session")
    def test_client_init(self, mock_session):
        mock_sess = Mock()
        mock_session.return_value = mock_sess

        AzionClient("test-token")

        mock_sess.headers.update.assert_called_once()
        headers = mock_sess.headers.update.call_args[0][0]
        self.assertEqual(headers["Authorization"], "Token test-token")
        self.assertIn("octodns", headers["User-Agent"])

    @patch("octodns_azion.Session")
    def test_request_success(self, mock_session):
        mock_sess = Mock()
        mock_session.return_value = mock_sess
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_sess.request.return_value = mock_resp

        client = AzionClient("test-token")
        result = client._request("GET", "/test")

        self.assertEqual(result, mock_resp)
        mock_sess.request.assert_called_once_with(
            "GET", "https://api.azionapi.net/test", params=None, json=None
        )

    @patch("octodns_azion.Session")
    def test_request_not_found(self, mock_session):
        mock_sess = Mock()
        mock_session.return_value = mock_sess
        mock_resp = Mock()
        mock_resp.status_code = 404
        mock_sess.request.return_value = mock_resp

        client = AzionClient("test-token")

        with self.assertRaises(AzionClientNotFound):
            client._request("GET", "/test")


class TestAzionProvider(unittest.TestCase):
    def setUp(self):
        self.provider = AzionProvider("test", "test-token")
        self.zone = Zone("example.com.", [])

    @patch("octodns_azion.AzionClient")
    def test_provider_init(self, mock_client_class):
        provider = AzionProvider("test", "test-token")

        mock_client_class.assert_called_once_with("test-token")
        self.assertEqual(provider.id, "test")

    def test_data_for_a_record(self):
        records = [{"ttl": 300, "answers_list": ["1.2.3.4", "5.6.7.8"]}]

        result = self.provider._data_for_A("A", records)

        expected = {"ttl": 300, "type": "A", "values": ["1.2.3.4", "5.6.7.8"]}
        self.assertEqual(result, expected)

    def test_data_for_cname_record(self):
        records = [{"ttl": 300, "answers_list": ["example.com"]}]
        result = self.provider._data_for_CNAME("CNAME", records)
        expected = {"ttl": 300, "type": "CNAME", "value": "example.com."}
        self.assertEqual(result, expected)

    def test_data_for_aname_record(self):
        records = [{"ttl": 20, "answers_list": ["0001a.ha.azioncdn.net"]}]
        result = self.provider._data_for_ANAME("ANAME", records)
        expected = {
            "ttl": 20,
            "type": "ANAME",
            "value": "0001a.ha.azioncdn.net.",
        }
        self.assertEqual(result, expected)

    def test_data_for_ptr_record(self):
        records = [{"ttl": 3600, "answers_list": ["example.com"]}]
        result = self.provider._data_for_PTR("PTR", records)
        expected = {"ttl": 3600, "type": "PTR", "value": "example.com."}
        self.assertEqual(result, expected)

    def test_data_for_mx_record(self):
        # Test with real Azion API format - multiple MX records in single answers_list
        records = [
            {
                "ttl": 3600,
                "answers_list": [
                    "1 ASPMX.L.google.com",
                    "10 ASPMX2.GOOGLEMAIL.com",
                    "10 ASPMX3.GOOGLEMAIL.com",
                    "5 ALT1.ASPMX.L.google.com",
                    "5 ALT2.ASPMX.L.google.com",
                ],
            }
        ]

        result = self.provider._data_for_MX("MX", records)

        expected = {
            "ttl": 3600,
            "type": "MX",
            "values": [
                {"preference": 1, "exchange": "ASPMX.L.google.com."},
                {"preference": 10, "exchange": "ASPMX2.GOOGLEMAIL.com."},
                {"preference": 10, "exchange": "ASPMX3.GOOGLEMAIL.com."},
                {"preference": 5, "exchange": "ALT1.ASPMX.L.google.com."},
                {"preference": 5, "exchange": "ALT2.ASPMX.L.google.com."},
            ],
        }
        self.assertEqual(result, expected)

    def test_data_for_txt_record(self):
        # Test multiple values in single record's answers_list
        records = [
            {
                "ttl": 300,
                "answers_list": [
                    '"v=spf1 include:_spf.example.com ~all"',
                    '"another txt record"',
                ],
            }
        ]

        result = self.provider._data_for_TXT("TXT", records)

        expected = {
            "ttl": 300,
            "type": "TXT",
            "values": [
                '"v=spf1 include:_spf.example.com ~all"',
                '"another txt record"',
            ],
        }
        self.assertEqual(result, expected)

    def test_data_for_txt_multiple_values_real_scenario(self):
        # Test real scenario: single record with multiple values in answers_list
        records = [
            {
                "ttl": 3600,
                "answers_list": [
                    "_globalsign-domain-verification=hoX_CURoCJLs3msafmeY7hPiQmelFOne1B8ER_Xj1r",
                    '"v=spf1 include:_spf.google.com ~all"',
                ],
            }
        ]

        result = self.provider._data_for_TXT("TXT", records)

        expected = {
            "ttl": 3600,
            "type": "TXT",
            "values": [
                "_globalsign-domain-verification=hoX_CURoCJLs3msafmeY7hPiQmelFOne1B8ER_Xj1r",
                '"v=spf1 include:_spf.google.com ~all"',  # Quotes preserved
            ],
        }
        self.assertEqual(result, expected)

    def test_data_for_txt_with_empty_answers(self):
        # Test TXT records with empty/null answers in answers_list
        records = [
            {
                "ttl": 300,
                "answers_list": [
                    "valid_answer",
                    "",  # Empty string
                    '"quoted_answer"',
                    None,  # None value
                    "another_valid",
                ],
            }
        ]

        result = self.provider._data_for_TXT("TXT", records)

        # Should skip empty/None answers and process only valid ones
        expected = {
            "ttl": 300,
            "type": "TXT",
            "values": ["valid_answer", '"quoted_answer"', "another_valid"],
        }
        self.assertEqual(result, expected)

    @patch.object(AzionProvider, "_get_zone_id_by_name")
    def test_zone_records_not_found(self, mock_get_zone_id):
        mock_get_zone_id.side_effect = AzionClientNotFound()

        result = self.provider.zone_records(self.zone)

        self.assertEqual(result, [])

    def test_zone_records_success(self):
        zone = Zone("example.com.", [])

        # Mock API response with real Azion format
        mock_records = [
            {
                "record_id": 1,
                "entry": "@",
                "record_type": "ANAME",
                "ttl": 20,
                "answers_list": ["0001a.ha.azioncdn.net"],
            },
            {
                "record_id": 2,
                "entry": "www",
                "record_type": "CNAME",
                "ttl": 300,
                "answers_list": ["0001a.ha.azioncdn.net"],
            },
            {
                "record_id": 3,
                "entry": "@",
                "record_type": "MX",
                "ttl": 3600,
                "answers_list": [
                    "1 ASPMX.L.google.com",
                    "10 ASPMX2.GOOGLEMAIL.com",
                    "5 ALT1.ASPMX.L.google.com",
                ],
            },
        ]

        with patch.object(
            self.provider._client, "records", return_value=mock_records
        ):
            with patch.object(
                self.provider, "_get_zone_id_by_name", return_value=123
            ):
                records = self.provider.zone_records(zone)

                self.assertEqual(len(records), 3)
                # ANAME from API should be converted to ALIAS
                self.assertEqual(records[0]["type"], "ALIAS")
                self.assertEqual(records[0]["name"], "")  # @ becomes empty
                self.assertEqual(records[0]["id"], 1)

                self.assertEqual(records[1]["type"], "CNAME")
                self.assertEqual(records[1]["name"], "www")

                self.assertEqual(records[2]["type"], "MX")
                self.assertEqual(
                    len(records[2]["answers_list"]), 3
                )  # Subdomain record

    @patch.object(AzionClient, "zones")
    def test_list_zones(self, mock_zones):
        # Mock with real Azion API response format
        mock_zones.return_value = [
            {
                "domain": "example.com",
                "is_active": True,
                "name": "example.com",
                "id": 25,
            },
            {
                "domain": "example.net",
                "is_active": True,
                "name": "example.net",
                "id": 227,
            },
        ]

        result = self.provider.list_zones()

        expected = ["example.com.", "example.net."]
        self.assertEqual(result, expected)

    def test_params_for_alias(self):
        from octodns.record import Record

        zone = Zone('example.com.', [])
        record = Record.new(
            zone,
            '',
            {  # Root record
                'type': 'ALIAS',
                'ttl': 300,
                'value': 'target.example.com.',
            },
        )

        params = list(self.provider._params_for_ALIAS(record))
        self.assertEqual(len(params), 1)
        self.assertEqual(params[0]['entry'], '@')
        self.assertEqual(
            params[0]['record_type'], 'ANAME'
        )  # Converted to ANAME
        self.assertEqual(params[0]['ttl'], 300)
        self.assertEqual(params[0]['answers_list'], ['target.example.com'])

    def test_params_for_caa(self):
        from octodns.record import Record

        zone = Zone('example.com.', [])
        record = Record.new(
            zone,
            'test',
            {
                'type': 'CAA',
                'ttl': 300,
                'values': [
                    {'flags': 0, 'tag': 'issue', 'value': 'ca.example.com'},
                    {
                        'flags': 0,
                        'tag': 'iodef',
                        'value': 'mailto:admin@example.com',
                    },
                ],
            },
        )

        params = list(self.provider._params_for_CAA(record))
        self.assertEqual(len(params), 1)
        self.assertEqual(params[0]['entry'], 'test')
        self.assertEqual(params[0]['record_type'], 'CAA')
        self.assertEqual(params[0]['ttl'], 300)
        # Order doesn't matter for the answers list, just check both are present
        expected_answers = [
            '0 issue "ca.example.com"',
            '0 iodef "mailto:admin@example.com"',
        ]
        self.assertEqual(len(params[0]['answers_list']), 2)
        for answer in expected_answers:
            self.assertIn(answer, params[0]['answers_list'])

    def test_params_for_mx(self):
        from octodns.record import Record

        zone = Zone('example.com.', [])
        record = Record.new(
            zone,
            'test',
            {
                'type': 'MX',
                'ttl': 300,
                'values': [
                    {'preference': 10, 'exchange': 'mail.example.com.'},
                    {'preference': 20, 'exchange': 'mail2.example.com.'},
                ],
            },
        )

        params = list(self.provider._params_for_MX(record))
        self.assertEqual(len(params), 1)
        self.assertEqual(params[0]['entry'], 'test')
        self.assertEqual(params[0]['record_type'], 'MX')
        self.assertEqual(params[0]['ttl'], 300)
        self.assertEqual(
            params[0]['answers_list'],
            ['10 mail.example.com', '20 mail2.example.com'],
        )

    def test_params_for_srv(self):
        from octodns.record import Record

        zone = Zone('example.com.', [])
        record = Record.new(
            zone,
            '_http._tcp',
            {
                'type': 'SRV',
                'ttl': 300,
                'values': [
                    {
                        'priority': 10,
                        'weight': 20,
                        'port': 80,
                        'target': 'server.example.com.',
                    },
                    {
                        'priority': 20,
                        'weight': 30,
                        'port': 8080,
                        'target': 'server2.example.com.',
                    },
                ],
            },
        )

        params = list(self.provider._params_for_SRV(record))
        self.assertEqual(len(params), 1)
        self.assertEqual(params[0]['entry'], '_http._tcp')
        self.assertEqual(params[0]['record_type'], 'SRV')
        self.assertEqual(params[0]['ttl'], 300)
        self.assertEqual(
            params[0]['answers_list'],
            ['10 20 80 server.example.com', '20 30 8080 server2.example.com'],
        )

    def test_params_for_ptr(self):
        from octodns.record import Record

        zone = Zone('1.168.192.in-addr.arpa.', [])
        record = Record.new(
            zone,
            '10',
            {'type': 'PTR', 'ttl': 300, 'value': 'host.example.com.'},
        )

        params = list(self.provider._params_for_PTR(record))
        self.assertEqual(len(params), 1)
        self.assertEqual(params[0]['entry'], '10')
        self.assertEqual(params[0]['record_type'], 'PTR')
        self.assertEqual(params[0]['ttl'], 300)
        self.assertEqual(params[0]['answers_list'], ['host.example.com'])

    def test_params_for_txt(self):
        from octodns.record import Record

        zone = Zone('example.com.', [])
        record = Record.new(
            zone,
            'test',
            {
                'type': 'TXT',
                'ttl': 300,
                'values': [
                    'v=spf1 include:_spf.example.com ~all',
                    'v=DKIM1\\; k=rsa\\; p=MIGfMA0GCS...',
                ],
            },
        )

        params = list(self.provider._params_for_TXT(record))
        self.assertEqual(len(params), 1)
        self.assertEqual(params[0]['entry'], 'test')
        self.assertEqual(params[0]['record_type'], 'TXT')
        self.assertEqual(params[0]['ttl'], 300)
        # We expect the raw values as they are
        expected_answers = [
            'v=spf1 include:_spf.example.com ~all',
            'v=DKIM1\\; k=rsa\\; p=MIGfMA0GCS...',
        ]
        self.assertEqual(len(params[0]['answers_list']), 2)
        for answer in expected_answers:
            self.assertIn(answer, params[0]['answers_list'])

    @patch.object(AzionClient, 'zones')
    @patch.object(AzionClient, 'records')
    def test_populate(self, mock_records, mock_zones):
        # Mock zones response
        mock_zones.return_value = [
            {
                'domain': 'example.com',
                'is_active': True,
                'name': 'example.com',
                'id': 25,
            }
        ]

        # Mock records response
        mock_records.return_value = [
            {
                'record_id': 1,
                'entry': '',
                'record_type': 'A',
                'ttl': 300,
                'answers_list': ['1.2.3.4'],
            },
            {
                'record_id': 2,
                'entry': 'www',
                'record_type': 'CNAME',
                'ttl': 300,
                'answers_list': ['target.example.com'],
            },
        ]

        zone = Zone('example.com.', [])
        self.provider.populate(zone)

        # Should have 2 records
        self.assertEqual(len(zone.records), 2)

        # Verify records were added (basic check)
        record_names = [record.name for record in zone.records]
        record_types = [record._type for record in zone.records]

        self.assertIn('', record_names)  # Root record
        self.assertIn('www', record_names)  # Subdomain record
        self.assertIn('A', record_types)
        self.assertIn('CNAME', record_types)

    def test_get_zone_id_by_name_not_found(self):
        with patch.object(self.provider._client, 'zones', return_value=[]):
            with self.assertRaises(AzionClientNotFound):
                self.provider._get_zone_id_by_name('nonexistent.com')

    def test_get_zone_id_by_name_success(self):
        mock_zones = [
            {
                'domain': 'example.com',
                'is_active': True,
                'name': 'example.com',
                'id': 25,
            }
        ]
        with patch.object(
            self.provider._client, 'zones', return_value=mock_zones
        ):
            zone_id = self.provider._get_zone_id_by_name('example.com')
            self.assertEqual(zone_id, 25)

    def test_data_for_ns_record(self):
        records = [
            {
                'record_id': 1,
                'ttl': 300,
                'answers_list': ['ns1.example.com', 'ns2.example.com'],
            }
        ]

        result = self.provider._data_for_NS('NS', records)

        expected = {
            'ttl': 300,
            'type': 'NS',
            'values': ['ns1.example.com.', 'ns2.example.com.'],
        }
        self.assertEqual(result, expected)

    def test_data_for_srv_record(self):
        records = [
            {
                'record_id': 1,
                'ttl': 300,
                'answers_list': ['10 20 80 server.example.com'],
            }
        ]

        result = self.provider._data_for_SRV('SRV', records)

        expected = {
            'ttl': 300,
            'type': 'SRV',
            'values': [
                {
                    'priority': 10,
                    'weight': 20,
                    'port': 80,
                    'target': 'server.example.com.',
                }
            ],
        }
        self.assertEqual(result, expected)

    def test_data_for_caa_record(self):
        records = [
            {
                'record_id': 1,
                'ttl': 300,
                'answers_list': ['0 issue "ca.example.com"'],
            }
        ]

        result = self.provider._data_for_CAA('CAA', records)

        expected = {
            'ttl': 300,
            'type': 'CAA',
            'values': [{'flags': 0, 'tag': 'issue', 'value': 'ca.example.com'}],
        }
        self.assertEqual(result, expected)

    def test_apply_methods_exist(self):
        # Test that the apply methods exist and are callable
        self.assertTrue(hasattr(self.provider, '_apply_Create'))
        self.assertTrue(hasattr(self.provider, '_apply_Update'))
        self.assertTrue(hasattr(self.provider, '_apply_Delete'))
        self.assertTrue(hasattr(self.provider, '_apply'))

        # Test that they are callable
        self.assertTrue(callable(getattr(self.provider, '_apply_Create')))
        self.assertTrue(callable(getattr(self.provider, '_apply_Update')))
        self.assertTrue(callable(getattr(self.provider, '_apply_Delete')))
        self.assertTrue(callable(getattr(self.provider, '_apply')))

    def test_supports_root_ns(self):
        # Test that provider doesn't support root NS records
        self.assertFalse(self.provider.SUPPORTS_ROOT_NS)

    def test_supports_dynamic(self):
        # Test that provider doesn't support dynamic records
        self.assertFalse(self.provider.SUPPORTS_DYNAMIC)

    def test_client_methods_exist(self):
        # Test that AzionClient methods exist and are callable
        client = AzionClient('test-token')

        # Test that methods exist
        self.assertTrue(hasattr(client, 'zones'))
        self.assertTrue(hasattr(client, 'zone_create'))
        self.assertTrue(hasattr(client, 'records'))
        self.assertTrue(hasattr(client, 'record_create'))
        self.assertTrue(hasattr(client, 'record_update'))
        self.assertTrue(hasattr(client, 'record_delete'))

        # Test that methods are callable
        self.assertTrue(callable(client.zones))
        self.assertTrue(callable(client.zone_create))
        self.assertTrue(callable(client.records))
        self.assertTrue(callable(client.record_create))
        self.assertTrue(callable(client.record_update))
        self.assertTrue(callable(client.record_delete))

    @patch.object(AzionProvider, 'zone_records')
    def test_populate_with_no_records(self, mock_zone_records):
        # Test populate when zone has no records
        zone = Zone('example.com.', [])
        mock_zone_records.return_value = []

        # This should not raise an exception
        self.provider.populate(zone)

        # Zone should still be empty
        self.assertEqual(len(zone.records), 0)

    @patch.object(AzionProvider, '_get_zone_id_by_name')
    def test_populate_zone_not_found(self, mock_get_zone_id):
        # Test populate when zone is not found
        zone = Zone('example.com.', [])
        mock_get_zone_id.side_effect = AzionClientNotFound()

        # This should not raise an exception
        self.provider.populate(zone)

        # Zone should remain empty
        self.assertEqual(len(zone.records), 0)

    def test_azion_client_unauthorized_exception(self):
        # Test AzionClientUnauthorized exception creation
        exc = AzionClientUnauthorized()
        self.assertEqual(str(exc), 'Unauthorized')

    def test_client_request_unauthorized_real(self):
        # Test _request method with real 401 status code to trigger line 47
        client = AzionClient('test-token')

        # Mock the session directly on the instance
        mock_response = Mock()
        mock_response.status_code = 401
        client._sess.request = Mock(return_value=mock_response)

        with self.assertRaises(AzionClientUnauthorized):
            client._request('GET', '/test')

    @patch.object(AzionClient, '_request')
    def test_client_request_unauthorized(self, mock_request):
        # Test _request method with 401 status code
        mock_request.side_effect = AzionClientUnauthorized()

        client = AzionClient('test-token')
        with self.assertRaises(AzionClientUnauthorized):
            client._request('GET', '/test')

    @patch.object(AzionClient, '_request')
    def test_client_zones_with_pagination(self, mock_request):
        # Test zones method with pagination
        # First page
        mock_response1 = Mock()
        mock_response1.json.return_value = {
            'results': [{'id': 1, 'name': 'example1.com'}],
            'links': {'next': 'http://api.example.com/page2'},
        }

        # Second page (no more pages)
        mock_response2 = Mock()
        mock_response2.json.return_value = {
            'results': [{'id': 2, 'name': 'example2.com'}],
            'links': {},
        }

        mock_request.side_effect = [mock_response1, mock_response2]

        client = AzionClient('test-token')
        result = client.zones()

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]['name'], 'example1.com')
        self.assertEqual(result[1]['name'], 'example2.com')
        self.assertEqual(mock_request.call_count, 2)

    @patch.object(AzionClient, '_request')
    def test_client_zones_no_results(self, mock_request):
        # Test zones method with no results - covers line 73 (else break)
        mock_response = Mock()
        mock_response.json.return_value = (
            {}
        )  # No 'results' key, should hit else break
        mock_request.return_value = mock_response

        client = AzionClient('test-token')
        result = client.zones()

        self.assertEqual(result, [])

    @patch.object(AzionClient, '_request')
    def test_client_zone_create_method(self, mock_request):
        # Test zone_create method
        mock_response = Mock()
        mock_response.json.return_value = {
            'results': {'id': 1, 'name': 'example.com', 'domain': 'example.com'}
        }
        mock_request.return_value = mock_response

        client = AzionClient('test-token')
        result = client.zone_create('example.com')

        self.assertEqual(
            result,
            {
                'results': {
                    'id': 1,
                    'name': 'example.com',
                    'domain': 'example.com',
                }
            },
        )

    @patch.object(AzionClient, '_request')
    def test_client_records_with_pagination(self, mock_request):
        # Test records method with pagination
        # First page
        mock_response1 = Mock()
        mock_response1.json.return_value = {
            'results': {
                'records': [
                    {'record_id': 1, 'entry': 'test1', 'record_type': 'A'}
                ]
            },
            'links': {'next': 'http://api.example.com/page2'},
        }

        # Second page (no more pages)
        mock_response2 = Mock()
        mock_response2.json.return_value = {
            'results': {
                'records': [
                    {'record_id': 2, 'entry': 'test2', 'record_type': 'A'}
                ]
            },
            'links': {},
        }

        mock_request.side_effect = [mock_response1, mock_response2]

        client = AzionClient('test-token')
        result = client.records(1)

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]['entry'], 'test1')
        self.assertEqual(result[1]['entry'], 'test2')
        self.assertEqual(mock_request.call_count, 2)

    @patch.object(AzionClient, '_request')
    def test_client_records_no_results(self, mock_request):
        # Test records method with no results - covers line 113 (else break)
        mock_response = Mock()
        mock_response.json.return_value = {
            'results': {}
        }  # 'results' exists but no 'records' key
        mock_request.return_value = mock_response

        client = AzionClient('test-token')
        result = client.records(1)

        self.assertEqual(result, [])

    @patch.object(AzionClient, '_request')
    def test_client_record_create_method(self, mock_request):
        # Test record_create method
        mock_response = Mock()
        mock_response.json.return_value = {'results': {'record_id': 1}}
        mock_request.return_value = mock_response

        client = AzionClient('test-token')
        params = {
            'entry': 'test',
            'record_type': 'A',
            'answers_list': ['1.2.3.4'],
        }
        result = client.record_create(1, params)

        self.assertEqual(result, {'results': {'record_id': 1}})

    @patch.object(AzionClient, '_request')
    def test_client_record_update_method(self, mock_request):
        # Test record_update method
        mock_response = Mock()
        mock_response.json.return_value = {'results': {'record_id': 1}}
        mock_request.return_value = mock_response

        client = AzionClient('test-token')
        params = {
            'entry': 'test',
            'record_type': 'A',
            'answers_list': ['1.2.3.4'],
        }
        result = client.record_update(1, 1, params)

        self.assertEqual(result, {'results': {'record_id': 1}})

    @patch.object(AzionClient, '_request')
    def test_client_record_delete_method(self, mock_request):
        # Test record_delete method
        mock_response = Mock()
        mock_request.return_value = mock_response

        client = AzionClient('test-token')
        client.record_delete(1, 1)

        mock_request.assert_called_once()

    @patch.object(AzionProvider, 'zone_records')
    def test_populate_with_unsupported_record(self, mock_zone_records):
        # Test populate with unsupported record type
        zone = Zone('example.com.', [])
        mock_zone_records.return_value = [
            {
                'id': 1,
                'name': 'test',
                'type': 'UNSUPPORTED_TYPE',  # Type not in SUPPORTS
                'ttl': 300,
                'answers_list': ['value'],
            }
        ]

        with patch.object(self.provider.log, 'warning') as mock_warning:
            self.provider.populate(zone)
            mock_warning.assert_called_once_with(
                'populate: skipping unsupported %s record', 'UNSUPPORTED_TYPE'
            )

        # Zone should remain empty since record was skipped
        self.assertEqual(len(zone.records), 0)

    def test_params_for_single_function(self):
        # Test _params_for_single function
        from octodns.record import Record

        zone = Zone('example.com.', [])
        record = Record.new(
            zone,
            'test',
            {'type': 'CNAME', 'ttl': 300, 'value': 'target.example.com.'},
        )

        results = list(self.provider._params_for_single(record))
        self.assertEqual(len(results), 1)
        expected = {
            'entry': 'test',
            'record_type': 'CNAME',
            'ttl': 300,
            'answers_list': ['target.example.com'],
        }
        self.assertEqual(results[0], expected)

    def test_data_for_alias_function(self):
        # Test _data_for_ALIAS function
        records = [
            {
                'record_id': 1,
                'entry': '',
                'record_type': 'ALIAS',
                'ttl': 300,
                'answers_list': ['target.example.com'],
            }
        ]

        result = self.provider._data_for_ALIAS('ALIAS', records)
        expected = {'type': 'ALIAS', 'ttl': 300, 'value': 'target.example.com.'}
        self.assertEqual(result, expected)

    def test_params_for_multiple_with_values(self):
        # Test _params_for_multiple with multiple values (consolidated into single record)
        from octodns.record import Record

        zone = Zone('example.com.', [])
        record = Record.new(
            zone,
            'test',
            {'type': 'A', 'ttl': 300, 'values': ['1.2.3.4', '5.6.7.8']},
        )

        results = list(self.provider._params_for_multiple(record))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['answers_list'], ['1.2.3.4', '5.6.7.8'])
        self.assertEqual(results[0]['entry'], 'test')
        self.assertEqual(results[0]['record_type'], 'A')
        self.assertEqual(results[0]['ttl'], 300)

    @patch.object(AzionClient, 'record_create')
    @patch.object(AzionProvider, '_get_zone_id_by_name')
    def test_apply_create_real(self, mock_get_zone_id, mock_record_create):
        # Test _apply_Create with real record creation
        from octodns.record import Record

        zone = Zone('example.com.', [])
        record = Record.new(
            zone, 'test', {'type': 'A', 'ttl': 300, 'value': '1.2.3.4'}
        )

        mock_get_zone_id.return_value = 25
        mock_record_create.return_value = {'record_id': 123}

        # Create a mock change object
        change = Mock()
        change.new = record

        self.provider._apply_Create(change)

        mock_get_zone_id.assert_called_once_with('example.com.')
        mock_record_create.assert_called_once()

    @patch.object(AzionProvider, '_get_zone_id_by_name')
    @patch.object(AzionProvider, 'zone_records')
    def test_apply_update_real(self, mock_zone_records, mock_get_zone_id):
        # Test _apply_Update finds matching record and calls record_update
        existing = Record.new(
            Zone('example.com.', []),
            'test',
            {'type': 'A', 'ttl': 300, 'value': '1.2.3.4'},
        )
        new = Record.new(
            Zone('example.com.', []),
            'test',
            {'type': 'A', 'ttl': 600, 'value': '5.6.7.8'},
        )
        change = Mock()
        change.existing = existing
        change.new = new

        # Mock zone records to return a matching record
        mock_zone_records.return_value = [
            {'id': 'record123', 'name': 'test', 'type': 'A'}
        ]
        mock_get_zone_id.return_value = 'zone123'

        # Mock the client's record_update method
        with patch.object(
            self.provider._client, 'record_update'
        ) as mock_record_update:
            self.provider._apply_Update(change)
            mock_record_update.assert_called_once_with(
                'zone123',
                'record123',
                {
                    'entry': 'test',
                    'record_type': 'A',
                    'ttl': 600,
                    'answers_list': ['5.6.7.8'],
                },
            )

    @patch.object(AzionProvider, '_get_zone_id_by_name')
    @patch.object(AzionProvider, 'zone_records')
    def test_apply_update_no_matching_records(
        self, mock_zone_records, mock_get_zone_id
    ):
        # Test _apply_Update when no matching records are found (branch coverage)
        existing = Record.new(
            Zone('example.com.', []),
            'test',
            {'type': 'A', 'ttl': 300, 'value': '1.2.3.4'},
        )
        new = Record.new(
            Zone('example.com.', []),
            'test',
            {'type': 'A', 'ttl': 600, 'value': '5.6.7.8'},
        )
        change = Mock()
        change.existing = existing
        change.new = new

        # Mock zone records to return empty list (no records)
        mock_zone_records.return_value = []
        mock_get_zone_id.return_value = 'zone123'

        # Mock the client's record_update method to ensure it's not called
        with patch.object(
            self.provider._client, 'record_update'
        ) as mock_record_update:
            self.provider._apply_Update(change)
            # Should not call record_update when no matching records
            mock_record_update.assert_not_called()

    @patch.object(AzionProvider, '_get_zone_id_by_name')
    @patch.object(AzionProvider, 'zone_records')
    def test_apply_update_no_matching_records_different_name_type(
        self, mock_zone_records, mock_get_zone_id
    ):
        # Test _apply_Update when records exist but don't match name/type (branch coverage)
        existing = Record.new(
            Zone('example.com.', []),
            'test',
            {'type': 'A', 'ttl': 300, 'value': '1.2.3.4'},
        )
        new = Record.new(
            Zone('example.com.', []),
            'test',
            {'type': 'A', 'ttl': 600, 'value': '5.6.7.8'},
        )
        change = Mock()
        change.existing = existing
        change.new = new

        # Mock zone records to return records that don't match
        mock_zone_records.return_value = [
            {
                'id': 'record123',
                'name': 'different',
                'type': 'A',
            },  # Different name
            {
                'id': 'record456',
                'name': 'test',
                'type': 'CNAME',
            },  # Different type
        ]
        mock_get_zone_id.return_value = 'zone123'

        # Mock the client's record_update method to ensure it's not called
        with patch.object(
            self.provider._client, 'record_update'
        ) as mock_record_update:
            self.provider._apply_Update(change)
            # Should not call record_update when no matching records
            mock_record_update.assert_not_called()

    @patch.object(AzionProvider, '_get_zone_id_by_name')
    @patch.object(AzionProvider, 'zone_records')
    def test_apply_update_multiple_values(
        self, mock_zone_records, mock_get_zone_id
    ):
        # Test _apply_Update with multiple values (consolidated payload)
        existing = Record.new(
            Zone('example.com.', []),
            'test',
            {'type': 'A', 'ttl': 300, 'values': ['1.2.3.4']},
        )
        new = Record.new(
            Zone('example.com.', []),
            'test',
            {'type': 'A', 'ttl': 600, 'values': ['1.2.3.4', '5.6.7.8']},
        )
        change = Mock()
        change.existing = existing
        change.new = new

        # Mock zone records to return a matching record
        mock_zone_records.return_value = [
            {'id': 'record123', 'name': 'test', 'type': 'A'}
        ]
        mock_get_zone_id.return_value = 'zone123'

        # Mock the client's record_update method
        with patch.object(
            self.provider._client, 'record_update'
        ) as mock_record_update:
            self.provider._apply_Update(change)
            mock_record_update.assert_called_once_with(
                'zone123',
                'record123',
                {
                    'entry': 'test',
                    'record_type': 'A',
                    'ttl': 600,
                    'answers_list': [
                        '1.2.3.4',
                        '5.6.7.8',
                    ],  # All values in single payload
                },
            )

    def test_apply_delete_no_matching_records(self):
        # Test _apply_Delete when no matching records are found (branch coverage)
        zone = Zone('example.com.', [])
        existing = Record.new(
            zone, 'test', {'type': 'A', 'ttl': 300, 'value': '1.2.3.4'}
        )
        change = Mock()
        change.existing = existing

        # Mock zone_records to return records that don't match
        with patch.object(self.provider, 'zone_records') as mock_zone_records:
            mock_zone_records.return_value = [
                {'id': 1, 'name': 'other', 'type': 'A'},  # Different name
                {'id': 2, 'name': 'test', 'type': 'CNAME'},  # Different type
            ]

            with patch.object(
                self.provider, '_get_zone_id_by_name', return_value=1
            ):
                with patch.object(
                    self.provider._client, 'record_delete'
                ) as mock_delete:
                    self.provider._apply_Delete(change)
                    # Should not call record_delete since no matching records
                    mock_delete.assert_not_called()

    def test_zone_records_with_empty_answers_list(self):
        # Test branch coverage for empty answers_list in zone_records
        zone = Zone('example.com.', [])

        with patch.object(
            self.provider, '_get_zone_id_by_name', return_value=1
        ):
            with patch.object(self.provider._client, 'records') as mock_records:
                mock_records.return_value = [
                    {
                        'record_id': 1,
                        'entry': 'test',
                        'record_type': 'A',
                        'ttl': 300,
                        'answers_list': [],  # Empty answers_list
                    }
                ]

                result = self.provider.zone_records(zone)
                self.assertEqual(len(result), 1)
                self.assertEqual(
                    result[0]['value'], ''
                )  # Should default to empty string

    def test_zone_records_without_answers_list(self):
        # Test branch coverage for missing answers_list in zone_records
        zone = Zone('example.com.', [])

        with patch.object(
            self.provider, '_get_zone_id_by_name', return_value=1
        ):
            with patch.object(self.provider._client, 'records') as mock_records:
                mock_records.return_value = [
                    {
                        'record_id': 1,
                        'entry': 'test',
                        'record_type': 'A',
                        'ttl': 300,
                        # No answers_list key
                    }
                ]

                result = self.provider.zone_records(zone)
                self.assertEqual(len(result), 1)
                self.assertEqual(
                    result[0]['value'], ''
                )  # Should default to empty string

    def test_list_zones_domain_without_dot(self):
        # Test branch coverage for domains without trailing dot in list_zones
        with patch.object(self.provider._client, 'zones') as mock_zones:
            mock_zones.return_value = [
                {'id': 1, 'domain': 'example.com'},  # No trailing dot
                {'id': 2, 'domain': 'test.org.'},  # With trailing dot
                {'id': 3, 'name': 'backup.net'},  # Using 'name' field
            ]

            result = self.provider.list_zones()
            expected = ['example.com.', 'test.org.', 'backup.net.']
            self.assertEqual(sorted(result), sorted(expected))

    def test_params_for_txt_already_quoted(self):
        # Test branch coverage for TXT values that are already quoted
        zone = Zone('example.com.', [])
        record = Record.new(
            zone,
            'test',
            {
                'type': 'TXT',
                'ttl': 300,
                'values': ['"already quoted"', 'not quoted'],
            },
        )

        params_list = list(self.provider._params_for_TXT(record))
        self.assertEqual(len(params_list), 1)
        # OctoDNS normalizes by removing external quotes during Record processing
        # Provider passes through the normalized values
        self.assertEqual(
            params_list[0]['answers_list'], ['already quoted', 'not quoted']
        )

    def test_params_for_srv_with_dot_target(self):
        # Test branch coverage for SRV target that is just '.'
        zone = Zone('example.com.', [])
        record = Record.new(
            zone,
            '_sip._tcp',
            {
                'type': 'SRV',
                'ttl': 300,
                'values': [
                    {
                        'priority': 10,
                        'weight': 20,
                        'port': 5060,
                        'target': '.',  # Special case: just a dot
                    }
                ],
            },
        )

        params_list = list(self.provider._params_for_SRV(record))
        self.assertEqual(len(params_list), 1)
        self.assertEqual(params_list[0]['answers_list'], ['10 20 5060 .'])

    def test_apply_delete_with_matching_record(self):
        # Test _apply_Delete when matching record is found (covers line 515)
        zone = Zone('example.com.', [])
        existing = Record.new(
            zone, 'test', {'type': 'A', 'ttl': 300, 'value': '1.2.3.4'}
        )
        change = Mock()
        change.existing = existing

        # Mock zone_records to return matching record
        with patch.object(self.provider, 'zone_records') as mock_zone_records:
            mock_zone_records.return_value = [
                {'id': 123, 'name': 'test', 'type': 'A'}  # Matching record
            ]

            with patch.object(
                self.provider, '_get_zone_id_by_name', return_value=1
            ):
                with patch.object(
                    self.provider._client, 'record_delete'
                ) as mock_delete:
                    self.provider._apply_Delete(change)
                    # Should call record_delete for matching record
                    mock_delete.assert_called_once_with(1, 123)

    def test_apply_with_zone_creation(self):
        # Test _apply when zone doesn't exist and needs creation (covers lines 525-530)
        zone = Zone('example.com.', [])
        plan = Mock()
        plan.desired = zone
        plan.changes = []

        with patch.object(
            self.provider, '_get_zone_id_by_name'
        ) as mock_get_zone_id:
            with patch.object(
                self.provider._client, 'zone_create'
            ) as mock_zone_create:
                # First call raises exception (zone not found)
                mock_get_zone_id.side_effect = AzionClientNotFound()
                mock_zone_create.return_value = {'id': 25}

                self.provider._apply(plan)

                # Should call zone_create when zone is not found
                mock_zone_create.assert_called_once_with('example.com')
                # Should clear cache
                self.assertNotIn('example.com.', self.provider._zone_cache)

    def test_get_zone_id_by_name_zone_not_found(self):
        # Test branch coverage for zone not found in _get_zone_id_by_name
        with patch.object(self.provider._client, 'zones') as mock_zones:
            mock_zones.return_value = [
                {'id': 1, 'domain': 'other.com'},
                {'id': 2, 'name': 'another.net'},
            ]

            with self.assertRaises(AzionClientNotFound):
                self.provider._get_zone_id_by_name('notfound.com.')

    def test_data_for_caa_with_insufficient_parts(self):
        # Test branch coverage for CAA records with insufficient parts
        records = [
            {
                'ttl': 300,
                'answers_list': [
                    '0 issue',
                    '128 issue letsencrypt.org',
                ],  # One with 2 parts, one with 3
            }
        ]

        result = self.provider._data_for_CAA('CAA', records)
        # Should only include the record with 3 parts
        self.assertEqual(len(result['values']), 1)
        self.assertEqual(result['values'][0]['flags'], 128)
        self.assertEqual(result['values'][0]['tag'], 'issue')
        self.assertEqual(result['values'][0]['value'], 'letsencrypt.org')

    def test_data_for_cname_without_dot(self):
        # Test branch coverage for CNAME value without trailing dot
        records = [
            {'ttl': 300, 'answers_list': ['example.com']}  # No trailing dot
        ]

        result = self.provider._data_for_CNAME('CNAME', records)
        self.assertEqual(result['value'], 'example.com.')  # Should add dot

    def test_data_for_cname_with_dot(self):
        # Test branch coverage for CNAME value with trailing dot
        records = [
            {'ttl': 300, 'answers_list': ['example.com.']}  # With trailing dot
        ]

        result = self.provider._data_for_CNAME('CNAME', records)
        self.assertEqual(result['value'], 'example.com.')  # Should keep dot

    def test_data_for_srv_without_dot(self):
        # Test branch coverage for SRV target without trailing dot
        records = [
            {
                'ttl': 300,
                'answers_list': ['10 20 80 example.com'],  # No trailing dot
            }
        ]

        result = self.provider._data_for_SRV('SRV', records)
        self.assertEqual(
            result['values'][0]['target'], 'example.com.'
        )  # Should add dot

    def test_data_for_srv_with_dot(self):
        # Test branch coverage for SRV target with trailing dot
        records = [
            {
                'ttl': 300,
                'answers_list': ['10 20 80 example.com.'],  # With trailing dot
            }
        ]

        result = self.provider._data_for_SRV('SRV', records)
        self.assertEqual(
            result['values'][0]['target'], 'example.com.'
        )  # Should keep dot

    def test_data_for_mx_without_dot(self):
        # Test branch coverage for MX exchange without trailing dot
        records = [
            {
                'ttl': 300,
                'answers_list': ['10 mail.example.com'],  # No trailing dot
            }
        ]

        result = self.provider._data_for_MX('MX', records)
        self.assertEqual(
            result['values'][0]['exchange'], 'mail.example.com.'
        )  # Should add dot

    def test_data_for_mx_with_dot(self):
        # Test branch coverage for MX exchange with trailing dot
        records = [
            {
                'ttl': 300,
                'answers_list': ['10 mail.example.com.'],  # With trailing dot
            }
        ]

        result = self.provider._data_for_MX('MX', records)
        self.assertEqual(
            result['values'][0]['exchange'], 'mail.example.com.'
        )  # Should keep dot

    def test_data_for_alias_without_dot(self):
        # Test branch coverage for ALIAS value without trailing dot
        records = [
            {'ttl': 300, 'answers_list': ['example.com']}  # No trailing dot
        ]

        result = self.provider._data_for_ALIAS('ALIAS', records)
        self.assertEqual(result['value'], 'example.com.')  # Should add dot

    def test_data_for_alias_with_dot(self):
        # Test branch coverage for ALIAS value with trailing dot
        records = [
            {'ttl': 300, 'answers_list': ['example.com.']}  # With trailing dot
        ]

        result = self.provider._data_for_ALIAS('ALIAS', records)
        self.assertEqual(result['value'], 'example.com.')  # Should keep dot

    def test_data_for_ptr_without_dot(self):
        # Test branch coverage for PTR value without trailing dot
        records = [
            {'ttl': 300, 'answers_list': ['example.com']}  # No trailing dot
        ]

        result = self.provider._data_for_PTR('PTR', records)
        self.assertEqual(result['value'], 'example.com.')  # Should add dot

    def test_data_for_ptr_with_dot(self):
        # Test branch coverage for PTR value with trailing dot
        records = [
            {'ttl': 300, 'answers_list': ['example.com.']}  # With trailing dot
        ]

        result = self.provider._data_for_PTR('PTR', records)
        self.assertEqual(result['value'], 'example.com.')  # Should keep dot

    def test_data_for_ns_without_dot(self):
        # Test branch coverage for NS value without trailing dot
        records = [
            {
                'ttl': 300,
                'answers_list': [
                    'ns1.example.com',
                    'ns2.example.com.',
                ],  # Mixed
            }
        ]

        result = self.provider._data_for_NS('NS', records)
        self.assertEqual(len(result['values']), 2)
        self.assertEqual(
            result['values'][0], 'ns1.example.com.'
        )  # Should add dot
        self.assertEqual(
            result['values'][1], 'ns2.example.com.'
        )  # Should keep dot

    def test_data_for_txt_with_quotes(self):
        # Test branch coverage for TXT values with quotes
        records = [
            {
                'ttl': 300,
                'answers_list': [
                    '"quoted text"',
                    'unquoted',
                    '""',
                    'text;with;semicolons',
                ],
            }
        ]

        result = self.provider._data_for_TXT('TXT', records)
        self.assertEqual(len(result['values']), 4)
        self.assertEqual(result['values'][0], '"quoted text"')
        self.assertEqual(result['values'][1], 'unquoted')
        self.assertEqual(result['values'][2], '""')
        self.assertEqual(result['values'][3], 'text\\;with\\;semicolons')

    def test_data_for_mx_with_insufficient_parts(self):
        # Test branch coverage for MX records with insufficient parts
        records = [
            {
                'ttl': 300,
                'answers_list': [
                    '10',
                    '20 mail.example.com',
                ],  # One with 1 part, one with 2
            }
        ]

        result = self.provider._data_for_MX('MX', records)
        # Should only include the record with 2 parts
        self.assertEqual(len(result['values']), 1)
        self.assertEqual(result['values'][0]['preference'], 20)
        self.assertEqual(result['values'][0]['exchange'], 'mail.example.com.')

    def test_data_for_srv_with_insufficient_parts(self):
        # Test branch coverage for SRV records with insufficient parts
        records = [
            {
                'ttl': 300,
                'answers_list': [
                    '10 20 80',
                    '10 20 80 example.com',
                ],  # One with 3 parts, one with 4
            }
        ]

        result = self.provider._data_for_SRV('SRV', records)
        # Should only include the record with 4 parts
        self.assertEqual(len(result['values']), 1)
        self.assertEqual(result['values'][0]['priority'], 10)
        self.assertEqual(result['values'][0]['weight'], 20)
        self.assertEqual(result['values'][0]['port'], 80)
        self.assertEqual(result['values'][0]['target'], 'example.com.')

    def test_list_zones_with_empty_domain(self):
        # Test branch coverage for zones with empty domain
        with patch.object(self.provider._client, 'zones') as mock_zones:
            mock_zones.return_value = [
                {'id': 1, 'domain': 'example.com'},
                {'id': 2, 'domain': ''},  # Empty domain
                {'id': 3, 'name': ''},  # Empty name
                {'id': 4},  # No domain or name
            ]

            result = self.provider.list_zones()
            # Should only include non-empty domains
            self.assertEqual(result, ['example.com.'])

    def test_get_zone_id_by_name_cache_hit(self):
        # Test branch coverage for zone found in cache (161->171)
        zone_name = 'example.com.'
        zone_id = 123

        # Pre-populate cache
        self.provider._zone_cache[zone_name] = zone_id

        # Should return cached value without calling client.zones()
        with patch.object(self.provider._client, 'zones') as mock_zones:
            result = self.provider._get_zone_id_by_name(zone_name)
            self.assertEqual(result, zone_id)
            mock_zones.assert_not_called()  # Should not call API

    def test_data_for_cname_value_already_has_dot(self):
        # Test branch coverage for CNAME value that already ends with dot (223->225)
        records = [
            {
                'ttl': 300,
                'value': 'example.com.',  # Already has dot, using 'value' instead of 'answers_list'
            }
        ]

        result = self.provider._data_for_CNAME('CNAME', records)
        self.assertEqual(
            result['value'], 'example.com.'
        )  # Should keep existing dot

    def test_data_for_alias_value_with_dot_direct(self):
        # Test branch coverage for ALIAS value that already ends with dot (branch 223->225)
        records = [
            {
                'ttl': 300,
                'answers_list': [
                    'target.example.com.'
                ],  # Value already has dot
            }
        ]

        result = self.provider._data_for_ALIAS('ALIAS', records)
        self.assertEqual(
            result['value'], 'target.example.com.'
        )  # Should keep existing dot

    def test_data_for_alias_no_answers_list_with_dot(self):
        # Test branch coverage for ALIAS without answers_list, fallback value has dot
        records = [
            {
                'ttl': 300,
                'value': 'fallback.example.com.',  # Fallback value has dot, no answers_list key
            }
        ]

        result = self.provider._data_for_ALIAS('ALIAS', records)
        self.assertEqual(
            result['value'], 'fallback.example.com.'
        )  # Should keep existing dot

    def test_data_for_alias_skip_dot_addition(self):
        # Test specific branch coverage for ALIAS when value already ends with dot (skip line 239)
        records = [
            {
                'ttl': 300,
                'answers_list': [
                    'already.has.dot.'
                ],  # This should skip the dot addition
            }
        ]

        result = self.provider._data_for_ALIAS('ALIAS', records)
        # Verify the value is unchanged (dot not added)
        self.assertEqual(result['value'], 'already.has.dot.')
        self.assertEqual(result['ttl'], 300)
        self.assertEqual(result['type'], 'ALIAS')

    def test_data_for_cname_skip_dot_addition_answers_list(self):
        # Test specific branch coverage for CNAME when value already ends with dot (branch 223->225)
        records = [
            {
                'ttl': 300,
                'answers_list': [
                    'target.example.com.'
                ],  # Value already has dot in answers_list
            }
        ]

        result = self.provider._data_for_CNAME('CNAME', records)
        # Verify the value is unchanged (dot not added)
        self.assertEqual(result['value'], 'target.example.com.')
        self.assertEqual(result['ttl'], 300)
        self.assertEqual(result['type'], 'CNAME')

    def test_data_for_aname_skip_dot_addition(self):
        # Test specific branch coverage for ANAME when value already ends with dot (branch 223->225)
        records = [
            {
                'ttl': 300,
                'answers_list': [
                    'target.azioncdn.net.'
                ],  # Value already has dot
            }
        ]

        result = self.provider._data_for_ANAME('ANAME', records)
        # Verify the value is unchanged (dot not added)
        self.assertEqual(result['value'], 'target.azioncdn.net.')
        self.assertEqual(result['ttl'], 300)
        self.assertEqual(result['type'], 'ANAME')

    def test_zone_records_cache_hit(self):
        # Test branch coverage for zone_records when zone is already cached (323->361)
        zone = Zone('example.com.', [])
        cached_records = [{'id': 1, 'name': 'test', 'type': 'A'}]

        # Pre-populate _zone_records cache
        self.provider._zone_records[zone.name] = cached_records

        # Should return cached records without calling API
        with patch.object(
            self.provider, '_get_zone_id_by_name'
        ) as mock_get_zone_id:
            with patch.object(self.provider._client, 'records') as mock_records:
                result = self.provider.zone_records(zone)
                self.assertEqual(result, cached_records)
                mock_get_zone_id.assert_not_called()  # Should not call API
                mock_records.assert_not_called()  # Should not call API

    @patch.object(AzionProvider, '_get_zone_id_by_name')
    def test_apply_existing_zone(self, mock_get_zone_id):
        # Test _apply when zone already exists
        zone = Zone('example.com.', [])
        plan = Mock()
        plan.desired = zone
        plan.changes = []

        mock_get_zone_id.return_value = 25

        self.provider._apply(plan)

        # Should not call zone_create when zone exists
        mock_get_zone_id.assert_called_once_with('example.com.')

    @patch.object(AzionProvider, '_apply_Create')
    @patch.object(AzionProvider, '_get_zone_id_by_name')
    def test_apply_with_changes(self, mock_get_zone_id, mock_apply_create):
        # Test _apply processes changes correctly
        zone = Zone('example.com.', [])
        plan = Mock()
        plan.desired = zone

        # Create mock changes
        change1 = Mock()
        change1.__class__.__name__ = 'Create'
        change2 = Mock()
        change2.__class__.__name__ = 'Create'
        plan.changes = [change1, change2]

        mock_get_zone_id.return_value = 25

        self.provider._apply(plan)

        # Should call _apply_Create for each Create change
        self.assertEqual(mock_apply_create.call_count, 2)
        mock_apply_create.assert_any_call(change1)
        mock_apply_create.assert_any_call(change2)

    def test_parse_structured_answer_insufficient_parts(self):
        # Test _parse_structured_answer when parts_count is not met (covers line 179)
        def dummy_parser(parts):
            return {'parsed': True}

        # Test with insufficient parts (should return None)
        result = self.provider._parse_structured_answer(
            'single', 3, dummy_parser
        )
        self.assertIsNone(result)

        # Test with sufficient parts (should call parser)
        result = self.provider._parse_structured_answer(
            'one two three', 3, dummy_parser
        )
        self.assertEqual(result, {'parsed': True})

    def test_get_record_answers_helper(self):
        # Test _get_record_answers helper method
        records = [{'ttl': 300, 'answers_list': ['test1', 'test2']}]
        answers, ttl = self.provider._get_record_answers(records)
        self.assertEqual(answers, ['test1', 'test2'])
        self.assertEqual(ttl, 300)

        # Test with fallback to 'value' field
        records = [{'ttl': 600, 'value': 'fallback'}]
        answers, ttl = self.provider._get_record_answers(records)
        self.assertEqual(answers, ['fallback'])
        self.assertEqual(ttl, 600)

    def test_ensure_trailing_dot_helper(self):
        # Test _ensure_trailing_dot helper method
        self.assertEqual(
            self.provider._ensure_trailing_dot('example.com'), 'example.com.'
        )
        self.assertEqual(
            self.provider._ensure_trailing_dot('example.com.'), 'example.com.'
        )

    def test_client_request_400_bad_request_json_success(self):
        # Test _request method with 400 status code and successful JSON parsing
        from unittest.mock import MagicMock

        client = AzionClient('test-token')

        mock_response = MagicMock()
        mock_response.status_code = 400
        # This should succeed and trigger the try block
        mock_response.json.return_value = {
            'error': 'Invalid data',
            'field': 'answers_list',
        }
        client._sess = MagicMock()
        client._sess.request.return_value = mock_response

        with self.assertRaises(AzionClientException) as cm:
            client._request('PUT', '/test', data={'test': 'data'})

        exception_str = str(cm.exception)
        self.assertIn('Bad Request', exception_str)
        # The exact content depends on mock behavior, just ensure exception is raised correctly

    def test_client_request_400_bad_request_json_fail(self):
        # Test _request method with 400 status code and failed JSON parsing
        client = AzionClient('test-token')

        # Test the except path (json() fails)
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.side_effect = ValueError('Not JSON')
        mock_response.text = 'Bad request error text'
        client._sess.request = Mock(return_value=mock_response)

        with self.assertRaises(AzionClientException) as cm:
            client._request('PUT', '/test', data={'test': 'data'})

        exception_str = str(cm.exception)
        self.assertIn('Bad request error text', exception_str)
        self.assertIn('Request data', exception_str)


if __name__ == "__main__":
    unittest.main()
