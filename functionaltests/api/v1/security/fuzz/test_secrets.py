# Copyright (c) 2014 Rackspace, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import binascii
import json
import sys
import time

from testtools import testcase

from barbican.tests import utils
from functionaltests.api import base
from functionaltests.api.v1.behaviors import secret_behaviors
from functionaltests.api.v1.models import secret_models
from functionaltests.api.v1.security import security_utils

# TODO(tdink) Move to a config file
secret_create_defaults_data = {
    "name": "AES key",
    "expiration": "2018-02-28T19:14:44.180394",
    "algorithm": "aes",
    "bit_length": 256,
    "mode": "cbc",
    "payload": "gF6+lLoF3ohA9aPRpt+6bQ==",
    "payload_content_type": "application/octet-stream",
    "payload_content_encoding": "base64",
}

secret_create_nones_data = {
    "name": None,
    "expiration": None,
    "algorithm": None,
    "bit_length": None,
    "mode": None,
    "payload": None,
    "payload_content_type": None,
    "payload_content_encoding": None,
}

secret_create_emptystrings_data = {
    "name": '',
    "expiration": '',
    "algorithm": '',
    "bit_length": '',
    "mode": '',
    "payload": '',
    "payload_content_type": '',
    "payload_content_encoding": '',
}

secret_create_two_phase_data = {
    "name": "AES key",
    "expiration": "2018-02-28T19:14:44.180394",
    "algorithm": "aes",
    "bit_length": 256,
    "mode": "cbc",
}

secret_create_all_the_things = {
    'name': '',
    'expiration': '',
    'algorithm': '',
    'bit_length': '',
    'mode': '',
    'payload_content_type': '',
    'payload': '',
    'content_types': '',
    'payload_content_encoding': '',
    'secret_ref': '',
    'status': '',
    'updated': '',
    'created': ''
}

fuzz_header_dataset = \
    {
        'accept': {'header': 'Accept',
                   'payloads': security_utils.get_fuzz_strings('ascii')},
        'cookie': {'header': 'Cookie',
                   'payloads': security_utils.get_fuzz_strings('ascii')},
        'host': {'header': 'Host',
                 'payloads': security_utils.get_fuzz_strings('ascii')},
        'content_type': {'header': 'Content-Type',
                         'payloads': security_utils.get_fuzz_strings('ascii')},
        'accept_enc': {'header': 'Accept-Encoding',
                       'payloads': security_utils.get_fuzz_strings('ascii')},
        'user_agent': {'header': 'User-Agent',
                       'payloads': security_utils.get_fuzz_strings('ascii')},
        'connection': {'header': 'Connection',
                       'payloads': security_utils.get_fuzz_strings('ascii')},

    }


@utils.parameterized_test_case
class SecretsTestCase(base.TestCase):

    def setUp(self):
        super(SecretsTestCase, self).setUp()
        self.behaviors = secret_behaviors.SecretBehaviors(self.client)

    def tearDown(self):
        self.behaviors.delete_all_created_secrets()
        super(SecretsTestCase, self).tearDown()

    '''
    @testcase.attr('security')
    def test_fuzz_create_secret_all_single(self):
        """Create a secret with 1 param as fuzzstring, rest undefined
        SLOOOOOOOOW

        Should return 400 ?"""
        models = security_utils.fuzz_model(
            secret_models.SecretModel,
            skeleton=secret_create_defaults_data,
            fuzz_string_type='all',
            fuzz_type='all')

        for model in models:
            resp, secret_ref = self.behaviors.create_secret(model)
            # self.assertEqual(resp.status_code, 400)
            assert(resp.status_code in [400, 201])
    @testcase.attr('security')
    def test_fuzz_create_secret_all_all(self):
        """Create a secret with all params as fuzzstring, rest undefined

        Should return 400 ?"""
        models = security_utils.fuzz_model(
            secret_models.SecretModel,
            skeleton=secret_create_all_the_things,
            fuzz_string_type='all',
            fuzz_type='all')

        for model in models:
            resp, secret_ref = self.behaviors.create_secret(model)
            # self.assertEqual(resp.status_code, 400)
            assert(resp.status_code in [400, 201])
    @testcase.attr('security')
    def test_fuzz_create_secret_unicode_single(self):
        """Create a secret with all params as a unicode char, rest undefined
        SLOOOOOOOOOOOOOOOOOOOOOOW

        Should return 400 ?"""
        models = security_utils.fuzz_model(
            secret_models.SecretModel,
            # skeleton=secret_create_all_the_things,
            skeleton=secret_create_defaults_data,
            fuzz_string_type='unicode',
            fuzz_type='single')

        for model in models:
            resp, secret_ref = self.behaviors.create_secret(model)
            # self.assertEqual(resp.status_code, 400)
            assert(resp.status_code in [400, 201])

    @utils.parameterized_dataset({
        'unicode': [security_utils.get_fuzz_strings('unicode')],
        'ascii': [security_utils.get_fuzz_strings('ascii')]
    })
    @testcase.attr('negative')
    def test_secret_create_defaults_invalid_payload(self, payloads):
        """Covers creating secrets with various invalid payloads."""
        for payload in payloads:
            model = secret_models.SecretModel(**secret_create_defaults_data)
            overrides = {"payload_content_type": "application/octet-stream",
                         "payload_content_encoding": "base64",
                         "payload": payload}
            model.override_values(**overrides)

            resp, secret_ref = self.behaviors.create_secret(model)
            self.assertIn(resp.status_code, [400, 201])

    @utils.parameterized_dataset({
        'unicode': [security_utils.get_fuzz_strings('unicode')],
        'ascii': [security_utils.get_fuzz_strings('ascii')]
    })
    @testcase.attr('negative')
    def test_fuzz_project_id(self, payloads):
        """Fuzzes Project-Id Header with random bytes"""
        model = secret_models.SecretModel(**secret_create_defaults_data)

        for payload in payloads:
            if payload.strip():
                headers = {'X-Project-Id': payload.encode('utf8'),
                           'X-Auth-Token': self.client._auth.token}

            resp = self.client.post('secrets', request_model=model,
                                    use_auth=False, extra_headers=headers)

            self.assertIn(resp.status_code, [400, 201])

    @utils.parameterized_dataset({
        'unicode': [security_utils.get_fuzz_strings('unicode')],
        'ascii': [security_utils.get_fuzz_strings('ascii')]
    })
    @testcase.attr('negative')
    def test_fuzz_content_type(self, payloads):
        """Fuzzes Content-Type Header with random bytes

        Should return 415"""
        model = secret_models.SecretModel(**secret_create_defaults_data)

        for payload in payloads:
            if payload.strip():
                headers = {'Content-Type': payload}

            resp = self.client.post('secrets', request_model=model,
                                    extra_headers=headers)

            self.assertEqual(resp.status_code, 415)

    @utils.parameterized_dataset({
        # 'unicode': [security_utils.get_fuzz_strings('unicode')],
        'ascii': [security_utils.get_fuzz_strings('ascii')]
    })
    @testcase.attr('negative')
    def test_fuzz_cookie_header(self, payloads):
        """Fuzzes Cookie header w/ random bytes

        Should return 201"""
        model = secret_models.SecretModel(**secret_create_defaults_data)

        for payload in payloads:
            if payload.strip():
                headers = {'Cookie': payload}

                resp = self.client.post('secrets', request_model=model,
                                        extra_headers=headers)

                self.assertEqual(resp.status_code, 201)

    @utils.parameterized_dataset({
        # 'unicode': [security_utils.get_fuzz_strings('unicode')],
        'ascii': [security_utils.get_fuzz_strings('ascii')]
    })
    @testcase.attr('negative')
    def test_fuzz_accept_header(self, payloads):
        """Fuzzes Accept header w/ random bytes

        Should return 406"""
        model = secret_models.SecretModel(**secret_create_defaults_data)

        for payload in payloads:
            if payload.strip():
                headers = {'Accept': payload}

                resp = self.client.post('secrets', request_model=model,
                                        extra_headers=headers)

                self.assertEqual(resp.status_code, 406)
    '''

    """
    @utils.parameterized_dataset({
        'accept': {'header': 'Accept',
                   'payloads': security_utils.get_fuzz_strings('ascii')},
        'cookie': {'header': 'Cookie',
                   'payloads': security_utils.get_fuzz_strings('ascii')},
        'host': {'header': 'Host',
                 'payloads': security_utils.get_fuzz_strings('ascii')},
        'content_type': {'header': 'Content-Type',
                         'payloads': security_utils.get_fuzz_strings('ascii')},
        'accept_enc': {'header': 'Accept-Encoding',
                       'payloads': security_utils.get_fuzz_strings('ascii')},
        'user_agent': {'header': 'User-Agent',
                       'payloads': security_utils.get_fuzz_strings('ascii')},
        'connection': {'header': 'Connection',
                       'payloads': security_utils.get_fuzz_strings('ascii')},

    })
    """
    '''
    @utils.parameterized_dataset(fuzz_header_dataset)
    @testcase.attr('negative')
    def test_fuzz_authed_header(self, **kwargs):
        """Fuzzes all headers w/ random bytes, with a token

        Should return [201, 406, 415]"""
        model = secret_models.SecretModel(**secret_create_defaults_data)

        for payload in kwargs['payloads']:
            if payload.strip():
                headers = {kwargs['header']: payload}

                resp = self.client.post('secrets', request_model=model,
                                        extra_headers=headers)
                if kwargs['header'] == 'Content-Type':
                    self.assertEqual(resp.status_code, 415)
                elif kwargs['header'] == 'Host':
                    self.assertEqual(resp.status_code, 200)
                    print resp.headers['location']
                elif kwargs['header'] == 'Accept':
                    self.assertEqual(resp.status_code, 406)
                else:
                    self.assertIn(resp.status_code, [201, 406, 415])
    '''
    @utils.parameterized_dataset(fuzz_header_dataset)
    @testcase.attr('negative')
    def test_fuzz_unauthed_header(self, **kwargs):
        """Fuzzes all headers w/ random bytes, without a token

        Should return 401"""
        model = secret_models.SecretModel(**secret_create_defaults_data)

        for payload in kwargs['payloads']:
            if payload.strip():
                headers = {kwargs['header']: payload}

                resp = self.client.post('secrets', request_model=model,
                                        extra_headers=headers, use_auth=False)
                self.assertEqual(resp.status_code, 401)
