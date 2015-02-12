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

bogus_project_id = 'abcd123'


@utils.parameterized_test_case
class SecretsTestCase(base.TestCase):

    def setUp(self):
        super(SecretsTestCase, self).setUp()
        self.behaviors = secret_behaviors.SecretBehaviors(self.client)

    def tearDown(self):
        self.behaviors.delete_all_created_secrets()
        super(SecretsTestCase, self).tearDown()

    # OVERSIZED REQUESTS #
    @testcase.attr('security')
    def test_huge_bogus_name(self):
        """Create a secret with a name larger than the max field size

        Should return 413(?)"""
        test_model = secret_models.SecretModel(**secret_create_defaults_data)
        overrides = {'name': 'a' * (self.max_field_size + 1)}
        test_model.override_values(**overrides)
        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 400)

    @testcase.attr('security')
    def test_huge_bogus_algorithm(self):
        """Create a secret with a bogus algorithm larger than the max field size

        Should return 400"""
        test_model = secret_models.SecretModel(**secret_create_defaults_data)
        overrides = {'algorithm': 'a' * (self.max_field_size + 1)}
        test_model.override_values(**overrides)
        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 400)

    @testcase.attr('security')
    def test_bogus_encoding(self):
        """Create a secret with a bogus encoding, larger than the max field size

        Should return 400"""
        test_model = secret_models.SecretModel(**secret_create_defaults_data)
        overrides = {'payload_content_encoding': 'a' * (self.max_field_size
                                                        + 1)}
        test_model.override_values(**overrides)
        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 400)

    @testcase.attr('security')
    def test_huge_bogus_secret(self):
        """Create a secret with a bogus secret, larger than the max field size

        Should return 413"""
        test_model = secret_models.SecretModel(**secret_create_defaults_data)
        # overrides = {'payload': 'a' * (self.max_payload_size + 1)}
        overrides = {'payload': 'a' * 100000}
        test_model.override_values(**overrides)
        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 413)

    @testcase.attr('security')
    def test_huge_bogus_project_id(self):
        """Create a secret with a bogus 1500-character project ID

        Should return 201"""
        model = secret_models.SecretModel(**secret_create_defaults_data)
        headers = {'X-Project-Id': 'a' * 1500,
                   'X-Auth-Token': self.client._auth.token}

        resp = self.client.post('secrets', request_model=model,
                                use_auth=False, extra_headers=headers)

        self.assertEqual(resp.status_code, 201)

    '''
    @testcase.attr('security')
    def test_huger_encoding(self):
        """Create a secret with XSS encoding, larger than the max field size

        Should return 413"""
        # RETURNS 400, INVALID JSON - CAN'T READ IT ALL
        test_model = secret_models.SecretModel(**secret_create_defaults_data)
        overrides = {'payload_content_encoding': 'a' * 10000000}
        test_model.override_values(**overrides)
        resp, secret_ref = self.behaviors.create_secret(test_model)
        self.assertEqual(resp.status_code, 413)
    '''

    # CONTENT TYPES #

    @testcase.attr('security')
    def test_atom_content_type(self):
        """Create a secret, with atom+xml as content type

        Should return 415"""
        test_model = secret_models.SecretModel(**secret_create_defaults_data)
        headers = {'Content-Type': 'application/atom+xml'}
        resp, secret_ref = self.behaviors.create_secret(test_model, headers)
        self.assertEqual(resp.status_code, 415)

    # BAD CONTENT #

    @utils.parameterized_dataset(
        {'xss': ['<script>alert(1)</script>'],
         'sqli': ['\'" union all select * from users/*--'],
         'unicode': [unichr(255) + unichr(0)],
         'b64_xss': ['PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='],
         'b64_sqli': ['JyIgdW5pb24gYWxsIHNlbGVjdCAqIGZyb20gdXNlcnMvKi0t'],
         'b64_unicode': ['/w==']})
    @testcase.attr('negative')
    def test_evil_payload(self, payload):
        """Creates a secret with various evil payloads

        Should return 201"""
        model = secret_models.SecretModel(**secret_create_defaults_data)

        overrides = {'payload': payload}
        model.override_values(**overrides)

        resp, secret_ref = self.behaviors.create_secret(model)
        self.assertEqual(resp.status_code, 201)

    # UNAUTHED TESTS #

    @testcase.attr('security')
    def test_unauthed_huge_bogus_token_no_proj_id(self):
        """Create a secret with a bogus 3500-character token

        Should return 400"""

        model = secret_models.SecretModel(**secret_create_defaults_data)
        headers = {'X-Auth-Token': 'a' * 3500}

        resp = self.client.post('secrets', request_model=model,
                                use_auth=False, extra_headers=headers)

        self.assertEqual(resp.status_code, 401)

    @testcase.attr('security')
    def test_unauthed_create_no_proj_id(self):
        """Create a secret without a token or Project-Id

        Should return 400"""
        test_model = secret_models.SecretModel(**secret_create_defaults_data)

        resp = self.client.post('secrets', request_model=test_model,
                                use_auth=False)

        self.assertEqual(resp.status_code, 401)

    @testcase.attr('security')
    def test_unauthed_get_no_proj_id(self):
        """Attempt to read a secret without a token or Project-Id

        Should return 400"""
        # test_model = secret_models.SecretModel(**secret_create_defaults_data)
        secret_ref = 'http://localhost:9311/v1/secrets/'
        secret_ref += '91ff8f86-677c-428c-bda6-1b61db872add'

        headers = {'Accept': '*/*',
                   'Accept-Encoding': '*/*'}

        resp = self.client.get(secret_ref, extra_headers=headers,
                               use_auth=False)

        self.assertEqual(resp.status_code, 401)

    @testcase.attr('security')
    def test_unauthed_update_no_proj_id(self):
        """Attempt to update a secret without a token or Project-Id

        Should return 400"""
        secret_ref = 'http://localhost:9311/v1/secrets/'
        secret_ref += '91ff8f86-677c-428c-bda6-1b61db872add'
        headers = {'Content-Type': 'text/plain',
                   'Content-Encoding': 'base64'}

        resp = self.client.put(secret_ref, data=None, extra_headers=headers,
                               use_auth=False)

        self.assertEqual(resp.status_code, 401)

    @testcase.attr('security')
    def test_unauthed_delete_no_proj_id(self):
        """Attempt to delete a secret without a token or Project-Id

        Should return 400"""
        secret_ref = 'http://localhost:9311/v1/secrets/'
        secret_ref += '91ff8f86-677c-428c-bda6-1b61db872add'

        resp = self.client.delete(secret_ref, use_auth=False)

        self.assertEqual(resp.status_code, 401)

    @testcase.attr('security')
    def test_unauthed_huge_bogus_token_w_proj_id(self):
        """Create a secret with a bogus 3500-character token

        Should return 401"""

        model = secret_models.SecretModel(**secret_create_defaults_data)
        headers = {'X-Auth-Token': 'a' * 3500,
                   'X-Project-Id': bogus_project_id}

        resp = self.client.post('secrets', request_model=model,
                                use_auth=False, extra_headers=headers)

        self.assertEqual(resp.status_code, 401)

    @testcase.attr('security')
    def test_unauthed_create_w_proj_id(self):
        """Create a secret without a token

        Should return 401"""
        test_model = secret_models.SecretModel(**secret_create_defaults_data)
        headers = {'X-Project-Id': bogus_project_id}

        resp = self.client.post('secrets', request_model=test_model,
                                use_auth=False, extra_headers=headers)

        self.assertEqual(resp.status_code, 401)

    @testcase.attr('security')
    def test_unauthed_get_w_proj_id(self):
        """Attempt to read a secret without a token or Project-Id

        Should return 401"""
        secret_ref = 'http://localhost:9311/v1/secrets/'
        secret_ref += '91ff8f86-677c-428c-bda6-1b61db872add'

        headers = {'Accept': '*/*',
                   'Accept-Encoding': '*/*',
                   'X-Project-Id': bogus_project_id}

        resp = self.client.get(secret_ref, extra_headers=headers,
                               use_auth=False)

        self.assertEqual(resp.status_code, 401)

    @testcase.attr('security')
    def test_unauthed_update_w_proj_id(self):
        """Attempt to update a secret without a token or Project-Id

        Should return 401"""
        secret_ref = 'http://localhost:9311/v1/secrets/'
        secret_ref += '91ff8f86-677c-428c-bda6-1b61db872add'
        headers = {'Content-Type': 'text/plain',
                   'Content-Encoding': 'base64',
                   'X-Project-Id': bogus_project_id}

        resp = self.client.put(secret_ref, data=None, extra_headers=headers,
                               use_auth=False)

        self.assertEqual(resp.status_code, 401)

    @testcase.attr('security')
    def test_unauthed_delete_w_proj_id(self):
        """Attempt to delete a secret without a token or Project-Id

        Should return 401"""
        secret_ref = 'http://localhost:9311/v1/secrets/'
        secret_ref += '91ff8f86-677c-428c-bda6-1b61db872add'
        headers = {'X-Project-Id': bogus_project_id}

        resp = self.client.delete(secret_ref, use_auth=False,
                                  extra_headers=headers)

        self.assertEqual(resp.status_code, 401)
