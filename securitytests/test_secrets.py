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
from testtools import testcase

from tempest import clients as tempest_clients

from barbican.tests import utils
from functionaltests.api import base
from functionaltests.api.v1.behaviors import secret_behaviors
from functionaltests.api.v1.models import secret_models
from functionaltests.api.v1.security import security_utils
from functionaltests.common import client

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
bogus_secret_ref = 'secrets/91ff8f86-677c-428c-bda6-1b61db872add'


@utils.parameterized_test_case
class SecretsTestCase(base.TestCase):

    def setUp(self):
        super(SecretsTestCase, self).setUp()
        self.behaviors = secret_behaviors.SecretBehaviors(self.client)

        # set up a second client
        credentials = security_utils.SecondCreds()
        mgr = tempest_clients.Manager(credentials=credentials)
        auth_provider = mgr.get_auth_provider(credentials)
        self.client2 = client.BarbicanClient(auth_provider)
        self.behaviors2 = secret_behaviors.SecretBehaviors(self.client2)

    def tearDown(self):
        self.behaviors.delete_all_created_secrets()
        super(SecretsTestCase, self).tearDown()

    # UNAUTHED TESTS #

    @testcase.attr('security')
    def test_unauthed_huge_bogus_token_no_proj_id(self):
        """Create a secret with a bogus 3500-character token

        Should return 401"""

        model = secret_models.SecretModel(**secret_create_defaults_data)
        headers = {
            'X-Auth-Token': 'a' * 3500
        }
        resp = self.client.post(
            'secrets', request_model=model, use_auth=False,
            extra_headers=headers
        )
        self.assertEqual(resp.status_code, 401)

    @testcase.attr('security')
    def test_unauthed_create_no_proj_id(self):
        """Create a secret without a token or Project-Id

        Should return 401"""
        model = secret_models.SecretModel(**secret_create_defaults_data)
        resp = self.client.post(
            'secrets', request_model=model, use_auth=False
        )
        self.assertEqual(resp.status_code, 401)

    @testcase.attr('security')
    def test_unauthed_get_no_proj_id(self):
        """Attempt to read a secret without a token or Project-Id

        Should return 401"""
        headers = {
            'Accept': '*/*',
            'Accept-Encoding': '*/*'
        }
        resp = self.client.get(
            bogus_secret_ref, extra_headers=headers, use_auth=False
        )
        self.assertEqual(resp.status_code, 401)

    @testcase.attr('security')
    def test_unauthed_update_no_proj_id(self):
        """Attempt to update a secret without a token or Project-Id

        Should return 401"""
        headers = {
            'Content-Type': 'text/plain',
            'Content-Encoding': 'base64'
        }
        resp = self.client.put(
            bogus_secret_ref, data=None, extra_headers=headers, use_auth=False
        )
        self.assertEqual(resp.status_code, 401)

    @testcase.attr('security')
    def test_unauthed_delete_no_proj_id(self):
        """Attempt to delete a secret without a token or Project-Id

        Should return 401"""

        resp = self.client.delete(bogus_secret_ref, use_auth=False)
        self.assertEqual(resp.status_code, 401)

    @testcase.attr('security')
    def test_unauthed_huge_bogus_token_w_proj_id(self):
        """Create a secret with a bogus 3500-character token

        Should return 401"""

        model = secret_models.SecretModel(**secret_create_defaults_data)
        headers = {
            'X-Auth-Token': 'a' * 3500,
            'X-Project-Id': bogus_project_id
        }
        resp = self.client.post(
            'secrets', request_model=model, use_auth=False,
            extra_headers=headers
        )
        self.assertEqual(resp.status_code, 401)

    @testcase.attr('security')
    def test_unauthed_create_w_proj_id(self):
        """Create a secret without a token

        Should return 401"""
        model = secret_models.SecretModel(**secret_create_defaults_data)
        headers = {
            'X-Project-Id': bogus_project_id
        }
        resp = self.client.post(
            'secrets', request_model=model, use_auth=False,
            extra_headers=headers
        )
        self.assertEqual(resp.status_code, 401)

    @testcase.attr('security')
    def test_unauthed_get_w_proj_id(self):
        """Attempt to read a secret without a token or Project-Id

        Should return 401"""
        headers = {
            'Accept': '*/*',
            'Accept-Encoding': '*/*',
            'X-Project-Id': bogus_project_id
        }
        resp = self.client.get(
            bogus_secret_ref, extra_headers=headers, use_auth=False
        )
        self.assertEqual(resp.status_code, 401)

    @testcase.attr('security')
    def test_unauthed_update_w_proj_id(self):
        """Attempt to update a secret without a token or Project-Id

        Should return 401"""
        headers = {
            'Content-Type': 'text/plain',
            'Content-Encoding': 'base64',
            'X-Project-Id': bogus_project_id
        }
        resp = self.client.put(
            bogus_secret_ref, data=None, extra_headers=headers, use_auth=False
        )
        self.assertEqual(resp.status_code, 401)

    @testcase.attr('security')
    def test_unauthed_delete_w_proj_id(self):
        """Attempt to delete a secret without a token or Project-Id

        Should return 401"""
        headers = {
            'X-Project-Id': bogus_project_id
        }
        resp = self.client.delete(
            bogus_secret_ref, use_auth=False, extra_headers=headers
        )
        self.assertEqual(resp.status_code, 401)
