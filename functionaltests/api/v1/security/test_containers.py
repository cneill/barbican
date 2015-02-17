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

from barbican.tests import utils
from functionaltests.api import base
from functionaltests.api.v1.behaviors import container_behaviors
from functionaltests.api.v1.behaviors import secret_behaviors
from functionaltests.api.v1.models import container_models
from functionaltests.api.v1.models import secret_models

create_secret_defaults_data = {
    "name": "AES key",
    "expiration": "2018-02-28T19:14:44.180394",
    "algorithm": "aes",
    "bit_length": 256,
    "mode": "cbc",
    "payload": "gF6+lLoF3ohA9aPRpt+6bQ==",
    "payload_content_type": "application/octet-stream",
    "payload_content_encoding": "base64",
}

create_container_defaults_data = {
    "name": "containername",
    "type": "generic",
    "secret_refs": [
        {
            "name": "secret1",
        },
        {
            "name": "secret2",
        },
        {
            "name": "secret3"
        }
    ]
}

create_container_rsa_data = {
    "name": "rsacontainer",
    "type": "rsa",
    "secret_refs": [
        {
            "name": "public_key",
        },
        {
            "name": "private_key",
        },
        {
            "name": "private_key_passphrase"
        }
    ]
}

create_container_empty_data = {
    "name": None,
    "type": "generic",
    "secret_refs": []
}

bogus_project_id = 'abcd123'
bogus_container_ref = 'containers/bc4079ff-3416-4b53-8875-e6af3e0af8c3'


@utils.parameterized_test_case
class ContainersTestCase(base.TestCase):

    def setUp(self):
        super(ContainersTestCase, self).setUp()
        self.secret_behaviors = secret_behaviors.SecretBehaviors(self.client)
        self.behaviors = container_behaviors.ContainerBehaviors(
            self.client)

        # Set up three secrets
        secret_ref_1 = self._create_a_secret()
        secret_ref_2 = self._create_a_secret()
        secret_ref_3 = self._create_a_secret()

        create_container_defaults_data[
            'secret_refs'][0]['secret_ref'] = secret_ref_1
        create_container_defaults_data[
            'secret_refs'][1]['secret_ref'] = secret_ref_2
        create_container_defaults_data[
            'secret_refs'][2]['secret_ref'] = secret_ref_3

        create_container_rsa_data[
            'secret_refs'][0]['secret_ref'] = secret_ref_1
        create_container_rsa_data[
            'secret_refs'][1]['secret_ref'] = secret_ref_2
        create_container_rsa_data[
            'secret_refs'][2]['secret_ref'] = secret_ref_3

        self.secret_id_1 = secret_ref_1.split('/')[-1]
        self.secret_id_2 = secret_ref_2.split('/')[-1]
        self.secret_id_3 = secret_ref_3.split('/')[-1]

    def tearDown(self):
        self.secret_behaviors.delete_all_created_secrets()
        super(ContainersTestCase, self).tearDown()

    def _create_a_secret(self):
        secret_model = secret_models.SecretModel(**create_secret_defaults_data)
        resp, secret_ref = self.secret_behaviors.create_secret(secret_model)
        self.assertEqual(resp.status_code, 201)
        self.assertIsNotNone(secret_ref)

        return secret_ref

    def _get_a_secret(self, secret_id):
        resp = self.client.get('secrets/{0}'.format(secret_id))
        self.assertEqual(resp.status_code, 200)
        return resp.json()

    # OVERSIZED REQUESTS #
    @testcase.attr('security')
    def test_huge_name(self):
        """Create a container with a 1000000-len name

        RETURNING 400 FOR UNPARSEABLE JSON - NO MAX REQUEST LENGTH!
        Should return 413"""
        model = container_models.ContainerModel(
            **create_container_defaults_data)
        overrides = {'name': 'a' * 1000000}
        model.override_values(**overrides)
        resp, container_ref = self.behaviors.create_container(model)
        self.assertEqual(resp.status_code, 413)
        self.assertGreater(len(container_ref), 0)

    @testcase.attr('security')
    def test_huge_bogus_type(self):
        """Create a container with a bogus 1000000-len type

        RETURNING 400 FOR UNPARSEABLE JSON - NO MAX REQUEST LENGTH!
        Should return 413"""
        model = container_models.ContainerModel(
            **create_container_defaults_data)
        overrides = {'type': 'a' * 1000000}
        model.override_values(**overrides)
        resp, secret_ref = self.behaviors.create_container(model)
        self.assertEqual(resp.status_code, 413)

    # CONTENT TYPES #
    @utils.parameterized_dataset(
        {'atom_xml': ['application/atom+xml'],
         'app_xml': ['application/xml'],
         'txt_xml': ['text/xml'],
         'app_soap_xml': ['application/soap+xml'],
         'app_rdf_xml': ['application/rdf+xml'],
         'app_rss_xml': ['application/rss+xml'],
         'app_js': ['application/javascript'],
         'app_ecma': ['application/ecmascript'],
         'app_x_js': ['application/x-javascript'],
         'txt_js': ['text/javascript'],
         'multipart_enc': ['multipart/encrypted'],
         'multipart_form': ['multipart/form-data'],
         'app_form': ['application/x-www-form-urlencoded'],
         'app_pkcs12': ['application/x-pkcs12'],
         'msg_http': ['message/http'],
         'msg_partial': ['message/partial'],
         'example': ['example']
         })
    @testcase.attr('security')
    def test_content_type(self, payload):
        """Create a container with different content types

        Should return 415"""
        model = container_models.ContainerModel(
            **create_container_defaults_data)
        headers = {'Content-Type': payload}
        resp, secret_ref = self.behaviors.create_container(
            model, extra_headers=headers)
        self.assertEqual(resp.status_code, 415)

    # LOGIC TESTS #

    @utils.parameterized_dataset(
        {'js_link': {'name': 'js_link',
                     'payload': ['/secrets/javascript:alert(1)']},
         'unicode': {'name': 'unicode', 'payload': [unichr(255) + unichr(0)]},
         'google': {'name': 'google', 'payload': ['google.com']},
         'huge': {'name': 'huge', 'payload': ['a' * 100000]},
         'sqli1': {'name': 'sqli1', 'payload': None}
         })
    @testcase.attr('derp')
    def test_bogus_secret_ref(self, **kwargs):
        """Create a container with bogus secret_refs

        Should return 404"""
        model = container_models.ContainerModel(
            **create_container_defaults_data)
        payload = kwargs['payload']
        if kwargs['name'].startswith('sqli'):
            sec_ref = self._create_a_secret()
            overrides = {'secret_refs': [{'name': kwargs['name'],
                                          'secret_ref': sec_ref + '` or 1=1'}]}
        else:
            overrides = {'secret_refs': [{'name': kwargs['name'],
                                          'secret_ref': payload}]}
        model.override_values(**overrides)
        resp, secret_ref = self.behaviors.create_container(model)
        self.assertEqual(resp.status_code, 404)

    # UNAUTHED #

    @testcase.attr('security')
    def test_unauthed_create_huge_bogus_token_no_proj_id(self):
        """Create a container with a bogus 3500-character token

        Should return 401"""

        model = container_models.ContainerModel(
            **create_container_defaults_data)
        headers = {'X-Auth-Token': 'a' * 3500}

        resp = self.client.post('containers', request_model=model,
                                use_auth=False, extra_headers=headers)

        self.assertEqual(resp.status_code, 401)

    @testcase.attr('security')
    def test_unauthed_create_no_proj_id(self):
        """Create a secret without a token or Project-Id

        Should return 401"""
        model = container_models.ContainerModel(
            **create_container_defaults_data)

        resp = self.client.post('containers', request_model=model,
                                use_auth=False)

        self.assertEqual(resp.status_code, 401)

    @testcase.attr('security')
    def test_unauthed_get_no_proj_id(self):
        """Attempt to read a secret without a token or Project-Id

        Should return 401"""
        headers = {'Accept': '*/*',
                   'Accept-Encoding': '*/*'}

        resp = self.client.get(bogus_container_ref, extra_headers=headers,
                               use_auth=False)

        self.assertEqual(resp.status_code, 401)

    @testcase.attr('security')
    def test_unauthed_delete_no_proj_id(self):
        """Attempt to delete a secret without a token or Project-Id

        Should return 401"""
        resp = self.client.delete(bogus_container_ref, use_auth=False)

        self.assertEqual(resp.status_code, 401)

    @testcase.attr('security')
    def test_unauthed_huge_bogus_token_w_proj_id(self):
        """Create a secret with a bogus 3500-character token

        Should return 401"""
        model = container_models.ContainerModel(
            **create_container_defaults_data)

        headers = {'X-Auth-Token': 'a' * 3500,
                   'X-Project-Id': bogus_project_id}

        resp = self.client.post('containers', request_model=model,
                                use_auth=False, extra_headers=headers)

        self.assertEqual(resp.status_code, 401)

    @testcase.attr('security')
    def test_unauthed_create_w_proj_id(self):
        """Create a secret without a token

        Should return 401"""
        model = container_models.ContainerModel(
            **create_container_defaults_data)

        headers = {'X-Project-Id': bogus_project_id}

        resp = self.client.post('containers', request_model=model,
                                use_auth=False, extra_headers=headers)

        self.assertEqual(resp.status_code, 401)

    @testcase.attr('security')
    def test_unauthed_get_w_proj_id(self):
        """Attempt to read a secret without a token or Project-Id

        Should return 401"""

        headers = {'Accept': '*/*',
                   'Accept-Encoding': '*/*',
                   'X-Project-Id': bogus_project_id}

        resp = self.client.get(bogus_container_ref, extra_headers=headers,
                               use_auth=False)

        self.assertEqual(resp.status_code, 401)

    @testcase.attr('security')
    def test_unauthed_delete_w_proj_id(self):
        """Attempt to delete a secret without a token or Project-Id

        Should return 401"""
        headers = {'X-Project-Id': bogus_project_id}

        resp = self.client.delete(bogus_container_ref, use_auth=False,
                                  extra_headers=headers)

        self.assertEqual(resp.status_code, 401)
