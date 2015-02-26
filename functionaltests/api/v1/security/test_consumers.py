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
import copy

from testtools import testcase

from barbican.tests import utils

from functionaltests.api import base
from functionaltests.api.v1.behaviors import consumer_behaviors
from functionaltests.api.v1.behaviors import container_behaviors
from functionaltests.api.v1.behaviors import secret_behaviors
from functionaltests.api.v1.models import consumer_model
from functionaltests.api.v1.models import container_models
from functionaltests.api.v1.models import secret_models

create_secret_data = {
    "name": "AES key",
    "expiration": "2018-02-28T19:14:44.180394",
    "algorithm": "aes",
    "bit_length": 256,
    "mode": "cbc",
    "payload": "gF6+lLoF3ohA9aPRpt+6bQ==",
    "payload_content_type": "application/octet-stream",
    "payload_content_encoding": "base64",
}

default_consumer_data = {
    "name": "consumername",
    "URL": "consumerURL"
}

create_container_data = {
    "name": "containername",
    "type": "generic",
    "secret_refs": [
        {
            "name": "secret1",
        },
        {
            "name": "secret2",
        }
    ]
}

@utils.parameterized_test_case
class ConsumersTestCase(base.TestCase):
    default_data = default_consumer_data

    def _create_a_secret(self):
        secret_model = secret_models.SecretModel(**create_secret_data)
        resp, secret_ref = self.secret_behaviors.create_secret(secret_model)
        self.assertEqual(resp.status_code, 201)
        self.assertIsNotNone(secret_ref)

        return secret_ref

    def setUp(self):
        super(ConsumersTestCase, self).setUp()
        self.secret_behaviors = secret_behaviors.SecretBehaviors(self.client)
        self.container_behaviors = container_behaviors.ContainerBehaviors(
            self.client
        )
        self.consumer_behaviors = consumer_behaviors.ConsumerBehaviors(
            self.client
        )

        self.consumer_data = copy.deepcopy(self.default_data)

        # Set up two secrets
        secret_ref_1 = self._create_a_secret()
        secret_ref_2 = self._create_a_secret()

        # Create a container with our secrets
        create_container_data['secret_refs'][0]['secret_ref'] = secret_ref_1
        create_container_data['secret_refs'][1]['secret_ref'] = secret_ref_2
        container_model = container_models.ContainerModel(
            **create_container_data
        )

        resp, container_ref = self.container_behaviors.create_container(
            container_model
        )
        self.assertEqual(resp.status_code, 201)
        self.assertIsNotNone(container_ref)
        self.container_ref = container_ref
        self.dummy_proj_id = 'abcdefg'

    def tearDown(self):
        self.secret_behaviors.delete_all_created_secrets()
        super(ConsumersTestCase, self).tearDown()
    
    # JUNK DATA #
    @utils.parameterized_dataset(
        {'ssh': ['ssh://127.0.0.1:22'],
         'gopher': ['gopher://127.0.0.1:80'],
         'javascript': ['javascript:alert(1)'],
         'huge': ['a' * 1000000],    # RETURNS 400 - BAD JSON
         'double_quote': ['"']
         })
    @testcase.attr('negative')
    def test_bogus_URL(self, payload):
        model = consumer_model.ConsumerModel(**self.consumer_data)
        overrides = {'URL': payload}
        model.override_values(**overrides)
        resp, consumer_data = self.consumer_behaviors.create_consumer(
            model, self.container_ref
        )
        self.assertEqual(resp.status_code, 400)

    # RESOURCE EXHAUSTION #

    '''
    @testcase.attr('negative')
    def test_many_consumers(self):
        """Test creating a huge number of consumers to look for resource
        exhaustion

        SLOW - MEMORY INTENSIVE; WILL GO UNTIL ALL MEMORY IS GONE
        Should return 200s for all requests"""
        for i in xrange(10000):
            model_data = {'name': 'a' * (250000 + i), 'URL': 'a' * 250000}
            model = consumer_model.ConsumerModel(**model_data)
            resp, consumer_data = self.consumer_behaviors.create_consumer(
                model, self.container_ref
            )
            self.assertEqual(resp.status_code, 200)
    '''
    # UNAUTHED #

    @testcase.attr('negative')
    def test_unauthed_create_no_proj_id(self):
        model = consumer_model.ConsumerModel(**self.consumer_data)
        resp = self.client.post(
            '{0}/consumers'.format(self.container_ref), request_model=model,
            use_auth=False
        )

        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative')
    def test_unauthed_gets_no_proj_id(self):
        resp = self.client.get(
            '{0}/consumers'.format(self.container_ref), use_auth=False
        )

        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative')
    def test_unauthed_delete_no_proj_id(self):
        resp = self.client.delete(
            '{0}/consumers'.format(self.container_ref), use_auth=False
        )

        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative')
    def test_unauthed_create_w_proj_id(self):
        model = consumer_model.ConsumerModel(**self.consumer_data)
        headers = {'X-Project-Id': self.dummy_proj_id}
        resp = self.client.post(
            '{0}/consumers'.format(self.container_ref), request_model=model,
            use_auth=False, extra_headers=headers
        )

        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative')
    def test_unauthed_gets_w_proj_id(self):
        headers = {'X-Project-Id': self.dummy_proj_id}
        resp = self.client.get(
            '{0}/consumers'.format(self.container_ref), use_auth=False,
            extra_headers=headers
        )

        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative')
    def test_unauthed_delete_w_proj_id(self):
        headers = {'X-Project-Id': self.dummy_proj_id}
        resp = self.client.delete(
            '{0}/consumers'.format(self.container_ref), use_auth=False,
            extra_headers=headers
        )

        self.assertEqual(401, resp.status_code)
