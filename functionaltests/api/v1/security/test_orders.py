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
import json
import sys

from testtools import testcase

from barbican.tests import utils
from functionaltests.api import base
from functionaltests.api.v1.behaviors import order_behaviors
from functionaltests.api.v1.behaviors import secret_behaviors
from functionaltests.api.v1.models import order_models


order_create_defaults_data = {
    'type': 'key',
    "meta": {
        "name": "barbican functional test secret name",
        "algorithm": "aes",
        "bit_length": 256,
        "mode": "cbc",
        "payload_content_type": "application/octet-stream",
    }
}

# Any field with None will be created in the model with None as the value
# but will be omitted in the final request (via the requests package)
# to the server.
#
# Given that fact, order_create_nones_data is effectively an empty json request
# to the server.
order_create_nones_data = {
    'type': None,
    "meta": {
        "name": None,
        "algorithm": None,
        "bit_length": None,
        "mode": None,
        "payload_content_type": None,
    }
}


@utils.parameterized_test_case
class OrdersTestCase(base.TestCase):

    def setUp(self):
        super(OrdersTestCase, self).setUp()
        self.behaviors = order_behaviors.OrderBehaviors(self.client)
        self.secret_behaviors = secret_behaviors.SecretBehaviors(self.client)
        self.default_data = copy.deepcopy(order_create_defaults_data)
        self.nones_data = copy.deepcopy(order_create_nones_data)
        self.dummy_ref = 'orders/bc7da070-7b86-4071-935d-ef6b83729200'
        self.dummy_proj_id = 'abcdefg'

    def tearDown(self):
        self.behaviors.delete_all_created_orders()
        super(OrdersTestCase, self).tearDown()

    # UNAUTHED #

    @testcase.attr('negative')
    def test_unauthed_create_no_proj_id(self):
        model = order_models.OrderModel(**self.default_data)

        resp = self.client.post(
            'orders', request_model=model, use_auth=False)
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative')
    def test_unauthed_get_no_proj_id(self):
        resp = self.client.get(self.dummy_ref, use_auth=False)
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative')
    def test_unauthed_gets_no_proj_id(self):
        resp = self.client.get('orders', use_auth=False)
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative')
    def test_unauthed_delete_no_proj_id(self):
        resp = self.client.delete(self.dummy_ref, use_auth=False)
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative')
    def test_unauthed_create_w_proj_id(self):
        model = order_models.OrderModel(**self.default_data)
        headers = {'X-Project-Id': self.dummy_proj_id}
        resp = self.client.post(
            'orders', request_model=model, use_auth=False,
            extra_headers=headers)
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative')
    def test_unauthed_get_w_proj_id(self):
        headers = {'X-Project-Id': self.dummy_proj_id}
        resp = self.client.get(
            self.dummy_ref, use_auth=False, extra_headers=headers)
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative')
    def test_unauthed_gets_w_proj_id(self):
        headers = {'X-Project-Id': self.dummy_proj_id}
        resp = self.client.get('orders', use_auth=False, extra_headers=headers)
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative')
    def test_unauthed_delete_w_proj_id(self):
        headers = {'X-Project-Id': self.dummy_proj_id}
        resp = self.client.delete(
            self.dummy_ref, use_auth=False, extra_headers=headers)
        self.assertEqual(401, resp.status_code)
