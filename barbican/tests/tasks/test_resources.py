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

import mock

from barbican import i18n as u
from barbican.model import models
from barbican.openstack.common import timeutils
from barbican.tasks import resources
from barbican.tests import utils


class BaseOrderTestCase(utils.BaseTestCase):

    def setUp(self):
        super(BaseOrderTestCase, self).setUp()
        self.requestor = 'requestor1234'
        self.order = models.Order()
        self.order.id = "id1"
        self.order.requestor = self.requestor
        self.order.type = "key"
        self.meta = {'name': 'name',
                     'payload_content_type':
                     'application/octet-stream',
                     'algorithm': 'AES',
                     'bit_length': 256,
                     'expiration': timeutils.utcnow(),
                     'mode': 'CBC'}
        self.order.meta = self.meta

        self.external_project_id = 'keystone1234'
        self.project_id = 'projectid1234'
        self.project = models.Project()
        self.project.id = self.project_id
        self.project.external_id = self.external_project_id
        self.project_repo = mock.MagicMock()
        self.project_repo.get.return_value = self.project

        self.order.status = models.States.PENDING
        self.order.project_id = self.project_id
        self.order_repo = mock.MagicMock()
        self.order_repo.get.return_value = self.order

        self.order_repo = mock.MagicMock()
        self.order_repo.get.return_value = self.order

        self.order_plugin_meta_repo = mock.MagicMock()
        self.order_barbican_meta_repo = mock.MagicMock()

        self.secret = models.Secret()

        self.secret_repo = mock.MagicMock()
        self.secret_repo.create_from.return_value = None

        self.project_secret_repo = mock.MagicMock()
        self.project_secret_repo.create_from.return_value = None

        self.datum_repo = mock.MagicMock()
        self.datum_repo.create_from.return_value = None

        self.kek_repo = mock.MagicMock()

        self.secret_meta_repo = mock.MagicMock()

        self.container_repo = mock.MagicMock()
        self.container_repo.create_from.return_value = None

        self.container_secret_repo = mock.MagicMock()
        self.container_secret_repo.create_from.return_value = None
        self.container = models.Container()


class WhenBeginningKeyTypeOrder(BaseOrderTestCase):

    def setUp(self):
        super(WhenBeginningKeyTypeOrder, self).setUp()

        self.resource = resources.BeginTypeOrder(
            project_repo=self.project_repo,
            order_repo=self.order_repo,
            secret_repo=self.secret_repo,
            project_secret_repo=self.project_secret_repo,
            datum_repo=self.datum_repo,
            kek_repo=self.kek_repo,
            secret_meta_repo=self.secret_meta_repo,
            container_repo=self.container_repo,
            container_secret_repo=self.container_secret_repo,
            order_plugin_meta_repo=self.order_plugin_meta_repo,
            order_barbican_meta_repo=self.order_barbican_meta_repo)

    @mock.patch('barbican.plugin.resources.generate_secret')
    def test_should_process_key_order(self, mock_generate_secret):
        mock_generate_secret.return_value = self.secret
        self.resource.process(self.order.id, self.external_project_id)

        self.order_repo.get.assert_called_once_with(
            entity_id=self.order.id,
            external_project_id=self.external_project_id)
        self.assertEqual(self.order.status, models.States.ACTIVE)

        secret_info = self.order.to_dict_fields()['meta']
        mock_generate_secret.assert_called_once_with(
            secret_info,
            secret_info.get('payload_content_type',
                            'application/octet-stream'),
            self.project,
            mock.ANY
        )

    def test_should_fail_during_retrieval(self):
        # Force an error during the order retrieval phase.
        self.order_repo.get = mock.MagicMock(return_value=None,
                                             side_effect=ValueError())

        self.assertRaises(
            ValueError,
            self.resource.process,
            self.order.id,
            self.external_project_id,
        )

        # Order state doesn't change because can't retrieve it to change it.
        self.assertEqual(models.States.PENDING, self.order.status)

    def test_should_fail_during_processing(self):
        # Force an error during the processing handler phase.
        self.project_repo.get = mock.MagicMock(return_value=None,
                                               side_effect=ValueError())

        self.assertRaises(
            ValueError,
            self.resource.process,
            self.order.id,
            self.external_project_id,
        )

        self.assertEqual(models.States.ERROR, self.order.status)
        self.assertEqual(500, self.order.error_status_code)
        self.assertEqual(u._('Process TypeOrder failure seen - please contact '
                             'site administrator.'), self.order.error_reason)

    @mock.patch('barbican.plugin.resources.generate_secret')
    def test_should_fail_during_success_report_fail(self,
                                                    mock_generate_secret):
        mock_generate_secret.return_value = self.secret
        # Force an error during the processing handler phase.
        self.order_repo.save = mock.MagicMock(return_value=None,
                                              side_effect=ValueError())

        self.assertRaises(
            ValueError,
            self.resource.process,
            self.order.id,
            self.external_project_id,
        )

    def test_should_fail_during_error_report_fail(self):
        # Force an error during the error-report handling after
        # error in processing handler phase.

        # Force an error during the processing handler phase.
        self.project_repo.get = mock.MagicMock(return_value=None,
                                               side_effect=TypeError())

        # Force exception in the error-reporting phase.
        self.order_repo.save = mock.MagicMock(return_value=None,
                                              side_effect=ValueError())

        # Should see the original exception (TypeError) instead of the
        # secondary one (ValueError).
        self.assertRaises(
            TypeError,
            self.resource.process,
            self.order.id,
            self.external_project_id,
        )


class WhenUpdatingKeyTypeOrder(BaseOrderTestCase):

    def setUp(self):
        super(WhenUpdatingKeyTypeOrder, self).setUp()

        self.resource = resources.UpdateOrder(
            project_repo=self.project_repo,
            order_repo=self.order_repo,
            secret_repo=self.secret_repo,
            project_secret_repo=self.project_secret_repo,
            datum_repo=self.datum_repo,
            kek_repo=self.kek_repo,
            secret_meta_repo=self.secret_meta_repo,
            container_repo=self.container_repo,
            container_secret_repo=self.container_secret_repo)

    @mock.patch(
        'barbican.tasks.certificate_resources.modify_certificate_request')
    def test_should_fail_during_processing(self, mock_mod_cert):
        mock_mod_cert.side_effect = ValueError('Abort!')

        self.order.type = models.OrderType.CERTIFICATE

        exception = self.assertRaises(
            ValueError,
            self.resource.process,
            self.order_id,
            self.external_project_id,
            self.meta,
        )

        self.assertEqual('Abort!', exception.message)

        mock_mod_cert.assert_called_once_with(self.order, self.meta, mock.ANY)

        self.assertEqual(models.States.ERROR, self.order.status)
        self.assertEqual(500, self.order.error_status_code)
        self.assertEqual(u._('Update Order failure seen - please contact '
                             'site administrator.'), self.order.error_reason)


class WhenBeginningAsymmetricTypeOrder(BaseOrderTestCase):

    def setUp(self):
        super(WhenBeginningAsymmetricTypeOrder, self).setUp()

        self.order.type = "asymmetric"

        self.resource = resources.BeginTypeOrder(
            project_repo=self.project_repo,
            order_repo=self.order_repo,
            secret_repo=self.secret_repo,
            project_secret_repo=self.project_secret_repo,
            datum_repo=self.datum_repo,
            kek_repo=self.kek_repo,
            secret_meta_repo=self.secret_meta_repo,
            container_repo=self.container_repo,
            container_secret_repo=self.container_secret_repo,
            order_plugin_meta_repo=self.order_plugin_meta_repo,
            order_barbican_meta_repo=self.order_barbican_meta_repo)

    @mock.patch('barbican.plugin.resources.generate_asymmetric_secret')
    def test_should_process_asymmetric_order(self,
                                             mock_generate_asymmetric_secret):
        mock_generate_asymmetric_secret.return_value = self.container
        self.resource.process(self.order.id, self.external_project_id)

        self.order_repo.get.assert_called_once_with(
            entity_id=self.order.id,
            external_project_id=self.external_project_id)

        self.assertEqual(self.order.status, models.States.ACTIVE)

        secret_info = self.order.to_dict_fields()['meta']
        mock_generate_asymmetric_secret.assert_called_once_with(
            secret_info,
            secret_info.get('payload_content_type',
                            'application/octet-stream'),
            self.project,
            mock.ANY
        )

    def test_should_fail_during_retrieval(self):
        # Force an error during the order retrieval phase.
        self.order_repo.get = mock.MagicMock(return_value=None,
                                             side_effect=ValueError())

        self.assertRaises(
            ValueError,
            self.resource.process,
            self.order.id,
            self.external_project_id,
        )

        # Order state doesn't change because can't retrieve it to change it.
        self.assertEqual(models.States.PENDING, self.order.status)

    def test_should_fail_during_processing(self):
        # Force an error during the processing handler phase.
        self.project_repo.get = mock.MagicMock(return_value=None,
                                               side_effect=ValueError())

        self.assertRaises(
            ValueError,
            self.resource.process,
            self.order.id,
            self.external_project_id,
        )

        self.assertEqual(models.States.ERROR, self.order.status)
        self.assertEqual(500, self.order.error_status_code)
        self.assertEqual(u._('Process TypeOrder failure seen - please contact '
                             'site administrator.'), self.order.error_reason)

    @mock.patch('barbican.plugin.resources.generate_asymmetric_secret')
    def test_should_fail_during_success_report_fail(self,
                                                    mock_generate_asym_secret):
        mock_generate_asym_secret.return_value = self.container
        # Force an error during the processing handler phase.
        self.order_repo.save = mock.MagicMock(return_value=None,
                                              side_effect=ValueError())

        self.assertRaises(
            ValueError,
            self.resource.process,
            self.order.id,
            self.external_project_id,
        )

    def test_should_fail_during_error_report_fail(self):
        # Force an error during the error-report handling after
        # error in processing handler phase.

        # Force an error during the processing handler phase.
        self.project_repo.get = mock.MagicMock(return_value=None,
                                               side_effect=TypeError())

        # Force exception in the error-reporting phase.
        self.order_repo.save = mock.MagicMock(return_value=None,
                                              side_effect=ValueError())

        # Should see the original exception (TypeError) instead of the
        # secondary one (ValueError).
        self.assertRaises(
            TypeError,
            self.resource.process,
            self.order.id,
            self.external_project_id,
        )
