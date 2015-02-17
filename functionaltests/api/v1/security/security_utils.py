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
import os

from tempest import auth
from tempest import config

CONF = config.CONF


def generate_test_cases(data, headers=None, parameters=None):
    override_obj = {}

    if type(data) is not list:
        data = [data]

    if headers and type(headers) is not list:
        headers = [headers]

    if parameters and type(parameters) is not list:
        parameters = [parameters]

    if headers:
        for header in headers:
            for item in data:
                override_obj[header] = item

    if parameters:
        for param in parameters:
            for item in data:
                override_obj[param] = item


def get_fuzz_strings(fuzz_string_type):
    """Get a set of fuzz strings, either by generating them or reading them
    from a file

    fuzz_string_type = ['all', 'sql', 'xss', 'xml', 'json', 'bytes']
    """

    fuzz_file_dir = '/Users/char7232/wordlists'
    fuzz_file = None
    fuzz_strings = []

    if fuzz_string_type == 'sql':
        fuzz_file = os.path.join(fuzz_file_dir, 'sql.txt')

    elif fuzz_string_type == 'xss':
        fuzz_file = os.path.join(fuzz_file_dir, 'xss.txt')

    elif fuzz_string_type == 'xml':
        fuzz_file = os.path.join(fuzz_file_dir, 'xml.txt')

    elif fuzz_string_type == 'json':
        fuzz_file = os.path.join(fuzz_file_dir, 'json.txt')

    elif fuzz_string_type == 'all':
        fuzz_file = os.path.join(fuzz_file_dir, 'all.txt')

    if fuzz_file:
        with open(fuzz_file, 'r') as f:
            contents = f.read()
            for line in contents.split('\n'):
                if line.strip():
                    fuzz_strings.append(line.strip())

    elif fuzz_string_type == 'ascii':
        for i in xrange(0, 256):
            fuzz_strings.append(chr(i))

    elif fuzz_string_type == 'unicode':
        for i in xrange(0, 0x10000):
            fuzz_strings.append(unichr(i))

    return fuzz_strings


def fuzz_model(model_type, skeleton={}, fuzz_string_type='all',
               fuzz_type='single'):
    """Take a model and a skeleton, and return a list of models with fuzz
    strings replacing parameters

    fuzz_string_type = ['all', 'sql', 'xss', 'xml', 'json', 'bytes']
    fuzz_type = ['single', 'all']"""

    temp = model_type()
    params = dir(temp)
    fuzz_strings = get_fuzz_strings(fuzz_string_type)
    fuzzed_models = []

    for fuzz_string in fuzz_strings:
        overrides = {}
        for i, variable in enumerate(params):
            if fuzz_type == 'single':
                overrides = {}

            if (callable(getattr(temp, variable))
                    or variable.startswith('__')):
                continue

            overrides[variable] = fuzz_string
            model = model_type(**skeleton)
            model.override_values(**overrides)

            if fuzz_type == 'single':
                fuzzed_models.append(model)

            elif fuzz_type == 'all':
                if i == len(params) - 1:
                    fuzzed_models.append(model)

    return fuzzed_models


class SecondCreds(auth.KeystoneV3Credentials):

    def __init__(self):
        credentials = dict(
            username=CONF.identity.admin_username + '2',
            password=CONF.identity.admin_password,
            project_name=CONF.identity.admin_tenant_name,
            domain_name=CONF.identity.admin_domain_name,
        )

        super(SecondCreds, self).__init__(**credentials)
