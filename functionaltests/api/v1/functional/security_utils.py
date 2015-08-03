# Copyright (c) 2015 Rackspace, Inc.
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
import json
import re
import urllib


class Fuzzer(object):
    def __init__(self, default_fuzz_type='junk'):
        self.default_fuzz_type = default_fuzz_type

        self.types = [
            'sqli', 'xss', 'xml', 'json', 'ascii', 'unicode', 'content_types',
            'huge', 'junk', 'json_recursion', 'date', 'bad_numbers',
            'bad_urls', 'traversal', 'rce'
        ]

        self.named_types = [
            'content_types', 'date', 'huge', 'junk', 'xss', 'quick',
            'bad_numbers', 'bad_urls', 'traversal', 'rce', 'sqli', 'xml'
        ]

        self.content_types = {
            'atom_xml': 'application/atom+xml',
            'app_xml': 'application/xml',
            'txt_xml': 'text/xml',
            'app_soap_xml': 'application/soap+xml',
            'app_rdf_xml': 'application/rdf+xml',
            'app_rss_xml': 'application/rss+xml',
            'app_js': 'application/javascript',
            'app_ecma': 'application/ecmascript',
            'app_x_js': 'application/x-javascript',
            'txt_js': 'text/javascript',
            'app_pkcs12': 'application/x-pkcs12',
            'app_form': 'application/x-www-form-urlencoded',
            'multipart_enc': 'multipart/encrypted',
            'multipart_form': 'multipart/form-data',
            'msg_http': 'message/http',
            'msg_partial': 'message/partial',
            'junk': 'junk',
        }

        self.date = {
            'date_w_null': '2018-02-28T19:14:44.180394' + chr(0x00),
            'date_w_unicode': '2018-02-28T19:14:44.180394' + unichr(0xff),
            'date_w_format': '2018-02-28T19:%f14:44.180394',
            'huge': '2018-02-28T12:12:12.' + ('4' * 100000),
        }

        self.huge = {
            '10^3': 'a' * 10 ** 3,
            '10^4': 'a' * 10 ** 4,
            '10^5': 'a' * 10 ** 5,
            '10^6': 'a' * 10 ** 6,
            '10^7': 'a' * 10 ** 7
        }

        self.xss = {
            'double_bracket': '<<script>alert(1);//<</script>',
            'tag_close': '\'"><script>alert(1);</script>',
            'img_js_link': '<IMG SRC=javascript:alert(1)>',
            'img_js_link_w_0x0D': '<IMG SRC=jav&#x0D;ascript:alert(1);>',
            'img_js_link_overencode':
                "<IMG%20SRC='%26%23x6a;avasc%26%23000010ript:alert(1);'>",
            'iframe_js_link': '<IFRAME SRC=javascript:alert(1)></IFRAME>',
            'js_context': '\\\'";alert(1);//'
        }

        self.sqli = {
            'hex_select': '\\x27\\x4F\\x52 SELECT *',
            'hex_select_2': '\\x27\\x6F\\x72 SELECT *',
            'hex_select_raw': '\x27\x4F\x52 SELECT *',
            'hex_select_raw': '\x27\x6F\x72 SELECT *',
            'hex_union': '\\x27UNION SELECT',
            'hex_union_raw': '\x27UNION SELECT',
            'or_select': '\'"or select *',
            'or_x_is_x': '\' or \'x\'=\'x',
            '0_or_1_is_1': '0 or 1=1',
            '0_or_1_is_1_dashed': '0 or 1=1--',
            'a_or_x_is_x_dquote': 'a" or "x"="x',
            'a_or_x_is_x_squote': 'a\' or \'x\'=\'x',
            'a_or_x_is_x_paren_dqoute': 'a") or ("x"="x',
            'a_or_x_is_x_paren_sqoute': 'a\') or (\'x\'=\'x',
            'a_or_x_is_x_full_statement': '\'a\' or \'x\'=\'x\';',
            'xml':
                '<?xml version="1.0" encoding="ISO-8859-1"?><foo>'
                '<![CDATA[\'or 1=1 or \'\'=\']]></foo>'
        }

        self.xml = {
            'xml_xxe_etc_passwd':
                '<?xml version="1.0" encoding="ISO-8859-1"?>'
                '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM'
                ' "file:////etc/passwd">]><foo>&xxe;</foo>'
        }

        self.junk = {
            'nullbyte': unichr(0x00),
            'higher_ascii': unichr(0x80) + unichr(0xfe),
            'higher_unicode': unichr(0x1111) + unichr(0xffff),
            'unicode_single_quote': unichr(0x2018),
            'unicode_double_quote': unichr(0x201c),
            'null_unencoded': '\\00',
        }

        self.bad_numbers = {
            'negative_zero': '-0',
            'negative_hex': '-0xff',
            'overflow': 999999999999999,
            'negative_overflow': -999999999999999,
            'negative_float_overflow': -0.999999999999999,
            'hex_overflow': '0xffffffff',
            'extreme_overflow': 9 ** 100,
            'nullbyte': chr(0x00)
        }

        self.rce = {
            'semicolon_id': ';id',
            'or_id': '||id',
            'pipe_id': '|id',
            'and_id': '&&id',
            'nullbyte_id': unichr(0x00) + 'id',
            'urlencoded_nullbyte_id': '%00id',
            'urlencoded_newline_id': '%0aid',
            'backticks_id': '`id`',
            'close_parens_id': ');id'
        }

        self.bad_urls = {
            'javascript': 'javascript:alert(1);',
            'data_img_b64': 'data:image/png;base64,junkjunk',
            'data_xml_b64': 'data:applicaton/xml;charset=utf-8,'
                            + urllib.quote_plus('<?xml version="1.0" ?>'),
            'file_etc_passwd': 'file:///etc/passwd',
            'relative_etc_passwd': '///etc/passwd',
            'back_slashes': '\etc\passwd',
        }

        self.traversal = {
            'etc_passwd_generic':
                '../../../../../../../../../../../../etc/passwd',
            'etc_passwd_long_w_null_html':
                '../../../../../../../../../../../../etc/passwd%00.html',
            'etc_passwd_urlencoded':
                '..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cetc/passwd',
            'etc_passwd_w_null_html': '/etc/passwd%00.html',
            'etc_passwd_overencoded_w_null_html':
                '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd%00'
                'index.html',
            'etc_passwd_cwd_long': '/./././././././././././etc/passwd',
            'etc_passwd_alternating':
                '/..\../..\../..\../..\../..\../..\../etc/passwd',
            'etc_passwd_back_slashes_w_null':
                '\..\..\..\..\..\..\..\..\..\..\etc\passwd%00',
            'etc_passwd_w_nulls': '%00/etc/passwd%00',
            'etc_passwd_urlencoded_w_null':
                '/..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../'
                '..%c0%af../etc/passwd%00',
            'etc_passwd_overencoded_w_null':
                '/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/'
                '%2e%2e/%2e%2e/etc/passwd%00',
            'etc_passwd_overencoded_w':
                '%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0'
                '%2e%c0%2e%c0%5cetc/passwd',
            'etc_passwd_overencoded_backslashes':
                '%25c0%25ae%25c0%25ae\%25c0%25ae%25c0%25ae\%25c0%25ae%25c0'
                '%25ae\%25c0%25ae%25c0%25ae\%25c0%25ae%25c0%25ae\etc/passwd',
            'etc_passwd_overencoded_unicode':
                '%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e%u2216'
                '%uff0e%uff0e%u2216etc/passwd',
            'etc_passwd_urlencoded_w_null_long':
                '%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..'
                '%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..'
                'etc%25%5cpasswd%00',
            'etc_passwd_double_encoded':
                '%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/'
                '%%32%65%%32%65/etc/passwd',
            'etc_passwd_mix_back_slashes':
                '.\\..\\.\\..\\.\\..\\.\\..\\.\\..\\.\\..\\.\\..\\.\\..\\'
                'etc/passwd',
            'etc_passwd_triple_slash':
                '..///..///..///..///..///..///..///..///etc/passwd',
            'etc_passwd_long_leading_dots':
                '.' * 72 + '/../../../../../../etc/passwd'
        }

    def get_strings(self, fuzz_string_type=None, encoding=None):
        """Get a set of fuzz strings based on fuzz_string_type and encoding

        Valid types defined in self.types
        """

        fuzz_strings = []

        if fuzz_string_type not in self.types or fuzz_string_type is None:
            fuzz_string_type = self.default_fuzz_type

        # Generate fuzz strings on the fly
        elif fuzz_string_type == "ascii":
            for i in xrange(0, 256):
                fuzz_strings.append(chr(i))

        elif fuzz_string_type == "unicode":
            for i in xrange(0, 0x1000):
                fuzz_strings.append(unichr(i))
            for i in xrange(0xf800, 0x10000):  # Random
                fuzz_strings.append(unichr(i))

        elif fuzz_string_type == "content_types":
            for name in self.content_types:
                fuzz_strings.append(self.content_types[name])

        elif fuzz_string_type == "xss":
            for name in self.xss:
                fuzz_strings.append(self.xss[name])

        elif fuzz_string_type == "json_recursion":
            obj = {}
            string = 'obj["hax"]'
            for i in xrange(850):
                exec(string + ' = {}')
                string += '["hax"]'
            fuzz_strings.append(json.dumps(obj))

        # Get pre-generated fuzz strings
        elif fuzz_string_type in self.named_types:
            temp = self.__dict__[fuzz_string_type]
            for name in temp:
                fuzz_strings.append(temp[name])

        return fuzz_strings

    def get_dataset(self, fuzz_string_type):
        """Get the fuzz string dataset for use in parameterized tests"""
        strings = self.get_strings(fuzz_string_type)
        result = {}

        for string in strings:
            name = self.get_fuzz_string_name(fuzz_string_type, string)
            result[name] = [string]
        return result

    def get_datasets(self, fuzz_string_types):
        """Get multiple datasets for use in parameterized tests"""
        result = {}
        for fuzz_type in fuzz_string_types:
            strings = self.get_strings(fuzz_type)
            for string in strings:
                name = '{0}_{1}'.format(
                    fuzz_type, self.get_fuzz_string_name(fuzz_type, string)
                )
                result[name] = {'fuzz_type': fuzz_type, 'payload': string}
        return result

    def get_fuzz_string_name(self, fuzz_string_type, fuzz_string, num=False):
        """Get the name of a fuzz string (pre-defined above or generated)"""
        result = None

        if fuzz_string_type in self.named_types:
            for name, string in self.__dict__[fuzz_string_type].iteritems():
                if string == fuzz_string:
                    result = name
                    break
        else:
            # Get first 20 characters, trim trailing spaces, convert
            # non-alphanumeric characters to underscores
            fuzz_string = re.sub(
                "[^a-z0-9A-Z]*", "_", fuzz_string[:20].strip()
            )
            result = "{0}_{1}".format(fuzz_string_type, fuzz_string)
            if num is not False and isinstance(num, int):
                result = "{0}_{1}".format(result, num)
        return result

    def verify_response(self, resp, fuzz_type='generic'):
        """Look for signs of vulnerability in fuzz test response based on type

        - Assertion fail if 5XX HTTP status code
        - Assertion fail if indication of vulnerability found in respnse body
        """

        fuzz_type = fuzz_type.lower()
        text = resp.text.lower()

        assert(resp.status_code not in range(500, 600))

        # RCE should return results of `id` command, containing "uid="
        if fuzz_type == 'rce':
            assert('uid=' not in text)

        # Traversal should return /etc/passwd, containing "root:*"
        elif fuzz_type == 'traversal':
            assert('root:' not in text)

        # SQL injection should return 'SQL' or 'syntax' in body
        elif fuzz_type == 'sqli':
            assert('sql' not in text)
            assert('syntax' not in text)

        # Crude XSS filter: find alert(1) in text body
        elif fuzz_type == 'xss':
            assert('alert(1)' not in text)

        # Just run generic checks (check for 500 for now)
        elif fuzz_type == 'generic':
            pass
