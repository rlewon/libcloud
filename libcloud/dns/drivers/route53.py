# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

__all__ = [
    'Route53DNSDriver'
]

import time
import copy
import base64
import hmac
import datetime

from hashlib import sha1
from xml.etree import ElementTree as ET

from libcloud.utils.py3 import b

from libcloud.utils.misc import merge_valid_keys, get_new_obj
from libcloud.utils.xml import findtext, findall, fixxpath
from libcloud.dns.types import Provider, RecordType
from libcloud.dns.types import ZoneDoesNotExistError, RecordDoesNotExistError
from libcloud.dns.base import DNSDriver, Zone, Record
from libcloud.common.types import LibcloudError
from libcloud.common.aws import AWSBaseResponse
from libcloud.common.base import ConnectionUserAndKey

EXPIRATION_SECONDS = 15 * 60

API_VERSION = '2012-02-29'
API_HOST = 'route53.amazonaws.com'
API_ROOT = '/%s/' % (API_VERSION)

NAMESPACE  = 'https://%s/doc%s' %(API_HOST, API_ROOT)

class Route53Error(LibcloudError):
    def __init__(self, code, errors):
        self.code = code
        self.errors = errors or []

    def __str__(self):
        return 'Errors: %s' % (', '.join(self.errors))

    def __repr__(self):
        return('<Route53 response code=%s>' % 
                (self.code, len(self.errors)))

class Route53DNSResponse(AWSBaseResponse):
    """
    Amazon Route53 response class.
    """
    def success(self):
        return self.status in [httplib.OK, httplib.CREATED, httplib.ACCEPTED]

    def error(self):
        status = int(self.status)

        if status == 403:
            if not self.body:
                raise InvalidCredsError(str(self.status) + ': ' + self.error)
            else:
                raise InvalidCredsError(self.body)

        elif status == 400:
            context = self.connection.context
            messages = []
            if context['InvalidChangeBatch']['Messages']:
                for message in context['InvalidChangeBatch']['Messages']:
                    messages.append(message['Message'])

                raise Route53Error('InvalidChangeBatch message(s): %s ',
                        messages)

class Route53Connection(ConnectionUserAndKey):
    """
    Route53 API end point
    """
    host = API_HOST

    def pre_connect_hook(self, params, headers):
        time_string = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        headers['Date'] = time_string
        tmp = []

        auth = {'AWSAccessKeyId': self.user_id, 'Signature':
                self._get_aws_auth_b64(self.key, time_string), 'Algorithm': 'HmacSHA1'}

        for k, v in auth.items():
            tmp.append("%s=%s" % (k, v))

        headers['X-Amzn-Authorization'] = "AWS3-HTTPS " + ",".join(tmp)

        return params, headers

    def _get_aws_auth_b64(self, secret_key, time_string):

        """Fri, 09 Nov 2001 01:08:47 -0000"""

        b64_hmac = base64.b64encode(
            hmac.new(b(secret_key), b(time_string), digestmod=sha1).digest()
        )

        return b64_hmac

class Route53DNSDriver(DNSDriver):
    type = Provider.ROUTE_53
    name = 'Route53 DNS'
    connectionCls = Route53Connection

    RECORD_TYPE_MAP = {
        RecordType.NS: 'NS',
        RecordType.MX: 'MX',
        RecordType.A: 'A',
        RecordType.AAAA: 'AAAA',
        RecordType.CNAME: 'CNAME',
        RecordType.TXT: 'TXT',
        RecordType.SRV: 'SRV',
    }

    def list_zones(self):
        data = ET.XML(self.connection.request(API_ROOT + 'hostedzone').object)
        zone_data = []

        for element in data.findall(fixxpath(xpath='HostedZones/HostedZone', namespace=NAMESPACE)):
            zone_data.append(self._to_zone(element))

        return zone_data

    def _to_zone(self, elem):
        extra=None

        """
        Build an Zone object from the item dictionary.
        """
        name = findtext(element=elem, xpath='Name', namespace=NAMESPACE)
        id = findtext(element=elem, xpath='Id', namespace=NAMESPACE)
        comment = findtext(element=elem, xpath='Config/Comment', namespace=NAMESPACE)
        extra = {'comment': comment}

        zone = Zone(id=id, domain=name, type='master', ttl=0,
                driver=self, extra=extra)
        return zone


    def _to_zones(self, items):
        """
        Convert a list of items to the Zone objects.
        """

        for item in items:
            zones.append(self._to_zone(item))

        return zones

