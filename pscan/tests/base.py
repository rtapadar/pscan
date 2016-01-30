#   Copyright 2016 Rudrajit Tapadar
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import netaddr
import pscan.scan as scan
import unittest


class TestPscan(unittest.TestCase):

    min_port = 1
    max_port = 65535

    def get_scanner_obj(self, hosts, ports=None):
        return scan.Scan(hosts, ports)

    def get_host_obj(self, hosts, ports=[]):
        if not ports:
            ports = range(self.min_port, self.max_port+1)
        ip_list = [str(ip) for ip in list(netaddr.IPNetwork(hosts))]
        return [scan.Host(ip, ports) for ip in ip_list]

    def assertPortEqual(self, x, y):
        self.assertHostEqual(x.host, y.host)
        self.assertEqual(x.port, y.port)
        self.assertEqual(x.status, y.status)

    def assertPortsEqual(self, x, y):
        [self.assertPortEqual(a, b) for (a, b) in zip(x, y)]

    def assertHostEqual(self, x, y):
        self.assertEqual(x.ip, y.ip)

    def assertHostsEqual(self, x, y):
        [self.assertHostEqual(a, b) for (a, b) in zip(x, y)]
