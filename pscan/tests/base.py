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

from pscan.scan import Host 
from pscan.scan import Scan
import netaddr 
import unittest

class TestPscan(unittest.TestCase):

    min_port = 1
    max_port = 65535
    
    @classmethod
    def setup(cls):
        pass

    @classmethod
    def teardown(cls):
        pass

    def get_scanner_obj(self, hosts, ports=None):
        return Scan(hosts, ports)
    
    def get_port_obj(self, hosts, ports=None):
        return Port(hosts, ports)
    
    def get_host_obj(self, hosts, ports=[]):
        if not ports:
          ports = range(self.min_port, self.max_port+1)
        ip_list = [str(ip) for ip in list(netaddr.IPNetwork(hosts))]
        return [Host(ip, ports) for ip in ip_list]

    def assertPortEqual(self, x, y):
        self.assertHostEqual(x.host, y.host)
        self.assertEqual(x.port, y.port)
        self.assertEqual(x.status, y.status)
        self.assertEqual(x.service, y.service)

    def assertPortsEqual(self, x, y):
        [self.assertPortEqual(a, b) for (a, b) in zip(x, y)]

    def assertHostEqual(self, x, y):
        self.assertEqual(x.ip, y.ip)

    def assertHostsEqual(self, x, y):
        [self.assertHostEqual(a, b) for (a, b) in zip(x, y)]
