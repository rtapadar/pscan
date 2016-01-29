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

from base import TestPscan
from pscan import exceptions as exc


class TestArgs(TestPscan):

    def test_host_valid_ipv4(self):
        hosts = "127.0.0.1"
        scanner = self.get_scanner_obj(hosts)
        h = self.get_host_obj(hosts)
        self.assertHostsEqual(scanner.hosts, h)
        self.assertPortsEqual(scanner.hosts[0].ports,
                              h[0].ports)

    def test_host_invalid_ipv4(self):
        hosts = "260.0.0.1"
        with self.assertRaises(exc.InvalidIPRange):
            scanner = self.get_scanner_obj(hosts)

    def test_host_valid_ipv4_range(self):
        hosts = "192.168.10.0/30"
        scanner = self.get_scanner_obj(hosts)
        h = self.get_host_obj(hosts)
        self.assertHostsEqual(scanner.hosts, h)
        self.assertPortsEqual(scanner.hosts[0].ports,
                              h[0].ports)

    def test_host_invalid_ipv4_range(self):
        hosts = "192.168.10.0/33"
        with self.assertRaises(exc.InvalidIPRange):
            scanner = self.get_scanner_obj(hosts)

    def test_host_valid_ipv6(self):
        hosts = "::1"
        scanner = self.get_scanner_obj(hosts)
        h = self.get_host_obj(hosts)
        self.assertHostsEqual(scanner.hosts, h)
        self.assertPortsEqual(scanner.hosts[0].ports,
                              h[0].ports)

    def test_host_invalid_ipv6(self):
        hosts = "::O1"
        with self.assertRaises(exc.InvalidIPRange):
            scanner = self.get_scanner_obj(hosts)

    def test_host_valid_ipv6_range(self):
        hosts = "::1/127"
        scanner = self.get_scanner_obj(hosts)
        h = self.get_host_obj(hosts)
        self.assertHostsEqual(scanner.hosts, h)
        self.assertPortsEqual(scanner.hosts[0].ports,
                              h[0].ports)

    def test_host_invalid_ipv6_range(self):
        hosts = "::O1/130"
        with self.assertRaises(exc.InvalidIPRange):
            scanner = self.get_scanner_obj(hosts)

    def test_host_valid_port(self):
        hosts = "127.0.0.1"
        ports = "22"
        scanner = self.get_scanner_obj(hosts, ports)
        h = self.get_host_obj(hosts, [22])
        self.assertHostsEqual(scanner.hosts, h)
        self.assertPortsEqual(scanner.hosts[0].ports,
                              h[0].ports)

    def test_host_invalid_port(self):
        hosts = "127.0.0.1"
        ports = "0"
        with self.assertRaises(exc.InvalidPortRange):
            scanner = self.get_scanner_obj(hosts, ports)

    def test_host_valid_port_range(self):
        hosts = "127.0.0.1"
        ports = "22-23"
        scanner = self.get_scanner_obj(hosts, ports)
        h = self.get_host_obj(hosts, [22, 23])
        self.assertHostsEqual(scanner.hosts, h)
        self.assertPortsEqual(scanner.hosts[0].ports,
                              h[0].ports)

    def test_host_invalid_port_range(self):
        hosts = "127.0.0.1"
        ports = "0-10"
        with self.assertRaises(exc.InvalidPortRange):
            scanner = self.get_scanner_obj(hosts, ports)
