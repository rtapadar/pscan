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
import errno
import mock
from StringIO import StringIO
import sys


class TestScan(TestPscan):

    @mock.patch('socket.socket.connect')
    def test_tcp_port_open(self, mock_connect):
        hosts = "127.0.0.1"
        ports = "22"
        mock_connect.return_value = None
        scanner = self.get_scanner_obj(hosts, ports)
        scanner.tcp()
        h = self.get_host_obj(hosts, [22])
        h[0].ports[0].status = "Open"
        self.assertPortsEqual(scanner.hosts[0].ports,
                              h[0].ports)

    @mock.patch('socket.socket.connect')
    def test_tcp_port_closed(self, mock_connect):
        hosts = "127.0.0.1"
        ports = "22"
        mock_connect.side_effect = IOError()
        scanner = self.get_scanner_obj(hosts, ports)
        scanner.tcp()
        h = self.get_host_obj(hosts, [22])
        h[0].ports[0].status = "Closed"
        self.assertPortsEqual(scanner.hosts[0].ports,
                              h[0].ports)

    @mock.patch('socket.socket.connect')
    def test_tcp_port_range(self, mock_connect):
        hosts = "127.0.0.1"
        ports = "21-22"
        mock_connect.return_value = None
        mock_connect.side_effect = [IOError(), None]
        scanner = self.get_scanner_obj(hosts, ports)
        scanner.tcp()
        h = self.get_host_obj(hosts, [21, 22])
        h[0].ports[0].status = "Closed"
        h[0].ports[1].status = "Open"
        self.assertPortsEqual(scanner.hosts[0].ports,
                              h[0].ports)

    @mock.patch('socket.socket.connect')
    def test_show_open_port(self, mock_connect):
        hosts = "127.0.0.1"
        ports = "5672"
        mock_connect.return_value = None
        scanner = self.get_scanner_obj(hosts, ports)
        scanner.tcp()
        s = sys.stdout
        o = StringIO()
        sys.stdout = o
        output = (
        "Showing results for target: 127.0.0.1\n"
        "+------+----------+-------+---------+\n"
        "| Port | Protocol | State | Service |\n"
        "+------+----------+-------+---------+\n"
        "| 5672 |   TCP    |  Open |   amqp  |\n"
        "+------+----------+-------+---------+"
        )
        scanner.show()
        self.assertEqual(o.getvalue().strip(), output)
        sys.stdout = s

    @mock.patch('socket.socket.connect')
    def test_show_closed_port(self, mock_connect):
        hosts = "127.0.0.1"
        ports = "5673"
        mock_connect.side_effect = IOError()
        scanner = self.get_scanner_obj(hosts, ports)
        scanner.tcp()
        s = sys.stdout
        o = StringIO()
        sys.stdout = o
        output = (
        "Showing results for target: 127.0.0.1\n"
        "+------+----------+--------+---------+\n"
        "| Port | Protocol | State  | Service |\n"
        "+------+----------+--------+---------+\n"
        "| 5673 |   TCP    | Closed | unknown |\n"
        "+------+----------+--------+---------+"
        )
        scanner.show()
        self.assertEqual(o.getvalue().strip(), output)
        sys.stdout = s

    @mock.patch('socket.socket.connect')
    def test_show_closed_port_range(self, mock_connect):
        hosts = "127.0.0.1"
        ports = "5673-5674"
        mock_connect.side_effect = IOError(errno.ECONNREFUSED)
        scanner = self.get_scanner_obj(hosts, ports)
        scanner.tcp()
        s = sys.stdout
        o = StringIO()
        sys.stdout = o
        output = (
        "Showing results for target: 127.0.0.1\n"
        "All 2 scanned ports are closed on the target."
        )
        scanner.show()
        self.assertEqual(o.getvalue().strip(), output)
        sys.stdout = s

    @mock.patch('socket.socket.connect')
    def test_show_partially_open_port_range(self, mock_connect):
        hosts = "127.0.0.1"
        ports = "5671-5672"
        mock_connect.return_value = None
        mock_connect.side_effect = [IOError(), None]
        scanner = self.get_scanner_obj(hosts, ports)
        scanner.tcp()
        s = sys.stdout
        o = StringIO()
        sys.stdout = o
        output = (
        "Showing results for target: 127.0.0.1\n"
        "+------+----------+-------+---------+\n"
        "| Port | Protocol | State | Service |\n"
        "+------+----------+-------+---------+\n"
        "| 5672 |   TCP    |  Open |   amqp  |\n"
        "+------+----------+-------+---------+"
        )
        scanner.show()
        self.assertEqual(o.getvalue().strip(), output)

    @mock.patch('socket.socket.connect')
    def test_udp_port_open(self, mock_connect):
        hosts = "127.0.0.1"
        ports = "53"
        mock_connect.return_value = None
        scanner = self.get_scanner_obj(hosts, ports)
        scanner.udp()
        #h = self.get_host_obj(hosts, [22])
        #h[0].ports[0].status = "Open"
        #self.assertPortsEqual(scanner.hosts[0].ports,
        #                      h[0].ports)
