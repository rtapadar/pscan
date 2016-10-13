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

import errno
import gevent.monkey
import gevent.pool
import netaddr
import prettytable
from pscan import exceptions as exc
import resource
import socket
gevent.monkey.patch_all()

soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))

min_port = 1
max_port = 65535
pool_size = soft


class Port(object):
    """Contains information for a specific port on a host."""

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.status = "Closed"


class Host(object):
    """Contains information of a host and its ports to be scanned."""

    def __init__(self, ip, ports=[]):
        self.ip = netaddr.IPAddress(ip)
        self.ports = [Port(self, port) for port in ports]

    def get_ports(self):
        return self.ports


class Scan(object):
    """Creates the scanner object. Importable as a module."""

    def __init__(self, hosts, ports):
        self.pool = gevent.pool.Pool(pool_size)
        self.protocol = None
        self.inet = None
        self.result = prettytable.PrettyTable(["Port", "Protocol",
                                               "State", "Service"])
        if not ports:
            self.ports = range(min_port, max_port+1)
        else:
            try:
                self.ports = self._parse_ports(ports)
            except Exception:
                raise exc.InvalidPortRange
        try:
            self.hosts = self._parse_hosts(hosts)
        except Exception:
            raise exc.InvalidIPRange

    def _parse_hosts(self, hosts):
        """Parses the list of hosts and creates corresponding objects."""

        ip_list = [str(ip) for ip in list(netaddr.IPNetwork(hosts))]
        if netaddr.valid_ipv4(ip_list[0]):
            self.inet = socket.AF_INET
        elif netaddr.valid_ipv6(ip_list[0]):
            self.inet = socket.AF_INET6
        return [Host(ip, self.ports) for ip in ip_list]

    def _parse_ports(self, ports):
        """Parses the range of port numbers for validity."""

        ports = ports.split('-')
        minport = int(ports[0])
        maxport = minport
        if len(ports) == 2:
            maxport = int(ports[1])
        elif len(ports) > 2:
            raise
        if minport < min_port or maxport > max_port or minport > maxport:
            raise
        return range(minport, maxport+1)

    def _scan(self, f):
        for host in self.hosts:
            for port in host.get_ports():
                self.pool.spawn(f, port)
            self.pool.join()

    def _tcp(self, port):
        try:
            sock = socket.socket(self.inet, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((str(port.host.ip), port.port))
        except Exception as e:
            if e.errno == errno.ECONNREFUSED:
                port.status = "Closed"
            else:
                pass
        else:
            port.status = "Open"
        sock.close()

    def tcp(self):
        """Performs a TCP scan."""

        self.protocol = "TCP"
        self._scan(self._tcp)

    def udp(self):
        """Performs a UDP scan."""

        self.protocol = "UDP"
        print("NOTE: The code for UDP Scanning is not complete."
              " Hence the scan result may not be correct.\n")
        # self._scan(self._udp)

    def _get_service(self, portnum):
        """Returns the service name for a given port."""

        try:
            service = socket.getservbyport(portnum)
        except Exception:
            service = "unknown"
        return service

    def show(self):
        """Displays the scanned results."""

        for host in self.hosts:
            print("Showing results for target: " + str(host.ip))
            single_port = False
            display_table = False
            ports = host.get_ports()
            if len(ports) == 1:
                single_port = True
                display_table = True
            for port in ports:
                if single_port:
                    self.result.add_row([port.port, self.protocol,
                                         port.status,
                                         self._get_service(port.port)])
                elif "Open" in port.status:
                    self.result.add_row([port.port, self.protocol,
                                         port.status,
                                         self._get_service(port.port)])
                    display_table = True
            if not display_table:
                print("All " + str(len(ports)) +
                      " scanned ports are closed on the target.")
            else:
                print(self.result)
            self.result.clear_rows()
