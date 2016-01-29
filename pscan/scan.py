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
udp_timeout = 0.1
pool_size = soft


class Port(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.status = "Closed"
        self.service = None


class Host(object):
    def __init__(self, ip, ports=[]):
        self.ip = netaddr.IPAddress(ip)
        self.ports = [Port(self, port) for port in ports]

    def get_ports(self):
        return self.ports


class Scan(object):
    def __init__(self, hosts, ports):
        self.pool = gevent.pool.Pool(pool_size)
        self.protocol = None
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
        ip_list = [str(ip) for ip in list(netaddr.IPNetwork(hosts))]
        return [Host(ip, self.ports) for ip in ip_list]

    def _parse_ports(self, ports):
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
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((str(port.host.ip), port.port))
            sock.close()
        except Exception as e:
            if e.errno == errno.ECONNREFUSED:
                port.status = "Closed"
            elif e.errno == errno.EMFILE:
                print(e)
        else:
            port.status = "Open"

    def _udp(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.1)
            sock.sendto("Hello", (str(port.host.ip), port.port))
            data, address = sock.recvfrom(255)
            sock.close()
        except Exception as e:
            print(e)
            port.status = "Closed"
        else:
            port.status = "Open"

    def tcp(self):
        self.protocol = "TCP"
        self._scan(self._tcp)

    def udp(self):
        self.protocol = "UDP"
        self._scan(self._udp)

    def _get_service(self, portnum):
        try:
            service = socket.getservbyport(portnum)
        except Exception:
            service = "unknown"
        return service

    def show(self):
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
                elif port.status == "Open":
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
