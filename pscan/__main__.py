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

import argparse
from pscan import scan


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('target', action="store",
                        help="IP or CIDR. eg. 10.10.10.10 or 10.10.10.0/24")
    parser.add_argument('-p', dest='PORT',
                        help="port or port-range. eg. 80 or 80-100.")
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('-sU', action='store_true', default=False,
                       help="UDP scan.")
    group.add_argument('-sT', action='store_true', default=True,
                       help="TCP scan. Default is TCP scan.")
    args = parser.parse_args()
    try:
        ports = None
        if args.target:
            target = args.target
        if args.PORT:
            ports = args.PORT
        s = scan.Scan(target, ports)
        print("")
        print("Starting Pscan 1.0\n")
        if args.sU:
            s.udp()
        else:
            s.tcp()
        s.show()
        print("")
    except Exception as e:
        print(e.__class__.__name__ + ":" + e.message + "\n")
        parser.print_help()

if __name__ == '__main__':
    main()
