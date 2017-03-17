# pscan
[![Build Status](https://travis-ci.org/rtapadar/pscan.svg?branch=master)](https://travis-ci.org/rtapadar/pscan)
[![Coverage Status](https://coveralls.io/repos/github/rtapadar/pscan/badge.svg?branch=master)](https://coveralls.io/github/rtapadar/pscan?branch=master)

```pscan``` is a simple python port-scanner module. Currently it can perform TCP connect scans on a range of IPv4 and IPv6 hosts.

## Prerequisites
This module has been tested with Python 2.7.6 on Ubuntu 14.04.

## Installation
```bash
git clone https://github.com/rtapadar/pscan.git
cd pscan
sudo python setup.py install
```

## Usage
```bash
usage: pscan [-h] [-p PORT] [-sU | -sT] target

positional arguments:
  target      IP or CIDR. eg. 10.10.10.10 or 10.10.10.0/24

optional arguments:
  -h, --help  show this help message and exit
  -p PORT     port or port-range. eg. 80 or 80-100.
  -sU         UDP scan.
  -sT         TCP scan. Default is TCP scan.
  ```

## Testing
The module is tested with ```nosetests``` and ```flake8``` run by ```tox```. The script ```runtests.sh``` can be used to test the module.
```bash
./runtests.sh
```

##License
Copyright 2016 Rudrajit Tapadar

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
