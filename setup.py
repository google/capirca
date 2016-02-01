#!/usr/bin/python
#
# Copyright 2009 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from distutils.core import setup

setup(name='capirca',
      maintainer='Google',
      maintainer_email='capirca-dev@googlegroups.com',
      version='1.109',
      url='https://github.com/google/capirca/',
      license='Apache License, Version 2.0',
      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: Apache Software License',
          'Operating System :: OS Independent',
          'Topic :: Internet',
          'Topic :: Software Development :: Libraries',
          'Topic :: Security'],
      py_modules=['aclgen', 'definate', 'definate.generator',
                  'definate.generator_factory', 'definate.dns_generator',
                  'definate.filter_factory', 'definate.global_filter',
                  'definate.file_filter', 'definate.definition_filter',
                  'definate.yaml_validator', 'lib.arista', 'lib.aruba',
                  'lib.brocade','lib.cisco', 'lib.ciscoasa',
                  'lib.ciscoxr','lib.gce','lib.ipset',
                  'lib.iptables', 'lib.juniper', 'lib.junipersrx',
                  'lib.nacaddr', 'lib.policy', 'lib.policyreader',
                  'lib.naming', 'lib.nsxv','lib.aclcheck',
                  'lib.aclgenerator', 'lib.port', 'lib.demo', 'lib.speedway',
                  'lib.ipset', 'lib.packetfilter', 'lib.gce',
                  'third_party.ipaddr', 'third_party.ply.lex',
                  'third_party.ply.yacc'])
