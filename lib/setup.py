#!/usr/bin/python
#
# Copyright 2011 Google Inc. All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from distutils.core import setup

import capirca

setup(name='capirca',
      maintainer='Google',
      maintainer_email='capirca-dev@googlegroups.com',
      version=ipaddr.__version__,
      url='https://github.com/google/capirca/',
      license='Apache License, Version 2.0',
      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: Apache Software License',
          'Operating System :: OS Independent',
          'Topic :: Internet',
          'Topic :: Software Development :: Libraries',
          'Topic :: System :: Networking',
          'Topic :: Security'],
      py_modules=['naming', 'policy', 'nacaddr', 'cisco', 'ciscoasa', 'juniper',
                  'junipersrx', 'iptables', 'policyreader', 'aclcheck', 'gce',
                  'aclgenerator', 'port', 'packetfilter', 'speedway', 'demo'])
