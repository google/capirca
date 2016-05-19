# Copyright 2015 Google Inc. All Rights Reserved.
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
# Network access control library and utilities
#
# capirca/__init__.py
#
# This package is intended to simplify the process of developing
# and working with large numbers of network access control lists
# for various platforms that share common network and service
# definitions.
#
# from capirca import naming
# from capirca import policy
# from capirca import cisco
# from capirca import gce
# from capirca import juniper
# from capirca import iptables
# from capirca import policyreader
# from capirca import aclcheck
# from capirca import aclgenerator
# from capirca import nacaddr
# from capirca import packetfilter
# from capirca import port
# from capirca import speedway
#

__version__ = '1.0.0'

__all__ = ['naming', 'policy', 'cisco', 'juniper', 'iptables',
           'policyreader', 'aclcheck', 'aclgenerator', 'nacaddr',
           'packetfilter', 'port', 'speedway', 'gce']

__author__ = 'Paul (Tony) Watson (watson@gmail.com / watson@google.com)'
