#!/usr/bin/python
#
# Copyright 2011 Google Inc. All Rights Reserved.
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

"""Cisco generator."""

__author__ = 'antony@slac.stanford.edu (Antonio Ceseracciu)'

import cisco
import nacaddr
import ipaddr

class Term(cisco.Term):

  _PLATFORM = 'cisconx'

  def __init__(self, term, af=4, proto_int=True, enable_dsmo=False,
               term_remark=False, platform='cisconx'):
    super(Term, self).__init__(term, af, proto_int, enable_dsmo, term_remark, platform)
 
  def _AddressToStr(self, addr):
    # inet4
    if type(addr) is nacaddr.IPv4 or type(addr) is ipaddr.IPv4Network:
      if addr.numhosts > 1:
        addr = '%s' % (addr.with_prefixlen)
      else:
        addr = 'host %s' % (addr.ip)
    # inet6
    if type(addr) is nacaddr.IPv6 or type(addr) is ipaddr.IPv6Network:
      if addr.numhosts > 1:
        addr = '%s' % (addr.with_prefixlen)
      else:
        addr = 'host %s' % (addr.ip)
    return addr


class CiscoNX(cisco.Cisco):
  """A cisco policy object."""

  _PLATFORM = 'cisconx'
  _DEFAULT_PROTOCOL = 'ip'
  SUFFIX = '.nacl'

  # Protocols should not be emitted as numbers.
  _PROTO_INT = False

  def PlatformTermClass(self):
    return Term   # Returns Term defined above.

  def _AppendTargetByFilterType(self, filter_name, filter_type):
    """Takes in the filter name and type and appends headers.

    Args:
      filter_name: Name of the current filter
      filter_type: Type of current filter

    Returns:
      list of strings
    """
    target = []
    if filter_type == 'inet6':
      target.append('no ipv6 access-list %s' % filter_name)
      target.append('ipv6 access-list %s' % filter_name)
    else:
      target.append('no ip access-list %s' % filter_name)
      target.append('ip access-list %s' % filter_name)
    return target

