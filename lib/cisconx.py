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

"""Cisco NXOS generator."""

from lib import aclgenerator
from lib import nacaddr
from lib import summarizer
from lib import cisco
import ipaddr


class Term(cisco.Term):
  _PLATFORM = 'cisconx'

  def __init__(self, term, af=4, proto_int=False, enable_dsmo=False,
               term_remark=False, platform='cisconx'):
    super(Term, self).__init__(term, af, proto_int, enable_dsmo, term_remark, platform)

  def _GetIpString(self, addr):
    """Formats the address object for printing in the ACL.

    Args:
      addr: str or ipaddr, address
    Returns:
      An address string suitable for the ACL.
    """
    if type(addr) is nacaddr.IPv4 or type(addr) is ipaddr.IPv4Network:
      if addr.numhosts > 1:
        return '%s' % (addr.with_prefixlen)
      return 'host %s' % (addr.ip)
    if type(addr) is nacaddr.IPv6 or type(addr) is ipaddr.IPv6Network:
      if addr.numhosts > 1:
        return '%s' % (addr.with_prefixlen)
      return 'host %s' % (addr.ip)
    # TODO clarify the use case
    if type(addr) is tuple:
      return '%s %s' % summarizer.ToDottedQuad(addr, negate=False, nondsm=False)
    return addr


class CiscoNX(cisco.Cisco):
  """A cisco nxos policy object."""

  _PLATFORM = 'cisconx'
  _DEFAULT_PROTOCOL = 'ip'
  SUFFIX = '.nacl'

  # Protocols should not be emitted as numbers.
  _PROTO_INT = False

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

  def __str__(self):
    target_header = []
    target = []
    # add the p4 tags
    target.extend(aclgenerator.AddRepositoryTags('! '))

    for (header, filter_name, filter_list, terms, obj_target
         ) in self.cisco_policies:
      for filter_type in filter_list:
        target.extend(self._AppendTargetByFilterType(filter_name, filter_type))
        if filter_type == 'object-group':
          obj_target.AddName(filter_name)

        target.extend(aclgenerator.AddRepositoryTags(
          ' remark ', date=False, revision=False))

        # add a header comment if one exists
        for comment in header.comment:
          for line in comment.split('\n'):
            target.append(' remark %s' % line)

        # now add the terms
        for term in terms:
          if filter_type != "object-group":
            nxos_term = Term(term.term, term.af, False,
                             term.enable_dsmo, term.term_remark,
                             term.platform)
            term_str = str(nxos_term)
          else:
            term_str = str(term)

          if term_str:
            target.append(term_str)

      if obj_target.valid:
        target = [str(obj_target)] + target
      # ensure that the header is always first
      target = target_header + target
      target += ['', 'exit', '']
    return '\n'.join(target)

