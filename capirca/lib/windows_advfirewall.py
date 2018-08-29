# Copyright 2016 Google Inc. All Rights Reserved.
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
"""Windows advfirewall policy generator."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

# pylint: disable=g-importing-member
from string import Template

# pylint: disable=unused-import
# logging is used in the test mock
from capirca.lib import windows
from six.moves import range
from absl import logging


class Term(windows.Term):
  """Generate windows advfirewall policy terms."""

  _PLATFORM = 'windows_advfirewall'
  CMD_PREFIX = 'netsh advfirewall firewall '

  # Logging:
  # netsh advfirewall>set allprofiles logging allowedconnections enable"
  # netsh advfirewall>set allprofiles logging droppedconnections enable"

  # 'in' or 'out'
  _DIR_ATOM = Template('dir=${dir}')
  # 'local' or 'remote'
  _ADDR_ATOM = Template('${dir}ip=${addr}')
  _PORT_ATOM = Template('${dir}port=${port}')
  # any | Integer | icmpv4 | icmpv6 | icmpv4:type,code | icmpv6:type,code
  # | tcp | udp
  _PROTO_ATOM = Template('protocol=${protocol}')
  # 'allow' or 'block'
  _ACTION_ATOM = Template('action=${action}')

  _RULE_FORMAT = Template('add rule name=${name} enable=yes interfacetype=any '
                          '${atoms}')

  _ACTION_TABLE = {
      'accept': 'allow',
      'deny': 'block',
      'reject': 'block',
      }

  def _HandleIcmpTypes(self, icmp_types, protocols):
    # advfirewall actually puts this in the protocol spec, eg.:
    # icmpv4 | icmpv6 | icmpv4:type,code | icmpv6:type,code
    types = ['']
    if icmp_types:
      types = self.NormalizeIcmpTypes(self.term.icmp_type, protocols, self.af)
      # NormalizeIcmpTypes enforces this the af/ip version match:
      icmp_prefix = 'icmpv4'
      if self.af == 'inet6':
        icmp_prefix = 'icmpv6'

      if types:
        protocols = []
        for typ in types:
          protocols.append('%s:%d' % (icmp_prefix, typ))
        types = ['']

    # fixup for icmp v4
    for i in range(len(protocols)):
      if protocols[i] == 'icmp':
        protocols[i] = 'icmpv4'

    return (types, protocols)

  def _HandlePorts(self, src_ports, dst_ports):
    return ([self._ComposePortString(src_ports)],
            [self._ComposePortString(dst_ports)])

  def _CartesianProduct(self, src_addr, dst_addr, protocol, unused_icmp_types,
                        src_port, dst_port, ret_str):
    # At least advfirewall supports port ranges, unlike windows ipsec,
    # so the src and dst port lists will always be one element long.
    for saddr in src_addr:
      for daddr in dst_addr:
        for proto in protocol:
          ret_str.append(self._ComposeRule(
              saddr, daddr, proto, src_port[0], dst_port[0],
              self.term.action[0]))

  def _ComposeRule(self, srcaddr, dstaddr, proto, srcport, dstport, action):
    """Convert the given parameters into a netsh add rule string."""
    atoms = []
    src_label = 'local'
    dst_label = 'remote'

    # We assume a default direction of OUT, but if it's IN, the Windows
    # advfirewall changes around the remote and local labels.
    if 'in' == self.filter.lower():
      src_label = 'remote'
      dst_label = 'local'

    atoms.append(self._DIR_ATOM.substitute(dir=self.filter))

    if srcaddr.prefixlen == 0:
      atoms.append(self._ADDR_ATOM.substitute(dir=src_label, addr='any'))
    else:
      atoms.append(self._ADDR_ATOM.substitute(dir=src_label, addr=str(srcaddr)))

    if dstaddr.prefixlen == 0:
      atoms.append(self._ADDR_ATOM.substitute(dir=dst_label, addr='any'))
    else:
      atoms.append(self._ADDR_ATOM.substitute(dir=dst_label, addr=str(dstaddr)))

    if srcport:
      atoms.append(self._PORT_ATOM.substitute(dir=src_label, port=srcport))
    if dstport:
      atoms.append(self._PORT_ATOM.substitute(dir=dst_label, port=dstport))

    if proto:
      if proto == 'vrrp':
        proto = '112'
      elif proto == 'ah':
        proto = '51'
      elif proto == 'htopt':
        proto = '0'
      atoms.append(self._PROTO_ATOM.substitute(protocol=proto))

    atoms.append(self._ACTION_ATOM.substitute(
        action=self._ACTION_TABLE[action]))

    return (self.CMD_PREFIX +
            self._RULE_FORMAT.substitute(
                name=self.term_name, atoms=' '.join(atoms)))

  def _ComposePortString(self, ports):
    """Convert the list of ports tuples into a multiport range string."""
    if not ports:
      return ''

    multiports = []
    for (start, end) in ports:
      if start == end:
        multiports.append(str(start))
      else:
        multiports.append('-'.join([str(start), str(end)]))
    return ','.join(multiports)


class WindowsAdvFirewall(windows.WindowsGenerator):
  """Generates filters and terms from provided policy object."""

  _PLATFORM = 'windows_advfirewall'
  _TERM = Term
