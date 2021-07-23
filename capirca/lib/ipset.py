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
"""Ipset iptables generator.  This is a subclass of Iptables generator.

ipset is a system inside the Linux kernel, which can very efficiently store
and match IPv4 and IPv6 addresses. This can be used to dramatically increase
performace of iptables firewall.

"""

import string

from capirca.lib import iptables
from capirca.lib import nacaddr


class Error(Exception):
  """Base error class."""


class Term(iptables.Term):
  """Single Ipset term representation."""

  _PLATFORM = 'ipset'
  _SET_MAX_LENGTH = 31
  _POSTJUMP_FORMAT = None
  _PREJUMP_FORMAT = None
  _TERM_FORMAT = None
  _COMMENT_FORMAT = string.Template(
      '-A $filter -m comment --comment "$comment"')
  _FILTER_TOP_FORMAT = string.Template('-A $filter')

  def __init__(self, *args, **kwargs):
    super().__init__(*args, **kwargs)
    # This stores tuples of set name and set contents, keyed by direction.
    # For example:
    # { 'src': ('set_name', [ipaddr object, ipaddr object]),
    #   'dst': ('set_name', [ipaddr object, ipaddr object]) }
    self.addr_sets = {}

  def _CalculateAddresses(self, src_addr_list, src_addr_exclude_list,
                          dst_addr_list, dst_addr_exclude_list):
    """Calculates source and destination address list for a term.

    Since ipset is very efficient at matching large number of
    addresses, we never return any exclude addresses. Instead
    least positive match is calculated for both source and destination
    addresses.

    For source and destination address list, three cases are possible.
    First case is when there are no addresses. In that case we return
    _all_ips.
    Second case is when there is strictly one address. In that case,
    we optimize by not generating a set, and it's then the only
    element of returned set.
    Third case is when there are more than one address in a set.
    In that case we generate a set and also return _all_ips. Note the
    difference to the first case where no set is actually generated.

    Args:
      src_addr_list: source address list of the term.
      src_addr_exclude_list: source address exclude list of the term.
      dst_addr_list: destination address list of the term.
      dst_addr_exclude_list: destination address exclude list of the term.

    Returns:
      tuple containing source address list, source address exclude list,
      destination address list, destination address exclude list in
      that order.

    """
    target_af = self.AF_MAP[self.af]
    src_addr_list = self._CalculateAddrList(src_addr_list,
                                            src_addr_exclude_list, target_af,
                                            'src')
    dst_addr_list = self._CalculateAddrList(dst_addr_list,
                                            dst_addr_exclude_list, target_af,
                                            'dst')
    return (src_addr_list, [], dst_addr_list, [])

  def _CalculateAddrList(self, addr_list, addr_exclude_list,
                         target_af, direction):
    """Calculates and stores address list for target AF and direction.

    Args:
      addr_list: address list.
      addr_exclude_list: address exclude list of the term.
      target_af: target address family.
      direction: direction in which address list will be used.

    Returns:
      calculated address list.

    """
    if not addr_list:
      addr_list = [self._all_ips]
    addr_list = [addr for addr in addr_list if addr.version == target_af]
    if addr_exclude_list:
      addr_exclude_list = [addr_exclude for addr_exclude in addr_exclude_list if
                           addr_exclude.version == target_af]
      addr_list = nacaddr.ExcludeAddrs(addr_list, addr_exclude_list)
    if len(addr_list) > 1:
      set_name = self._GenerateSetName(self.term.name, direction)
      self.addr_sets[direction] = (set_name, addr_list)
      addr_list = [self._all_ips]
    return addr_list

  def _GenerateAddressStatement(self, src_addr, dst_addr):
    """Returns the address section of an individual iptables rule.

    See _CalculateAddresses documentation. Three cases are possible here,
    and they map directly to cases in _CalculateAddresses.
    First, there can be no addresses for a direction (value is _all_ips then)
    In that case we return empty string.
    Second there can be stricly one address. In that case we return single
    address match (-s or -d).
    Third case, is when the value is _all_ips but also the set for particular
    direction is present. That's when we return a set match.

    Args:
      src_addr: ipaddr address or network object with source
        address of the rule.
      dst_addr: ipaddr address or network object with destination
        address of the rule.

    Returns:
      tuple containing source and destination address statement, in
      that order.

    """
    src_addr_stmt = ''
    dst_addr_stmt = ''
    if src_addr and dst_addr:
      if src_addr == self._all_ips:
        if 'src' in self.addr_sets:
          src_addr_stmt = ('-m set --match-set %s src' %
                           self.addr_sets['src'][0])
      else:
        src_addr_stmt = '-s %s/%d' % (src_addr.network_address,
                                      src_addr.prefixlen)
      if dst_addr == self._all_ips:
        if 'dst' in self.addr_sets:
          dst_addr_stmt = ('-m set --match-set %s dst' %
                           self.addr_sets['dst'][0])
      else:
        dst_addr_stmt = '-d %s/%d' % (dst_addr.network_address,
                                      dst_addr.prefixlen)
    return (src_addr_stmt, dst_addr_stmt)

  def _GenerateSetName(self, term_name, suffix):
    if self.af == 'inet6':
      suffix += '-v6'
    if len(term_name) + len(suffix) + 1 > self._SET_MAX_LENGTH:
      set_name_max_lenth = self._SET_MAX_LENGTH - len(suffix) - 1
      term_name = term_name[:set_name_max_lenth]
    return '%s-%s' % (term_name, suffix)


class Ipset(iptables.Iptables):
  """Ipset generator."""
  _PLATFORM = 'ipset'
  _SET_TYPE = 'hash:net'
  SUFFIX = '.ips'
  _TERM = Term
  _MARKER_BEGIN = '# begin:ipset-rules'
  _MARKER_END = '# end:ipset-rules'
  _GOOD_OPTIONS = ['nostate', 'abbreviateterms', 'truncateterms', 'noverbose',
                   'exists']

  # TODO(vklimovs): some not trivial processing is happening inside this
  # __str__, replace with explicit method
  def __str__(self):
    # Actual rendering happens in __str__, so it has to be called
    # before we do set specific part.
    iptables_output = super().__str__()
    output = []
    output.append(self._MARKER_BEGIN)
    for (_, _, _, _, terms) in self.iptables_policies:
      for term in terms:
        output.extend(self._GenerateSetConfig(term))
    output.append(self._MARKER_END)
    output.append(iptables_output)
    return '\n'.join(output)

  def _GenerateSetConfig(self, term):
    """Generates set configuration for supplied term.

    Args:
      term: input term.

    Returns:
      string that is configuration of supplied term.

    """
    output = []
    c_str = 'create'
    a_str = 'add'
    if 'exists' in self.filter_options:
      c_str = c_str + ' -exist'
      a_str = a_str + ' -exist'
    for direction in sorted(term.addr_sets, reverse=True):
      set_name, addr_list = term.addr_sets[direction]
      set_hashsize = 1 << len(addr_list).bit_length()
      set_maxelem = set_hashsize
      output.append('%s %s %s family %s hashsize %i maxelem %i' %
                    (c_str,
                     set_name,
                     self._SET_TYPE,
                     term.af,
                     set_hashsize,
                     set_maxelem))
      for address in addr_list:
        output.append('%s %s %s' % (a_str, set_name, address))
    return output
