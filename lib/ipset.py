#!/usr/bin/python
#
# Copyright 2013 Google Inc. All Rights Reserved.
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

__author__ = 'vklimovs@google.com (Vjaceslavs Klimovs)'

from string import Template

import iptables
import nacaddr


class Error(Exception):
  pass


class Term(iptables.Term):
  """Single Ipset term representation."""

  _PLATFORM = 'ipset'
  _SET_MAX_LENGTH = 31
  _POSTJUMP_FORMAT = None
  _PREJUMP_FORMAT = None
  _TERM_FORMAT = None
  _COMMENT_FORMAT = Template('-A $filter -m comment --comment "$comment"')
  _FILTER_TOP_FORMAT = Template('-A $filter')

  def __init__(self, *args, **kwargs):
    super(Term, self).__init__(*args, **kwargs)
    # This stores tuples of set name and set contents, keyed by direction.
    # For example:
    # { 'src': ('term_name', [ipaddr object, ipaddr object]),
    #  'dst': ('term_name', [ipaddr object, ipaddr object]) }
    self.addr_sets = dict()

  def _CalculateAddresses(self, src_addr_list, src_ex_addr_list,
                          dst_addr_list, dst_ex_addr_list):
    """Calculate source and destination address list for a term.

    Since ipset is very efficient at matching large number of
    addresses, we never return eny exclude addresses. Instead
    least positive match is calculated for both source and destination
    addresses.

    For source and destination address list, three cases are possible.
    First case is when there is no addresses. In that case we return
    _all_ips.
    Second case is when there is strictly one address. In that case,
    we optimize by not generating a set, and it's then the only
    element of returned set.
    Third case case is when there is more than one address in a set.
    In that case we generate a set and also return _all_ips. Note the
    difference to the first case where no set is actually generated.

    Args:
      src_addr_list: source address list of the term.
      src_ex_addr_list: source address exclude list of the term.
      dst_addr_list: destination address list of the term.
      dst_ex_addr_list: destination address exclude list of the term.

    Returns:
      tuple containing source address list, source exclude address list,
      destination address list, destination exclude address list in
      that order.

    """
    if not src_addr_list:
      src_addr_list = [self._all_ips]
    src_addr_list = [src_addr for src_addr in src_addr_list if
                     src_addr.version == self.AF_MAP[self.af]]
    if src_ex_addr_list:
      src_ex_addr_list = [src_ex_addr for src_ex_addr in src_ex_addr_list if
                          src_ex_addr.version == self.AF_MAP[self.af]]
      src_addr_list = nacaddr.ExcludeAddrs(src_addr_list, src_ex_addr_list)
    if len(src_addr_list) > 1:
      set_name = self._GenerateSetName(self.term.name, 'src')
      self.addr_sets['src'] = (set_name, src_addr_list)
      src_addr_list = [self._all_ips]

    if not dst_addr_list:
      dst_addr_list = [self._all_ips]
    dst_addr_list = [dst_addr for dst_addr in dst_addr_list if
                     dst_addr.version == self.AF_MAP[self.af]]
    if dst_ex_addr_list:
      dst_ex_addr_list = [dst_ex_addr for dst_ex_addr in dst_ex_addr_list if
                          dst_ex_addr.version == self.AF_MAP[self.af]]
      dst_addr_list = nacaddr.ExcludeAddrs(dst_addr_list, dst_ex_addr_list)
    if len(dst_addr_list) > 1:
      set_name = self._GenerateSetName(self.term.name, 'dst')
      self.addr_sets['dst'] = (set_name, dst_addr_list)
      dst_addr_list = [self._all_ips]
    return (src_addr_list, [], dst_addr_list, [])

  def _GenerateAddressStatement(self, src_addr, dst_addr):
    """Return the address section of an individual iptables rule.

    See _CalculateAddresses documentation. Three cases are possible here,
    and they map directly to cases in _CalculateAddresses.
    First, there can be no addresses for a direction (value is _all_ips then)
    In that case we return empty string.
    Second there can be stricly one address. In that case we return single
    address match (-s or -d).
    Third case, is when the value is _all_ips but also the set for particular
    direction is present. That's when we return a set match.

    Args:
      src_addr: source address of the rule.
      dst_addr: destination address of the rule.

    Returns:
      tuple containing source and destination address statement, in
      that order.

    """
    src_addr_stmt = ''
    dst_addr_stmt = ''
    if src_addr and dst_addr:
      if src_addr == self._all_ips:
        if 'src' in self.addr_sets:
          src_addr_stmt = ('-m set --set %s src' % self.addr_sets['src'][0])
      else:
        src_addr_stmt = '-s %s/%d' % (src_addr.ip, src_addr.prefixlen)
      if dst_addr == self._all_ips:
        if 'dst' in self.addr_sets:
          dst_addr_stmt = ('-m set --set %s dst' % self.addr_sets['dst'][0])
      else:
        dst_addr_stmt = '-d %s/%d' % (dst_addr.ip, dst_addr.prefixlen)
    return (src_addr_stmt, dst_addr_stmt)

  def _GenerateSetName(self, term_name, suffix):
    if self.af == 'inet6':
      suffix += '-v6'
    if len(term_name) + len(suffix) + 1 > self._SET_MAX_LENGTH:
      term_name = term_name[:self._SET_MAX_LENGTH -
                            (len(term_name) + len(suffix) + 1)]
    return term_name + '-' + suffix


class Ipset(iptables.Iptables):
  """Ipset generator."""
  _PLATFORM = 'ipset'
  _SET_TYPE = 'hash:net'
  _SUFFIX = '.ips'
  _TERM = Term

  def __str__(self):
    # Actual rendering happens in __str__, so it has to be called
    # before we do set specific part.
    iptables_output = iptables.Iptables.__str__(self)
    output = []
    for (_, _, _, _, terms) in self.iptables_policies:
      for term in terms:
        output.extend(self._GenerateSetConfig(term))
    output.append(iptables_output)
    return '\n'.join(output)

  def _GenerateSetConfig(self, term):
    """Generate set configuration for supplied term.

    Args:
      term: input term.

    Returns:
      string that is configuration of supplied term.

    """
    output = []
    for direction in sorted(term.addr_sets, reverse=True):
      set_hashsize = 2 ** len(term.addr_sets[direction][1]).bit_length()
      set_maxelem = 2 ** len(term.addr_sets[direction][1]).bit_length()
      output.append('create %s %s family %s hashsize %i maxelem %i' %
                    (term.addr_sets[direction][0],
                     self._SET_TYPE,
                     term.af,
                     set_hashsize,
                     set_maxelem))
      for address in term.addr_sets[direction][1]:
        output.append('add %s %s' % (term.addr_sets[direction][0], address))
    return output
