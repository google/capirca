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

"""Aruba generator.

BETA: This only generates netdestination lists for hosts.
"""

__author__ = 'cburgoyne@google.com (Chris Burgoyne)'

from lib import aclgenerator


class Error(Exception):
  """Generic error class."""
  pass


class UnsupportedArubaAccessListError(Error):
  """Raised unsupported options are requested for Aruba ACLs."""
  pass


class Term(aclgenerator.Term):
  """Creates the term for the Aruba ACL."""

  def __init__(self, term, ip_ver):
    super(Term, self).__init__(term)
    self.term = term
    self.ip_ver = ip_ver
    # Ensuring no unused options have been set.
    if self.term.action and self.term.action[0] != 'accept':
      raise UnsupportedArubaAccessListError(
          'Aruba ACL action must be "accept".')
    if self.term.protocol:
      raise UnsupportedArubaAccessListError(
          'Aruba ACLs cannot specify protocols')
    if self.term.icmp_type:
      raise UnsupportedArubaAccessListError(
          'ICMP Type specifications are not permissible in Aruba ACLs')
    if (self.term.source_address
        or self.term.source_address_exclude
        or self.term.destination_address
        or self.term.destination_address_exclude):
      raise UnsupportedArubaAccessListError(
          'Aruba ACLs cannot use source or destination addresses')
    if self.term.option:
      raise UnsupportedArubaAccessListError(
          'Aruba ACLs prohibit use of options')
    if self.term.source_port or self.term.destination_port:
      raise UnsupportedArubaAccessListError(
          'Aruba ACLs prohibit use of port numbers')
    if self.term.counter:
      raise UnsupportedArubaAccessListError(
          'Counters are not implemented in Aruba ACLs')

  def __str__(self):
    ret_str = []
    if self.ip_ver in (4, 6):
      addresses = self.term.GetAddressOfVersion('address', self.ip_ver)
    else:
      addresses = []
    for a in addresses:
      ret_str.append('  host %s' % a.ip)
    return '\n'.join(ret_str)


class Aruba(aclgenerator.ACLGenerator):
  """An Aruba policy object."""

  _PLATFORM = 'aruba'
  SUFFIX = '.aruba'
  _OPTIONAL_SUPPORTED_KEYWORDS = set(['address'])

  def _TranslatePolicy(self, pol, exp_info):
    self.aruba_policies = []

    for header, terms in pol.filters:
      filter_name = header.FilterName(self._PLATFORM)
      filter_options = header.FilterOptions(self._PLATFORM)
      ip_ver = 4
      if 'ipv6' in filter_options:
        ip_ver = 6
      new_terms = []
      for term in terms:
        new_terms.append(Term(term, ip_ver))
      self.aruba_policies.append((filter_name, new_terms, ip_ver))

  def __str__(self):
    target = []

    # add the p4 tags
    target.extend(aclgenerator.AddRepositoryTags('! '))
    for filter_name, terms, ip_ver in self.aruba_policies:
      netdestination = 'netdestination'
      if ip_ver == 6:
        netdestination += '6'
      target.append('no %s %s' % (netdestination, filter_name))
      target.append('%s %s' % (netdestination, filter_name))

      # now add the terms
      for term in terms:
        target.append(str(term))

    if target:
      target.append('')
    return '\n'.join(target)
