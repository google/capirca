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
The word beta is very generous too: this only outputs a
very, very limited subset of possible acls.
"""

__author__ = 'cburgoyne@google.com (Chris Burgoyne)'

import logging

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

  def __str__(self):
    ret_str = []
    if self.ip_ver in (4, 6):
      addresses = self.term.GetAddressOfVersion('source_address', self.ip_ver)
    else:
      addresses = []
    for a in addresses:
      ret_str.append('  host %s' % a.ip)
    return '\n'.join(ret_str)


class Aruba(aclgenerator.ACLGenerator):
  """An Aruba policy object."""

  _PLATFORM = 'aruba'
  SUFFIX = '.aruba'

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    # aruba supports so little, it's easier to build by hand and not call the
    # the super class for the usual defaults.
    supported_tokens = {'action',
                        'source_address',
                        'comment',  # we allow this to save our sanity
                        'name',  # obj attribute, not token
                        'translated',  # obj attribute, not token
                       }
    supported_sub_tokens = {'action': {'accept',}}
    return supported_tokens, supported_sub_tokens

  def _TranslatePolicy(self, pol, exp_info):
    self.aruba_policies = []

    for header, terms in pol.filters:
      filter_name = header.FilterName(self._PLATFORM)
      filter_options = header.FilterOptions(self._PLATFORM)
      ip_ver = 4
      if 'ipv6' in filter_options:
        ip_ver = 6
      new_terms = []
      for t in terms:
        if t.comment:
          logging.warn('filter %s contains comments, these are not implemented '
                       'on aruba! The comments will not be rendered.',
                       filter_name)
          break

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
