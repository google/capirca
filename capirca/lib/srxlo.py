# Copyright 2014 Google Inc. All Rights Reserved.
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

"""Juniper SRX generator for loopback ACLs.

This is a subclass of Juniper generator. Juniper SRX loopback filter
uses the same syntax as regular Juniper stateless ACLs, with minor
differences. This subclass effects those differences.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from capirca.lib import juniper


class Term(juniper.Term):
  """Single SRXlo term representation."""

  _PLATFORM = 'srxlo'

  def __init__(self, *args, **kwargs):
    super(Term, self).__init__(*args, **kwargs)
    self.term.protocol = ['icmp6' if x == 'icmpv6' else x
                          for x in self.term.protocol]

  def NormalizeIcmpTypes(self, icmp_types, protocols, af):
    protocols = ['icmpv6' if x == 'icmp6' else x for x in protocols]
    return super(Term, self).NormalizeIcmpTypes(icmp_types, protocols, af)


class SRXlo(juniper.Juniper):
  """SRXlo generator."""
  _PLATFORM = 'srxlo'
  SUFFIX = '.jsl'
  _TERM = Term

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    supported_tokens, supported_sub_tokens = super(SRXlo, self)._BuildTokens()
    # flexible match is MX/Trio only
    supported_tokens.remove('flexible_match_range')

    return supported_tokens, supported_sub_tokens
