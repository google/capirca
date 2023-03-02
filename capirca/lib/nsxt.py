# Copyright 2015 The Capirca Project Authors All Rights Reserved.
# Copyright 2023 VMware, Inc. SPDX-License-Identifier: Apache-2.0
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

"""nsxt generator."""

import json

from absl import logging
from capirca.lib import aclgenerator
import six

_RULE_JSON = '''{
    "rules": [],
    "logging_enabled": "false",
    "target_type": "DFW",
    "resource_type": "SecurityPolicy",
    "display_name": "",
    "category": "Application",
    "is_default": "false"
}'''

_NSXT_SUPPORTED_KEYWORDS = [
  'name',
  'action',
  'resource_type',
  'display_name',
  'marked_for_delete',
  'overridden',
  'rule_id',
  'sequence_number',
  'sources_excluded',
  'destinations_excluded',
  'source_groups',
  'destination_groups',
  'services',
  'profiles',
  'logged',
  'scope',
  'disabled',
  'notes',
  'direction',
  'tag',
  'ip_protocol',
  'is_default',
  'protocol',
  'destination_port',
  'source_address',
  'destination_address',
  'source_port'
]


# generic error class
class Error(Exception):
  """Generic error class."""
  pass


class UnsupportednsxtAccessListError(Error):
  """Raised when we're give a non named access list."""
  pass


class NsxtAclTermError(Error):
  """Raised when there is a problem in a nsxt access list."""
  pass


class NsxtDuplicateTermError(Error):
  """Raised when there is a duplicate."""
  pass


class NsxtUnsupportedCriteriaOperator(Error):
  """Raised when an unsupported criteria comparison operator is encountered."""
  pass


class Term(aclgenerator.Term):
  """Creates a  single ACL Term for NSX-T."""

  def __init__(self, term, filter_type, applied_to=None, af=4):
    self.term = term
    # Our caller should have already verified the address family.
    assert af in (4, 6)
    self.af = af
    self.filter_type = filter_type
    self.applied_to = applied_to

  def __str__(self):
    """Convert term to a rule string.

    Returns:
      A rule as a string.

    """
    # Verify platform specific terms. Skip whole term if platform does not
    # match.
    if self.term.platform:
      if 'nsxt' not in self.term.platform:
        return ''
    if self.term.platform_exclude:
      if 'nsxt' in self.term.platform_exclude:
        return ''

    term_keywords = self.term.__dict__
    unsupported_keywords = []
    for key in term_keywords:
      if term_keywords[key]:
        if ('translated' not in key) and (key not in _NSXT_SUPPORTED_KEYWORDS):
            unsupported_keywords.append(key)
    if unsupported_keywords:
      logging.warning('WARNING: The keywords %s in Term %s are not supported '
                      'in Nsxt ', unsupported_keywords, self.term.name)

    name = self.term.name

    notes = ''
    if self.term.comment:
      notes = self.term.comment

    action = 'ALLOW'
    if self.term.action:
      action = self.term.action

    source_address = 'ANY'
    if self.term.source_address:
      source_address = []
      for i in self.term.source_address:
        source_address.append(str(i))

    destination_address = 'ANY'
    if self.term.destination_address:
      destination_address = []
      for i in self.term.destination_address:
        destination_address.append(str(i))

# Intentionally left with defaul values as these fields are mandatory in the API. If they need to be configured these should be extended to br read from the policy files.
    services = 'ANY'

    profiles = 'ANY'

    scope = 'ANY'

    direction = 'IN_OUT'

    tag = ''

    ip_protocol = ''
    if self.term.protocol:
      ip_protocol = self.term.protocol

    rule = {
      "action": action,
      "resource_type": "Rule",
      "display_name": name,
      "source_groups": source_address,
      "destination_groups": destination_address,
      "services": [
          services
      ],
      "profiles": [
          profiles
      ],
      "scope": [
          scope
      ],
      "notes": notes,
      "direction": direction,
      "tag": tag,
      "ip_protocol": ip_protocol
    }

    return ''.join(json.dumps(rule))


class Nsxt(aclgenerator.ACLGenerator):
  """nsxt rendering class.

    This class takes a policy object and renders the output into a syntax
    which is understood by nsxt policy.

  Attributes:
    pol: policy.Policy object

  Raises:
  UnsupportednsxtAccessListError: Raised when we're give a non named access
  list.

  """

  _PLATFORM = 'nsxt'
  _DEFAULT_PROTOCOL = 'ip'
  SUFFIX = '.nsxt'

  _OPTIONAL_SUPPORTED_KEYWORDS = set(['expiration',
                                      'logging',
                                      ])
  _FILTER_OPTIONS_DICT = {}

  def _TranslatePolicy(self, pol, exp_info):
    self.nsxt_policies = []

    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue

      filter_options = header.FilterOptions(self._PLATFORM)
      if len(filter_options) >= 2:
        filter_name = filter_options[1]

      self._ParseFilterOptions(filter_options)

      filter_type = ''
      applied_to = ''

      term_names = set()
      new_terms = []
      for term in terms:
        # Check for duplicate terms
        if term.name in term_names:
          raise NsxtDuplicateTermError('There are multiple terms named: %s' %
                                       term.name)
        term_names.add(term.name)

        term.name = self.FixTermLength(term.name)

        new_terms.append(Term(term, filter_type, applied_to, 4))

      self.nsxt_policies.append((header, filter_name, [filter_type],
                                 new_terms))

  def _ParseFilterOptions(self, filter_options):
    """Parses the target in header for filter type, section_id and applied_to.

    Args:
      filter_options: list of remaining target options

    Returns:
      A dictionary that contains fields necessary to create the firewall
      rule.

    Raises:
      UnsupportedNsxtAccessListError: Raised when we're give a non named access
      list.
    """
    # check for filter type
    if not 2 <= len(filter_options) <= 5:
      raise UnsupportedNsxtAccessListError(
          'Invalid Number of options specified: %d. Required options '
          'are: filter type and section name. Platform: %s' % (
              len(filter_options), self._PLATFORM))
    # mandatory section_name
    section_name = filter_options[0]
    # mandatory
    filter_type = filter_options[1]

    # a mixed filter outputs both ipv4 and ipv6 acls in the same output file
    good_filters = ['inet', 'inet6', 'mixed']

    # check if filter type is renderable
    if filter_type not in good_filters:
      raise UnsupportedNsxtAccessListError(
          'Access list type %s not supported by %s (good types: %s)' % (
              filter_type, self._PLATFORM, str(good_filters)))

    section_id = 0
    applied_to = None
    filter_opt_len = len(filter_options)

    if filter_opt_len > 2:
      for index in range(2, filter_opt_len):
        if index == 2 and filter_options[2] != 'securitygroup':
          section_id = filter_options[2]
          continue
        if filter_options[index] == 'securitygroup':
          if index + 1 <= filter_opt_len - 1:
            applied_to = filter_options[index + 1]
            break
          else:
            raise UnsupportedNsxtAccessListError(
                'Security Group Id is not provided for %s' % (self._PLATFORM))

    self._FILTER_OPTIONS_DICT['section_name'] = section_name
    self._FILTER_OPTIONS_DICT['filter_type'] = filter_type
    self._FILTER_OPTIONS_DICT['section_id'] = section_id
    self._FILTER_OPTIONS_DICT['applied_to'] = applied_to

  def __str__(self):
    """Render the output of the nsxt policy."""
    target_header = _RULE_JSON
    target = []

    for (_, _, _, terms) in self.nsxt_policies:

      for term in terms:
        term_str = str(term)

        if term_str:
          target.append(json.loads(term_str))

    section_name = six.ensure_str(self._FILTER_OPTIONS_DICT['section_name'])
    target_json = json.loads(target_header)
    target_json['display_name'] = section_name
    target_json['rules'] = target

    return json.dumps(target_json, indent=2)
