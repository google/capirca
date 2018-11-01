"""Google Cloud Armor Firewall Generator.

Refer to the links below for more information
https://cloud.google.com/armor/
https://cloud.google.com/armor/docs/
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals


import copy
import datetime
import json
import logging

from capirca.lib import aclgenerator


# Generic error class
class Error(Exception):
  """Generic error class."""


class Term(aclgenerator.Term):
  """Generates the Term for CloudArmor"""
  ACTION_MAP = {'accept': 'allow',
                'deny': 'deny(404)'}
  def __init__(self, term, priority):
    super(Term, self).__init__(term)
    self.term = term
    self.term.priority = priority

  def __str__(self):
    return ''

  def ConvertToDict(self):
    """Convert term to CloudArmor's JSON structure"""
    term_dict = {}
    rules = []

    term_dict['description'] = ' '.join(self.term.comment)
    term_dict['priority'] = int(self.term.priority)
    term_dict['action'] = self.ACTION_MAP[self.term.action[0]]
    term_dict['match'] = {'versionedExpr': 'SRC_IPS_V1', 'config': {}}
    term_dict['preview'] = False

    saddrs_ipv4 = self.term.GetAddressOfVersion('source_address', 4)

    rule = copy.deepcopy(term_dict)
    rule['match']['config']['srcIpRanges'] = [str(saddr) for saddr in saddrs_ipv4]
    rules.append(rule)

    return rules

class CloudArmor(aclgenerator.ACLGenerator):
  """A CloudArmor policy object"""
  _PLATFORM = 'cloudarmor'
  SUFFIX = '.ca'

  def _BuildTokens(self):
    """Build supported tokens for platform.
    """
    supported_tokens, _ = super(CloudArmor, self)._BuildTokens()
    supported_sub_tokens = {'action': {'accept', 'deny'}}
    return supported_tokens, supported_sub_tokens

  def _TranslatePolicy(self, pol, exp_info):
    self.cloudarmor_policies = []
    current_date = datetime.datetime.utcnow().date()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)

    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue

      term_counter = 1
      for term in terms:

        self.cloudarmor_policies.append(Term(term, priority=term_counter))
        term_counter = term_counter + 1

  def __str__(self):
    """Return the JSON blob for CloudArmor."""
    target = []

    for term in self.cloudarmor_policies:
      target.extend(term.ConvertToDict())
    # Sort by priority of each individual term
    target = sorted(target, key=lambda term: term['priority'])
    out = '%s\n\n' % (
        json.dumps(target, indent=2, separators=(',', ': '), sort_keys=True))
    return out
