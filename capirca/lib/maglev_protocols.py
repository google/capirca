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
"""Mgalev protocols generator for capirca."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import datetime
import logging

from capirca.lib import aclgenerator


class Term(aclgenerator.Term):
  """Used to create an individual term.

     The __str__ method must be implemented.

     Args: term policy.Term object

     This is created to be a maglev_protocols.
  """

  def __init__(self, term, term_type):
    self.term = term
    self.term_type = term_type

  def __str__(self):
    # Verify platform specific terms. Skip whole term if platform does not
    # match.
    if self.term.platform:
      if 'maglev_protocols' not in self.term.platform:
        return ''
    if self.term.platform_exclude:
      if 'maglev_protocols' in self.term.platform_exclude:
        return ''

    ret_str = []

    # NAME
    ret_str.append('# Term: '+self.term.name)

    # COMMENTS
    if self.term.comment:
      ret_str.append('# COMMENTS')
      for comment in self.term.comment:
        for line in comment.split('\n'):
          ret_str.append('# '+line)

    # PROTOCOL
    if self.term.protocol:
      ret_str.append(', '.join(self.term.protocol))

    return '\n '.join(ret_str)


class MaglevProtocols(aclgenerator.ACLGenerator):
  """maglev_protocols rendering class.

     This class takes a policy object and renders output into
     a syntax which is not useable by routers. This class should
     only be used for testing and understanding how to create a
     generator of your own.

     Args:
       pol: policy.Policy object
  """
  _PLATFORM = 'maglev_protocols'
  _SUFFIX = '.protocols'

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    # supported_tokens, _ = super(MaglevProtocols, self)._BuildTokens()
    supported_tokens = {'expiration',
                        'protocol',
                        'platform',
                        'action',
                        'comment',
                        'name',
                        'translated'}
    supported_sub_tokens = {'action': {'accept'}}
    return supported_tokens, supported_sub_tokens

  def _TranslatePolicy(self, pol, exp_info):
    current_date = datetime.date.today()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)
    self.maglev_protocols_policies = []
    if len(pol.filters) > 1:
      raise ProtocolFilterError('Multiple filters not supported')
    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue
      filter_options = header.FilterOptions('maglev_protocols')
      filter_name = filter_options[0]
      interface_specific = 'none'
      filter_type = 'inet'

      new_terms = []
      if len(terms) > 1:
        raise ProtocolFilterError('Multiple terms not supported')
      for term in terms:
        if term.expiration:
          if term.expiration <= exp_info_date:
            logging.info('INFO: Term %s in policy %s expires '
                         'in less than two weeks.', term.name, filter_name)
          if term.expiration <= current_date:
            logging.warning('WARNING: Term %s in policy %s is expired and '
                            'will not be rendered.', term.name, filter_name)
            continue
        new_terms.append(Term(term, filter_type))
      self.maglev_protocols_policies.append(
          (header, filter_name, filter_type, interface_specific, new_terms))

  def __str__(self):
    target = []
    for (_, _, _,
         _, terms) in self.maglev_protocols_policies:
      for term in terms:
        target.append(str(term))
    return '\n'.join(target)


class Error(Exception):
  pass


class ProtocolFilterError(Error):
  pass
