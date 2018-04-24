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
"""Demo generator for capirca."""

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

     This is created to be a demo.
  """
  _ACTIONS = {'accept': 'allow',
              'deny': 'discard',
              'reject': 'say go away to',
              'next': 'pass it onto the next term',
              'reject-with-tcp-rst': 'reset'
             }

  def __init__(self, term, term_type):
    self.term = term
    self.term_type = term_type

  def __str__(self):
    # Verify platform specific terms. Skip whole term if platform does not
    # match.
    if self.term.platform:
      if 'demo' not in self.term.platform:
        return ''
    if self.term.platform_exclude:
      if 'demo' in self.term.platform_exclude:
        return ''

    ret_str = []

    # NAME
    ret_str.append(' ' * 4 + 'Term: '+self.term.name+'{')

    # COMMENTS
    if self.term.comment:
      ret_str.append(' ')
      ret_str.append(' ' * 8 + '#COMMENTS')
      for comment in self.term.comment:
        for line in comment.split('\n'):
          ret_str.append(' ' * 8 + '#'+line)

    # SOURCE ADDRESS
    source_address = self.term.GetAddressOfVersion(
        'source_address', self.AF_MAP.get(self.term_type))
    source_address_exclude = self.term.GetAddressOfVersion(
        'source_address_exclude', self.AF_MAP.get(self.term_type))
    if source_address:
      ret_str.append(' ')
      ret_str.append(' ' * 8 + 'Source IP\'s')
      for saddr in source_address:
        ret_str.append(' ' * 8 + str(saddr))

    # SOURCE ADDRESS EXCLUDE
    if source_address_exclude:
      ret_str.append(' ')
      ret_str.append(' ' * 8 + 'Excluded Source IP\'s')
      for ex in source_address:
        ret_str.append(' ' * 8 + str(ex))

    # SOURCE PORT
    if self.term.source_port:
      ret_str.append(' ')
      ret_str.append(' ' * 8 + 'Source ports')
      ret_str.append(' ' * 8 + self._Group(self.term.source_port))

    # DESTINATION
    destination_address = self.term.GetAddressOfVersion(
        'destination_address', self.AF_MAP.get(self.term_type))
    destination_address_exclude = self.term.GetAddressOfVersion(
        'destination_address_exclude', self.AF_MAP.get(self.term_type))
    if destination_address:
      ret_str.append(' ')
      ret_str.append(' ' * 8 + 'Destination IP\'s')
      for daddr in destination_address:
        ret_str.append(' ' * 8 + str(daddr))

    # DESINATION ADDRESS EXCLUDE
    if destination_address_exclude:
      ret_str.append(' ')
      ret_str.append(' ' * 8 + 'Excluded Destination IP\'s')
      for ex in destination_address_exclude:
        ret_str.append(' ' * 8 + str(ex))

    # DESTINATION PORT
    if self.term.destination_port:
      ret_str.append(' ')
      ret_str.append(' ' * 8 + 'Destination Ports')
      ret_str.append(' ' * 8 + self._Group(self.term.destination_port))

    # PROTOCOL
    if self.term.protocol:
      ret_str.append(' ')
      ret_str.append(' ' * 8 + 'Protocol')
      ret_str.append(' ' * 8 + self._Group(self.term.protocol))

    # OPTION
    if self.term.option:
      ret_str.append(' ')
      ret_str.append(' ' * 8 + 'Options')
      for option in self.term.option:
        ret_str.append(' ' * 8 + option)

    # ACTION
    for action in self.term.action:
      ret_str.append(' ')
      ret_str.append(' ' * 8 + 'Action: '
                     + self._ACTIONS.get(str(action))+' all traffic')
    return '\n '.join(ret_str)

  def _Group(self, group):
    def _FormattedGroup(el):
      if isinstance(el, str):
        return el.lower()
      elif isinstance(el, int):
        return str(el)
      elif el[0] == el[1]:
        return '%d' % el[0]
      else:
        return '%d-%d' % (el[0], el[1])
    if len(group) > 1:
      rval = ''
      for item in group:
        rval = rval + str(item[0])+' '
    else:
      rval = _FormattedGroup(group[0])
    return rval


class Demo(aclgenerator.ACLGenerator):
  """Demo rendering class.

     This class takes a policy object and renders output into
     a syntax which is not useable by routers. This class should
     only be used for testing and understanding how to create a
     generator of your own.

     Args:
       pol: policy.Policy object
     Steps to implement this library
     1) Import library in aclgen.py
     2) Create a 3 letter entry in the table in the render_filters
          function for the demo library and set it to False
     3) In the for header in policy.headers: use the previous entry
          to add an if statement to create a deep copy of the
          policy object
     4) Create an if statement that will be used if that specific
          policy object is present will pass the policy file
          onto the demo Class.
     5) The returned object can be then printed to a file using the
          do_output_filter function
     6) Create a policy file with a target set to use demo
  """
  _PLATFORM = 'demo'
  _SUFFIX = '.demo'

  _OPTIONAL_SUPPORTED_KEYWORDS = set(['expiration',])

  def _TranslatePolicy(self, pol, exp_info):
    current_date = datetime.date.today()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)
    self.demo_policies = []
    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue
      filter_options = header.FilterOptions('demo')
      filter_name = filter_options[0]
      if len(filter_options) > 1:
        interface_specific = filter_options[1]
      else:
        interface_specific = 'none'
      filter_type = 'inet'
      term_names = set()
      new_terms = []
      for term in terms:
        if term.name in term_names:
          raise DemoFilterError('Duplicate term name')
        term_names.add(term.name)
        if term.expiration:
          if term.expiration <= exp_info_date:
            logging.info('INFO: Term %s in policy %s expires '
                         'in less than two weeks.', term.name, filter_name)
          if term.expiration <= current_date:
            logging.warn('WARNING: Term %s in policy %s is expired and '
                         'will not be rendered.', term.name, filter_name)
            continue
        new_terms.append(Term(term, filter_type))
      self.demo_policies.append((header, filter_name, filter_type,
                                 interface_specific, new_terms))

  def __str__(self):
    target = []
    for (header, filter_name, filter_type,
         interface_specific, terms) in self.demo_policies:
      target.append('Header {')
      target.append(' ' * 4 + 'Name: %s {' % filter_name)
      target.append(' ' * 8 + 'Type: %s ' % filter_type)
      for comment in header.comment:
        for line in comment.split('\n'):
          target.append(' ' * 8 + 'Comment: %s'%line)
      target.append(' ' * 8 + 'Family type: %s'%interface_specific)
      target.append(' ' * 4 +'}')
      for term in terms:
        target.append(str(term))
        target.append(' ' * 4 +'}')
        target.append(' ')
      target.append('}')
    return '\n'.join(target)


class Error(Exception):
  pass


class DemoFilterError(Error):
  pass
