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

"""Utility to provide exploration of policy definition files.

Allows read only access of policy definition files.  The library
creates a Policy object, which has filters containing terms.

This library does no expansion on the tokens directly, such as in policy.py.

TODO: This library is currently incomplete, and does not allow access to
      every argument of a policy term.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from capirca.lib import naming


class Error(Exception):
  """Generic error class."""


class FileOpenError(Error):
  """Trouble opening a file."""


class InvalidFilterError(Error):
  """Filter is invalid."""


class Filter(object):
  """Simple filter with a name a list of terms."""

  def __init__(self, filtername=''):
    self.name = filtername
    self.term = []

  def __str__(self):
    rval = []
    title = 'Filter: %s' % str(self.name)
    rval.append('\n%s' % title)
    rval.append('-' * len(title))
    for term in self.term:
      rval.append(str(term))
    return '\n\n'.join(rval)


class Term(object):
  """Simple term with a name a list of attributes."""

  def __init__(self, termname=''):
    self.name = termname
    self.source = []
    self.destination = []
    self.sport = []
    self.dport = []
    self.action = []
    self.option = []
    self.protocol = []

  def __str__(self):
    rval = []
    rval.append('  Term: %s' % self.name)
    rval.append('  Source-address:: %s' % ' '.join(self.source))
    rval.append('  Destination-address:: %s' % ' '.join(self.destination))
    rval.append('  Source-port:: %s' % ' '.join(self.sport))
    rval.append('  Destination-port:: %s' % ' '.join(self.dport))
    rval.append('  Protocol:: %s' % ' '.join(self.protocol))
    rval.append('  Option:: %s' % ' '.join(self.option))
    rval.append('  Action:: %s' % ' '.join(self.action))
    return '\n'.join(rval)


class Policy(object):
  """Holds basic attributes of an unexpanded policy definition file."""

  def __init__(self, filename, defs_data=None):
    """Build policy object and naming definitions from provided filenames.

    Args:
      filename: location of a .pol file
      defs_data: location of naming definitions directory, if any
    """
    self.defs = naming.Naming(defs_data)
    self.filter = []
    try:
      self.data = open(filename, 'r').readlines()
    except IOError as error_info:
      info = str(filename) + ' cannot be opened'
      raise FileOpenError('%s\n%s' % (info, error_info))

    indent = 0
    in_header = False
    in_term = False
    filt = Filter()
    term = Term()
    in_string = False

    for line in self.data:
      words = line.strip().split()
      quotes = len(line.split('"')) + 1
      if quotes % 2:               # are we in or out of double quotes
        in_string = not in_string  # flip status of quote status
      if not in_string:
        if '{' in words:
          indent += 1
        if words:
          if words[0] == 'header':
            in_header = True
          if words[0] == 'term':
            in_term = True
            term = Term(words[1])
          if in_header and words[0] == 'target::':
            if filt.name != words[2]:  # avoid empty dupe filters due to
              filt = Filter(words[2])  # multiple target header lines
          if in_term:
            if words[0] == 'source-address::':
              term.source.extend(words[1:])
            if words[0] == 'destination-address::':
              term.destination.extend(words[1:])
            if words[0] == 'source-port::':
              term.sport.extend(words[1:])
            if words[0] == 'destination-port::':
              term.dport.extend(words[1:])
            if words[0] == 'action::':
              term.action.extend(words[1:])
            if words[0] == 'protocol::':
              term.protocol.extend(words[1:])
            if words[0] == 'option::':
              term.option.extend(words[1:])

        if '}' in words:
          indent -= 1
          if in_header:
            self.filter.append(filt)
            in_header = False
          if in_term:
            filt.term.append(term)
            in_term = False

  def __str__(self):
    return '\n'.join(str(i) for i in self.filter)

  def Matches(self, src=None, dst=None, dport=None, sport=None,
              filtername=None):
    """Return list of term names that match specific attributes.

    Args:
      src: source ip address '12.1.1.1'
      dst: destination ip address '10.1.1.1'
      dport: any port/protocol combo, such as '80/tcp' or '53/udp'
      sport: any port/protocol combo, such as '80/tcp' or '53/udp'
      filtername: a filter name or None to search all filters

    Returns:
      results: list of lists, each list is index to filter & term in the policy

    Raises:
      InvalidFilterError: Error if filter is invalid.

    Example:
      p=policyreader.Policy('policy_path', 'definitions_path')

      p.Matches(dst='209.85.216.5', dport='25/tcp')
      [[0, 26]]
      print p.filter[0].term[26].name

      for match in p.Matches(dst='209.85.216.5'):
        print p.filter[match[0]].term[match[1]].name

    """
    rval = []
    results = []
    filter_list = []
    dport_parents = None
    sport_parents = None
    destination_parents = None
    source_parents = None
    if dport:
      dport_parents = self.defs.GetServiceParents(dport)
    if sport:
      sport_parents = self.defs.GetServiceParents(sport)
    if dst:
      destination_parents = self.defs.GetIpParents(dst)
      try:
        destination_parents.remove('ANY')
        destination_parents.remove('RESERVED')
      except ValueError:
        pass  # ignore and continue
    if src:
      source_parents = self.defs.GetIpParents(src)
      try:
        source_parents.remove('ANY')
        source_parents.remove('RESERVED')
      except ValueError:
        pass  # ignore and continue
    if not filtername:
      filter_list = self.filter
    else:
      for idx, fil in enumerate(self.filter):
        if filtername == fil.name:
          filter_list = [self.filter[idx]]
      if not filter_list:
        raise InvalidFilterError('invalid filter name: %s' % filtername)

    for findex, xfilter in enumerate(filter_list):
      mterms = []
      mterms.append(set())  # dport
      mterms.append(set())  # sport
      mterms.append(set())  # dst
      mterms.append(set())  # src
      for tindex, term in enumerate(xfilter.term):
        if dport_parents:
          for token in dport_parents:
            if token in term.dport:
              mterms[0].add(tindex)
        else:
          mterms[0].add(tindex)
        if sport_parents:
          for token in sport_parents:
            if token in term.sport:
              mterms[1].add(tindex)
        else:
          mterms[1].add(tindex)
        if destination_parents:
          for token in destination_parents:
            if token in term.destination:
              mterms[2].add(tindex)
        else:
          mterms[2].add(tindex)
        if source_parents:
          for token in source_parents:
            if token in term.source:
              mterms[3].add(tindex)
        else:
          mterms[3].add(tindex)
      rval.append(list(mterms[0] & mterms[1] & mterms[2] & mterms[3]))
    for findex, fresult in enumerate(rval):
      for i in list(fresult):
        results.append([findex, i])
    return results
