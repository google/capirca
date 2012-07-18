#!/usr/bin/python
#
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

__author__ = 'pmoody@google.com (Peter Moody)'
__author__ = 'watson@google.com (Tony Watson)'


import datetime
import logging

import aclgenerator
import nacaddr


# generic error class
class Error(Exception):
  pass


class JuniperTermPortProtocolError(Error):
  pass


class TcpEstablishedWithNonTcp(Error):
  pass


class JuniperDuplicateTermError(Error):
  pass


class UnsupportedFilterError(Error):
  pass


class PrecedenceError(Error):
  pass


class Term(aclgenerator.Term):
  """Representation of an individual Juniper term.

    This is mostly useful for the __str__() method.

    Args: term policy.Term object
  """
  _DEFAULT_INDENT = 12
  _ACTIONS = {'accept': 'accept',
              'deny': 'discard',
              'reject': 'reject',
              'next': 'next term',
              'reject-with-tcp-rst': 'reject tcp-reset'}

  # the following lookup table is used to map between the various types of
  # filters the juniper generator can render.  As new differences are
  # encountered, they should be added to this table.  Accessing members
  # of this table looks like:
  #  self._TERM_TYPE('inet').get('saddr') -> 'source-address'
  #
  # it's critical that the members of each filter type be the same, that is
  # to say that if _TERM_TYPE.get('inet').get('foo') returns something,
  # _TERM_TYPE.get('inet6').get('foo') must return the inet6 equivalent.
  _TERM_TYPE = {'inet': {'addr': 'address',
                         'saddr': 'source-address',
                         'daddr': 'destination-address',
                         'protocol': 'protocol',
                         'protocol-except': 'protocol-except',
                         'tcp-est': 'tcp-established'},
                'inet6': {'addr': 'address',
                          'saddr': 'source-address',
                          'daddr': 'destination-address',
                          'protocol': 'next-header',
                          'protocol-except': 'next-header-except',
                          'tcp-est': 'tcp-established'},
                'bridge': {'addr': 'ip-address',
                           'saddr': 'ip-source-address',
                           'daddr': 'ip-destination-address',
                           'protocol': 'ip-protocol',
                           'protocol-except': 'ip-protocol-except',
                           'tcp-est': 'tcp-flags "(ack|rst)"'}}

  def __init__(self, term, term_type):
    self.term = term
    self.term_type = term_type

    if not term_type in self._TERM_TYPE:
      raise ValueError('Unknown Filter Type: %s' % term_type)

    if (not self.term.address and
        not self.term.destination_address and
        not self.term.destination_prefix and
        not self.term.destination_port and
        not self.term.precedence and
        not self.term.protocol and
        not self.term.protocol_except and
        not self.term.port and
        not self.term.source_address and
        not self.term.source_prefix and
        not self.term.source_port and
        not self.term.ether_type and
        not self.term.traffic_type):

      self.default_action = True
    else:
      self.default_action = False
    # some options need to modify the actions
    self.extra_actions = []

  # TODO(pmoody): get rid of all of the default string concatenation here.
  #  eg, indent(8) + 'foo;' -> '%s%s;' % (indent(8), 'foo'). pyglint likes this
  #  more.
  def __str__(self):
    ret_str = []
    from_str = []

    # we need a quick way to generate some number of ' ' chars for lining up
    # the terms properly.
    indent = lambda n: ' ' * (self._DEFAULT_INDENT + n)

    # Don't render icmpv6 protocol terms under inet, or icmp under inet6
    if ((self.term_type == 'inet6' and 'icmp' in self.term.protocol) or
        (self.term_type == 'inet' and 'icmpv6' in self.term.protocol)):
      ret_str.append(indent(0) + '/* Term %s' % self.term.name)
      ret_str.append(indent(0) + '** not rendered due to protocol/AF mismatch.')
      ret_str.append(indent(0) + '*/')
      return '\n'.join(ret_str)

    # comment
    # this deals just fine with multi line comments, but we could probably
    # output them a little cleaner; do things like make sure the
    # len(output) < 80, etc.
    if self.term.comment:
      ret_str.append(indent(0) + '/*')
      for comment in self.term.comment:
        for line in comment.split('\n'):
          ret_str.append(indent(0) + '** ' + line)
      ret_str.append(indent(0) + '*/')

    # Term verbatim output - this will skip over normal term creation
    # code.  Warning generated from policy.py if appropriate.
    if self.term.verbatim:
      for next_term in self.term.verbatim:
        if next_term.value[0] == 'juniper':
          ret_str.append(str(next_term.value[1]))
      return '\n'.join(ret_str)

    # option
    # this is going to be a little ugly b/c there are a few little messed
    # up options we can deal with.
    if self.term.option:
      for opt in [str(x) for x in self.term.option]:
        # there should be a better way to search the array of protocols
        if opt.find('sample') == 0:
          self.extra_actions.append('sample')

        # only append tcp-established for option established when
        # tcp is the only protocol, otherwise other protos break on juniper
        elif opt.find('established') == 0:
          if self.term.protocol == ['tcp']:
            if 'tcp-established;' not in [x.strip() for x in from_str]:
              from_str.append(indent(8) + self._TERM_TYPE.get(
                  self.term_type).get('tcp-est') + ';')

        # if tcp-established specified, but more than just tcp is included
        # in the protocols, raise an error
        elif opt.find('tcp-established') == 0:
          if self.term.protocol == ['tcp']:
            if 'tcp-established;' not in [x.strip() for x in from_str]:
              term_est = self._TERM_TYPE.get(self.term_type).get('tcp-est')
              from_str.append(indent(8) + term_est + ';')
          else:
            raise TcpEstablishedWithNonTcp(
                'tcp-established can only be used with tcp protocol in term %s'
                % self.term.name)
        elif opt.find('rst') == 0:
          from_str.append(indent(8) + 'tcp-flags "rst";')
        elif opt.find('initial') == 0 and 'tcp' in self.term.protocol:
          from_str.append(indent(8) + 'tcp-initial;')
        elif opt.find('first-fragment') == 0:
          from_str.append(indent(8) + 'first-fragment;')

        # we don't have a special way of dealing with this, so we output it and
        # hope the user knows what they're doing.
        else:
          from_str.append('%s%s;' % (indent(8), opt))

    # term name
    ret_str.append(indent(0) + 'term ' + self.term.name + ' {')

    # a default action term doesn't have any from { clause
    if not self.default_action:
      ret_str.append(indent(4) + 'from {')

      # address
      address = self.term.GetAddressOfVersion('address',
                                              self.AF_MAP.get(self.term_type))
      if address:
        ret_str.append(indent(8) +
                       self._TERM_TYPE.get(self.term_type).get('addr') + ' {')
        for addr in address:
          # nacaddr comments may not appear for some optimized addresses
          ret_str.append(indent(12) + str(addr) + ';' + self._Comment(addr))
        ret_str.append(indent(8) + '}')

      # source address
      source_address = self.term.GetAddressOfVersion(
          'source_address',
          self.AF_MAP.get(self.term_type))
      source_address_exclude = self.term.GetAddressOfVersion(
          'source_address_exclude',
          self.AF_MAP.get(self.term_type))
      if source_address:
        ret_str.append(indent(8) +
                       self._TERM_TYPE.get(self.term_type).get('saddr') + ' {')
        for saddr in source_address:
          # nacaddr comments may not  appear for some optimized addresses
          ret_str.append(indent(12) + str(saddr) + ';' + self._Comment(saddr))
        # source-excludes?
        if source_address_exclude:
          for ex in source_address_exclude:
            # nacaddr comments may not  appear for some optimized addresses
            ret_str.append(indent(12) + str(ex) + ' except;' +
                           self._Comment(ex, exclude=True))
        ret_str.append(indent(8) + '}')

      # destination address
      destination_address = self.term.GetAddressOfVersion(
          'destination_address',
          self.AF_MAP.get(self.term_type))
      destination_address_exclude = self.term.GetAddressOfVersion(
          'destination_address_exclude',
          self.AF_MAP.get(self.term_type))

      if destination_address:
        ret_str.append(indent(8) +
                       self._TERM_TYPE.get(self.term_type).get('daddr') + ' {')
        for daddr in destination_address:
          # nacaddr comments may not  appear for some optimized addresses
          ret_str.append(indent(12) + str(daddr) + ';' + self._Comment(daddr))
        # destination-excludes?
        if destination_address_exclude:
          for ex in destination_address_exclude:
            ret_str.append(indent(12) + str(ex) + ' except;' +
                           self._Comment(ex, exclude=True))

        ret_str.append(indent(8) + '}')

      # source prefix list
      if self.term.source_prefix:
        ret_str.append(indent(8) + 'source-prefix-list {')
        for pfx in self.term.source_prefix:
          ret_str.append(indent(12) + pfx + ';')
        ret_str.append(indent(8) + '}')

      # destination prefix list
      if self.term.destination_prefix:
        ret_str.append(indent(8) + 'destination-prefix-list {')
        for pfx in self.term.destination_prefix:
          ret_str.append(indent(12) + pfx + ';')
        ret_str.append(indent(8) + '}')

      # protocol
      if self.term.protocol:
        ret_str.append(indent(8) +
                       self._TERM_TYPE.get(self.term_type).get('protocol') +
                       ' ' + self._Group(self.term.protocol))

      # protocol
      if self.term.protocol_except:
        term_except = self._TERM_TYPE.get(self.term_type).get('protocol-except')
        ret_str.append(indent(8) + term_except + ' '
                       + self._Group(self.term.protocol_except))

      # port
      if self.term.port:
        ret_str.append(indent(8) + 'port ' + self._Group(self.term.port))

      # source port
      if self.term.source_port:
        ret_str.append(indent(8) + 'source-port ' +
                       self._Group(self.term.source_port))

      # destination port
      if self.term.destination_port:
        ret_str.append(indent(8) + 'destination-port ' +
                       self._Group(self.term.destination_port))

      # append any options beloging in the from {} section
      for next_str in from_str:
        ret_str.append(next_str)

      # packet length
      if self.term.packet_length:
        ret_str.append(indent(8) + 'packet-length ' +
                       str(self.term.packet_length) + ';')

      # fragment offset
      if self.term.fragment_offset:
        ret_str.append(indent(8) + 'fragment-offset ' +
                       str(self.term.fragment_offset) + ';')
      # icmp-types
      icmp_types = ['']
      if self.term.icmp_type:
        icmp_types = self.NormalizeIcmpTypes(self.term.icmp_type,
                                             self.term.protocol, self.term_type,
                                             self.term.name)
      if icmp_types != ['']:
        ret_str.append(indent(8) + 'icmp-type ' + self._Group(icmp_types))

      if self.term.ether_type:
        ret_str.append(indent(8) + 'ether-type ' +
                       self._Group(self.term.ether_type))

      if self.term.traffic_type:
        ret_str.append(indent(8) + 'traffic-type ' +
                       self._Group(self.term.traffic_type))

      if self.term.precedence:
        # precedence may be a single integer, or a space separated list
        policy_precedences = set()
        # precedence values may only be 0 through 7
        for precedence in self.term.precedence:
          if int(precedence) in range(0, 8):
            policy_precedences.add(precedence)
          else:
            raise PrecedenceError('Precedence value %s is out of bounds in %s' %
                                  (precedence, self.term.name))
        if len(policy_precedences) > 1:
          # A list looks like '[ 0 3 4 ]'
          precedence_string = '[ %s ]' % ' '.join(policy_precedences)
        else:
          precedence_string = policy_precedences.pop()

        ret_str.append(indent(8) + 'precedence %s;' % precedence_string)

      # end from { ... }
      ret_str.append(indent(4) + '}')

    # logging
    if self.term.logging:
      for log_target in self.term.logging:
        if str(log_target) == 'local':
          self.extra_actions.append('log')
        else:
          self.extra_actions.append('syslog')

    # routing instance.
    if self.term.routing_instance:
      self.extra_actions.append('routing-instance %s' %
                                str(self.term.routing_instance))
    # counter
    if self.term.counter:
      self.extra_actions.append('count %s' % str(self.term.counter))

    # policer
    if self.term.policer:
      self.extra_actions.append('policer %s' % str(self.term.policer))

    # quality-of-service
    if self.term.qos:
      self.extra_actions.append('forwarding-class %s' % str(self.term.qos))

    # loss-priority
    if self.term.loss_priority:
      self.extra_actions.append('loss-priority %s' %
                                str(self.term.loss_priority))

    ####
    # ACTIONS go below here
    ####
    ret_str.append(indent(4) + 'then {')

    for action in self.extra_actions:
      ret_str.append(indent(8) + str(action) + ';')

    for action in self.term.action:
      ret_str.append(indent(8) + self._ACTIONS.get(str(action)) + ';')

    # end then { ... }
    ret_str.append(indent(4) + '}')

    # end term accept-foo-to-bar { ... }
    ret_str.append(indent(0) + '}')

    return '\n'.join(ret_str)

  def _Comment(self, addr, exclude=False, line_length=132):
    """Returns address comment field if it exists.

    Args:
      addr: nacaddr.IPv4 object (?)
      exclude: bool - address excludes have different indentations
      line_length: integer - this is the length to which a comment will be
        truncated, no matter what.  ie, a 1000 character comment will be
        truncated to line_length, and then split.  if 0, the whole comment
        is kept. the current default of 132 is somewhat arbitrary.

    Returns:
      string

    Notes:
      This method tries to intelligently split long comments up.  if we've
      managed to summarize 4 /32's into a /30, each with a nacaddr text field
      of something like 'foobar N', normal concatination would make the
      resulting rendered comment look in mondrian like

                         source-address {
                             ...
                             1.1.1.0/30; /* foobar1, foobar2, foobar3, foo
      bar4 */

      b/c of the line splitting at 80 chars.  this method will split the
      comments at word breaks and make the previous example look like

                         source-address {
                              ....
                              1.1.1.0/30; /* foobar1, foobar2, foobar3,
                                          ** foobar4 */
      much cleaner.
    """
    rval = []
    # indentation, for multi-line comments, ensures that subsquent lines
    # are correctly alligned with the first line of the comment.
    indentation = 0
    if exclude:
      # len('1.1.1.1/32 except;') == 21
      indentation = 21 + self._DEFAULT_INDENT + len(str(addr))
    else:
      # len('1.1.1.1/32;') == 14
      indentation = 14 + self._DEFAULT_INDENT + len(str(addr))

    # length_eol is the width of the line; b/c of the addition of the space
    # and the /* characters, it needs to be a little less than the actual width
    # to keep from wrapping
    length_eol = 77 - indentation

    if isinstance(addr, (nacaddr.IPv4, nacaddr.IPv6)):
      if addr.text:

        if line_length == 0:
          # line_length of 0 means that we don't want to truncate the comment.
          line_length = len(addr.text)

        # There should never be a /* or */, but be safe and ignore those
        # comments
        if addr.text.find('/*') >= 0 or addr.text.find('*/') >= 0:
          logging.debug('Malformed comment [%s] ignoring', addr.text)
        else:

          text = addr.text[:line_length]

          comment = ' /*'
          while text:
            # split the line
            if len(text) > length_eol:
              new_length_eol = text[:length_eol].rfind(' ')
              if new_length_eol <= 0:
                new_length_eol = length_eol
            else:
              new_length_eol = length_eol

            # what line am I gunna output?
            line = comment + ' ' + text[:new_length_eol].strip()
            # truncate what's left
            text = text[new_length_eol:]
            # setup the comment and indentation for the next go-round
            comment = ' ' * indentation + '**'

            rval.append(line)

          rval[-1] += ' */'
    else:
      # should we be paying attention to any other addr type?
      logging.debug('Ignoring non IPv4 or IPv6 address: %s', addr)
    return '\n'.join(rval)

  def _Group(self, group):
    """If 1 item return it, else return [ item1 item2 ].

    Args:
      group: a list.  could be a list of strings (protocols) or a list of
             tuples (ports)

    Returns:
      rval: a string surrounded by '[' and '];' if len(group) > 1
            or with just ';' appended if len(group) == 1
    """

    def _FormattedGroup(el):
      """Return the actual formatting of an individual element.

      Args:
        el: either a string (protocol) or a tuple (ports)

      Returns:
        string: either the lower()'ed string or the ports, hyphenated
                if they're a range, or by itself if it's not.
      """
      if isinstance(el, str):
        return el.lower()
      elif isinstance(el, int):
        return str(el)
      # type is a tuple below here
      elif el[0] == el[1]:
        return '%d' % el[0]
      else:
        return '%d-%d' % (el[0], el[1])

    if len(group) > 1:
      rval = '[ ' + ' '.join([_FormattedGroup(x) for x in group]) + ' ];'
    else:
      rval = _FormattedGroup(group[0]) + ';'
    return rval


class Juniper(aclgenerator.ACLGenerator):
  """JCL rendering class.

    This class takes a policy object and renders the output into a syntax
    which is understood by juniper routers.

  Args:
    pol: policy.Policy object
  """

  _PLATFORM = 'juniper'
  _DEFAULT_PROTOCOL = 'ip'
  _SUPPORTED_AF = set(('inet', 'inet6', 'bridge'))
  _SUFFIX = '.jcl'

  _OPTIONAL_SUPPORTED_KEYWORDS = set(['counter',
                                      'destination_prefix',
                                      'ether_type',
                                      'expiration',
                                      'fragment_offset',
                                      'logging',
                                      'loss_priority',
                                      'packet_length',
                                      'policer',
                                      'precedence',
                                      'protocol_except',
                                      'qos',
                                      'routing_instance',
                                      'source_prefix',
                                      'traffic_type',
                                     ])

  def _TranslatePolicy(self, pol):
    self.juniper_policies = []
    current_date = datetime.date.today()

    for header, terms in pol.filters:
      if not self._PLATFORM in header.platforms:
        continue

      filter_options = header.FilterOptions(self._PLATFORM)
      filter_name = header.FilterName(self._PLATFORM)

      # Checks if the non-interface-specific option was specified.
      # I'm assuming that it will be specified as maximum one time, and
      # don't check for more appearances of the word in the options.
      interface_specific = not 'not-interface-specific' in filter_options[1:]
      # Remove the option so that it is not confused with a filter type
      if not interface_specific:
        filter_options.remove('not-interface-specific')

      # default to inet4 filters
      filter_type = 'inet'
      if len(filter_options) > 1:
        filter_type = filter_options[1]

      term_names = set()
      new_terms = []
      for term in terms:
        if term.name in term_names:
          raise JuniperDuplicateTermError('You have a duplicate term: %s' %
                                          term.name)
        term_names.add(term.name)

        term = self.FixHighPorts(term, af=filter_type)
        if not term:
          continue

        if term.expiration and term.expiration <= current_date:
          logging.warn('WARNING: Term %s in policy %s is expired and will not '
                       'be rendered.', term.name, filter_name)
          continue

        new_terms.append(Term(term, filter_type))

      self.juniper_policies.append((header, filter_name, filter_type,
                                    interface_specific, new_terms))

  def __str__(self):
    target = []

    for (header, filter_name, filter_type, interface_specific, terms
        ) in self.juniper_policies:
      # add the header information
      target.append('firewall {')
      target.append(' ' * 4 + 'family %s {' % filter_type)
      target.append(' ' * 8 + 'replace:')
      target.append(' ' * 8 + '/*')

      # we want the acl to contain id and date tags, but p4 will expand
      # the tags here when we submit the generator, so we have to trick
      # p4 into not knowing these words.  like taking c-a-n-d-y from a
      # baby.
      target.extend(aclgenerator.AddRepositoryTags(' ' * 8 + '** '))
      target.append(' ' * 8 + '**')

      for comment in header.comment:
        for line in comment.split('\n'):
          target.append(' ' * 8 + '** ' + line)
      target.append(' ' * 8 + '*/')

      target.append(' ' * 8 + 'filter ' + filter_name + ' {')
      if interface_specific:
        target.append(' ' * 12 + 'interface-specific;')

      for term in terms:
        target.append(str(term))

      target.append(' ' * 8 + '}')  # filter { ... }
      target.append(' ' * 4 + '}')  # family inet { ... }
      target.append('}')            # firewall { ... }
      target.append('\n')
    # end for header, filter_name, filter_type...
    return '\n'.join(target)
