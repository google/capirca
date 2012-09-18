#!/usr/bin/python2.4
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

"""ACL Generator base class."""

import copy
import re

import policy


# generic error class
class Error(Exception):
  """Base error class."""
  pass


class NoPlatformPolicyError(Error):
  """Raised when a policy is received that doesn't support this platform."""
  pass


class UnsupportedFilter(Error):
  """Raised when we see an inappropriate filter."""
  pass


class UnknownIcmpTypeError(Error):
  """Raised when we see an unknown icmp-type."""
  pass


class MismatchIcmpInetError(Error):
  """Raised when mistmatch between icmp/icmpv6 and inet/inet6."""
  pass


class EstablishedError(Error):
  """Raised when a term has established option with inappropriate protocol."""
  pass


class UnsupportedAF(Error):
  """Raised when provided an unsupported address family."""
  pass


class DuplicateTermError(Error):
  """Raised when duplication of term names are detected."""
  pass


class UnsupportedFilterError(Error):
  """Raised when we see an inappropriate filter."""


class Term(object):
  """Generic framework for a generator Term."""
  ICMP_TYPE = policy.Term.ICMP_TYPE
  PROTO_MAP = {'ip': 0,
               'icmp': 1,
               'igmp': 2,
               'ggp': 3,
               'ipencap': 4,
               'tcp': 6,
               'egp': 8,
               'igp': 9,
               'udp': 17,
               'rdp': 27,
               'ipv6': 41,
               'ipv6-route': 43,
               'ipv6-frag': 44,
               'rsvp': 46,
               'gre': 47,
               'esp': 50,
               'ah': 51,
               'icmpv6': 58,
               'ipv6-nonxt': 59,
               'ipv6-opts': 60,
               'ospf': 89,
               'ipip': 94,
               'pim': 103,
               'vrrp': 112,
               'l2tp': 115,
               'sctp': 132,
              }
  AF_MAP = {'inet': 4,
            'inet6': 6,
            'bridge': 4  # if this doesn't exist, output includes v4 & v6
           }
  # provide flipped key/value dicts
  PROTO_MAP_BY_NUMBER = dict([(v, k) for (k, v) in PROTO_MAP.iteritems()])
  AF_MAP_BY_NUMBER = dict([(v, k) for (k, v) in AF_MAP.iteritems()])

  def NormalizeAddressFamily(self, af):
    """Convert (if necessary) address family name to numeric value.

    Args:
      af: Address family, can be either numeric or string (e.g. 4 or 'inet')

    Returns:
      af: Numeric address family value

    Raises:
      MismatchIcmpInetError: mismatch between protocol and address family
    """
    # ensure address family (af) is valid
    if af in self.AF_MAP.values():
      return af
    elif af in self.AF_MAP:
      # convert AF name to number (e.g. 'inet' becomes 4, 'inet6' becomes 6)
      af = self.AF_MAP[af]
    else:
      raise MismatchIcmpInetError('%s %s' % (
          'ICMP/ICMPv6 mismatch with address family IPv4/IPv6; in term',
          self.term.name))
    return af

  def NormalizeIcmpTypes(self, icmp_types, protocols, af, term_name):
    """Return verified list of appropriate icmp-types.

    Args:
      icmp_types: list of icmp_types
      protocols: list of protocols
      af: address family of this term, either numeric or text (see self.AF_MAP)
      term_name: the name of the current term (for error reporting)

    Returns:
      sorted list of numeric icmp-type codes.

    Raises:
      UnsupportedFilterError: icmp-types specified with non-icmp protocol.
      MismatchIcmpInetError: mismatch between icmp protocol and address family.
      UnknownIcmpTypeError: unknown icmp-type specified
    """
    if not icmp_types:
      return ['']
    # only protocols icmp or icmpv6 can be used with icmp-types
    if protocols != ['icmp'] and protocols != ['icmpv6']:
      raise UnsupportedFilterError('%s %s' % (
          'icmp-types specified for non-icmp protocols in term: ', term_name))
    # make sure we have a numeric address family (4 or 6)
    af = self.NormalizeAddressFamily(af)
    # check that addr family and protocl are appropriate
    if ((af != 4 and protocols == ['icmp']) or
        (af != 6 and protocols == ['icmpv6'])):
      raise MismatchIcmpInetError('%s %s' % (
          'ICMP/ICMPv6 mismatch with address family IPv4/IPv6 in term',
          term_name))
    # ensure all icmp types are valid
    for icmptype in icmp_types:
      if icmptype not in self.ICMP_TYPE[af]:
        raise UnknownIcmpTypeError('%s %s %s %s' % (
            '\nUnrecognized ICMP-type (', icmptype,
            ') specified in term ', self.term.name))
    rval = []
    rval.extend([self.ICMP_TYPE[af][x] for x in icmp_types])
    rval.sort()
    return rval


class ACLGenerator(object):
  """Generates platform specific filters and terms from a policy object.

  This class takes a policy object and renders the output into a syntax which
  is understood by a specific platform (eg. iptables, cisco, etc).
  """

  _PLATFORM = None
  # Default protocol to apply when no protocol is specified.
  _DEFAULT_PROTOCOL = 'ip'
  # Unsupported protocols by address family.
  _SUPPORTED_AF = set(('inet', 'inet6'))
  # Commonly misspelled protocols that the generator should reject.
  _FILTER_BLACKLIST = {}

  # set of required keywords that every generator must support
  _REQUIRED_KEYWORDS = set(['action',
                            'comment',
                            'destination_address',
                            'destination_address_exclude',
                            'destination_port',
                            'icmp_type',
                            'name',         # obj attribute, not keyword
                            'option',
                            'platform',
                            'platform_exclude',
                            'protocol',
                            'source_address',
                            'source_address_exclude',
                            'source_port',
                            'translated',  # obj attribute, not keyword
                            'verbatim',
                           ])
  # Generators should redefine this in subclass as optional support is added
  _OPTIONAL_SUPPORTED_KEYWORDS = set([])


  def __init__(self, pol):
    """Initialise an ACLGenerator.  Store policy structure for processing."""
    object.__init__(self)

    # The default list of valid keyword tokens for generators
    self._VALID_KEYWORDS = self._REQUIRED_KEYWORDS.union(
        self._OPTIONAL_SUPPORTED_KEYWORDS)

    self.policy = pol

    for header, terms in pol.filters:
      if self._PLATFORM in header.platforms:
        # Verify valid keywords
        # error on unsupported optional keywords that could result
        # in dangerous or unexpected results
        for term in terms:
          # Only verify optional keywords if the term is active on the platform.
          if term.platform:
            if self._PLATFORM not in term.platform:
              continue
          if term.platform_exclude:
            if self._PLATFORM in term.platform_exclude:
              continue
          err = []
          for el, val in term.__dict__.items():
            if val and el not in self._VALID_KEYWORDS:
              err.append(el)
          if err:
            raise UnsupportedFilterError('%s %s %s %s %s %s' % ('\n', term.name,
                'unsupported optional keywords for target', self._PLATFORM,
                'in policy:', ' '.join(err)))
        continue

    self._TranslatePolicy(pol)

  def _TranslatePolicy(self, pol):
    """Translate policy contents to platform specific data structures."""
    raise Error('%s does not implement _TranslatePolicies()' % self._PLATFORM)

  def FixHighPorts(self, term, af='inet', all_protocols_stateful=False):
    """Evaluate protocol and ports of term, return sane version of term."""
    mod = term

    # Determine which protocols this term applies to.
    if term.protocol:
      protocols = set(term.protocol)
    else:
      protocols = set((self._DEFAULT_PROTOCOL,))

    # Check that the address family matches the protocols.
    if not af in self._SUPPORTED_AF:
      raise UnsupportedAF('\nAddress family %s, found in %s, '
                          'unsupported by %s' % (af, term.name, self._PLATFORM))
    if af in self._FILTER_BLACKLIST:
      unsupported_protocols = self._FILTER_BLACKLIST[af].intersection(protocols)
      if unsupported_protocols:
        raise UnsupportedFilter('\n%s targets do not support protocol(s) %s '
                                'with address family %s (in %s)' %
                                (self._PLATFORM, unsupported_protocols,
                                 af, term.name))

    # Many renders expect high ports for terms with the established option.
    for opt in [str(x) for x in term.option]:
      if opt.find('established') == 0:
        unstateful_protocols = protocols.difference(set(('tcp', 'udp')))
        if not unstateful_protocols:
          # TCP/UDP: add in high ports then collapse to eliminate overlaps.
          mod = copy.deepcopy(term)
          mod.destination_port.append((1024, 65535))
          mod.destination_port = mod.CollapsePortList(mod.destination_port)
        elif not all_protocols_stateful:
          errmsg = 'Established option supplied with inappropriate protocol(s)'
          raise EstablishedError('%s %s %s %s' %
                                 (errmsg, unstateful_protocols,
                                  'in term', term.name))
        break

    return mod


def AddRepositoryTags(prefix=''):
  """Add repository tagging into the output.

  Args:
    prefix: comment delimiter, if needed, to appear before tags
  Returns:
    list of text lines containing revision data
  """
  tags = []
  p4_id = '%sId:%s' % ('$', '$')
  p4_date = '%sDate:%s' % ('$', '$')
  tags.append('%s%s' % (prefix, p4_id))
  tags.append('%s%s' % (prefix, p4_date))
  return tags


def WrapWords(textlist, size, joiner='\n'):
  """Insert breaks into the listed strings at specified width.

  Args:
    textlist: a list of text strings
    size: width of reformated strings
    joiner: text to insert at break.  eg. '\n  ' to add an indent.
  Returns:
    list of strings
  """
  # \S*? is a non greedy match to collect words of len > size
  # .{1,%d} collects words and spaces up to size in length.
  # (?:\s|\Z) ensures that we break on spaces or at end of string.
  rval = []
  linelength_re = re.compile(r'(\S*?.{1,%d}(?:\s|\Z))' % size)
  for index in range(len(textlist)):
    if len(textlist[index]) > size:
      # insert joiner into the string at appropriate places.
      textlist[index] = joiner.join(linelength_re.findall(textlist[index]))
    # avoid empty comment lines
    rval.extend(x.strip() for x in textlist[index].strip().split(joiner) if x)
  return rval
