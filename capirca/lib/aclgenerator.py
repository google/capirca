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
import logging
import re
import string

from capirca.lib import policy
import six
import hashlib

# generic error class
class Error(Exception):
  """Base error class."""


class NoPlatformPolicyError(Error):
  """Raised when a policy is received that doesn't support this platform."""


class UnknownIcmpTypeError(Error):
  """Raised when we see an unknown icmp-type."""


class MismatchIcmpInetError(Error):
  """Raised when mistmatch between icmp/icmpv6 and inet/inet6."""


class EstablishedError(Error):
  """Raised when a term has established option with inappropriate protocol."""


class UnsupportedAFError(Error):
  """Raised when provided an unsupported address family."""


class DuplicateTermError(Error):
  """Raised when duplication of term names are detected."""


class UnsupportedFilterError(Error):
  """Raised when we see an inappropriate filter."""


class UnsupportedTargetOptionError(Error):
  """Raised when a filter has an impermissible default action specified."""


class TermNameTooLongError(Error):
  """Raised when term named can not be abbreviated."""


class Term:
  """Generic framework for a generator Term."""
  ICMP_TYPE = policy.Term.ICMP_TYPE
  # http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
  PROTO_MAP = {'hopopt': 0,
               'icmp': 1,
               'igmp': 2,
               'ggp': 3,
               'ipip': 4,
               'tcp': 6,
               'egp': 8,
               'igp': 9,
               'udp': 17,
               'rdp': 27,
               'ipv6': 41,
               'ipv6-route': 43,
               'fragment': 44,
               'rsvp': 46,
               'gre': 47,
               'esp': 50,
               'ah': 51,
               'icmpv6': 58,
               'ipv6-nonxt': 59,
               'ipv6-opts': 60,
               'ospf': 89,
               'pim': 103,
               'vrrp': 112,
               'l2tp': 115,
               'sctp': 132,
               'udplite': 136,
               'all': -1,  # Used for GCE default deny, do not use in pol file.
              }
  AF_MAP = {'inet': 4,
            'inet6': 6,
            'bridge': 4  # if this doesn't exist, output includes v4 & v6
           }
  # These protos are always expressed as numbers instead of name
  #  due to inconsistencies on the end platform's name-to-number
  #  mapping.
  ALWAYS_PROTO_NUM = ['ipip']
  # provide flipped key/value dicts
  PROTO_MAP_BY_NUMBER = dict([(v, k) for (k, v) in PROTO_MAP.items()])
  AF_MAP_BY_NUMBER = dict([(v, k) for (k, v) in AF_MAP.items()])

  NO_AF_LOG_ADDR = string.Template('Term $term will not be rendered, as it has'
                                   ' $direction address match specified but no'
                                   ' $direction addresses of $af address family'
                                   ' are present.')

  NO_AF_LOG_PROTO = string.Template('Term $term will not be rendered, as it has'
                                    ' $proto match specified but the ACL is of'
                                    ' $af address family.')

  def __init__(self, term):
    if term.protocol:
      for protocol in term.protocol:
        if (protocol not in self.PROTO_MAP and
            str(protocol) not in [str(p) for p in self.PROTO_MAP_BY_NUMBER]):
          raise UnsupportedFilterError('Protocol(s) %s are not supported.'
                                       % str(term.protocol))

      term.protocol = ProtocolNameToNumber(term.protocol,
                                           self.ALWAYS_PROTO_NUM,
                                           self.PROTO_MAP)
    self.term = term

  def NormalizeAddressFamily(self, af):
    """Convert (if necessary) address family name to numeric value.

    Args:
      af: Address family, can be either numeric or string (e.g. 4 or 'inet')

    Returns:
      af: Numeric address family value

    Raises:
      UnsupportedAFError: Address family not in keys or values of our AF_MAP.
    """
    # ensure address family (af) is valid
    if af in self.AF_MAP_BY_NUMBER:
      return af
    elif af in self.AF_MAP:
      # convert AF name to number (e.g. 'inet' becomes 4, 'inet6' becomes 6)
      af = self.AF_MAP[af]
    else:
      raise UnsupportedAFError('Address family %s is not supported, '
                               'term %s.' % (af, self.term.name))
    return af

  def NormalizeIcmpTypes(self, icmp_types, protocols, af):
    """Return verified list of appropriate icmp-types.

    Args:
      icmp_types: list of icmp_types
      protocols: list of protocols
      af: address family of this term, either numeric or text (see self.AF_MAP)

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
          'icmp-types specified for non-icmp protocols in term: ',
          self.term.name))
    # make sure we have a numeric address family (4 or 6)
    af = self.NormalizeAddressFamily(af)
    # check that addr family and protocl are appropriate
    if ((af != 4 and protocols == ['icmp']) or
        (af != 6 and protocols == ['icmpv6'])):
      raise MismatchIcmpInetError('%s %s, %s: %s, %s: %s' % (
          'ICMP/ICMPv6 mismatch with address family IPv4/IPv6 in term',
          self.term.name, 'address family', af, 'protocols',
          ','.join(protocols)))
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


class ACLGenerator:
  """Generates platform specific filters and terms from a policy object.

  This class takes a policy object and renders the output into a syntax which
  is understood by a specific platform (eg. iptables, cisco, etc).
  """

  _PLATFORM = None
  # Default protocol to apply when no protocol is specified.
  _DEFAULT_PROTOCOL = 'ip'
  # Unsupported protocols by address family.
  _SUPPORTED_AF = {'inet', 'inet6'}
  # Commonly misspelled protocols that the generator should reject.
  _FILTER_BLACKLIST = {}

  # Only warn if these tokens are not implemented by a platform. These are not
  # meant to be overridden in subclasses like supported tokens/sub tokens.
  WARN_IF_UNSUPPORTED = {
      'restrict_address_family',
      'counter',
      'destination_tag',
      'filter_term',
      'logging',
      'loss_priority',
      'owner',
      'qos',
      'routing_instance',
      'policer',
      'source_tag'
  }

  # Abbreviation table used to automatically abbreviate terms that exceed
  # specified limit. We use uppercase for abbreviations to distinguish
  # from lowercase names.  This is order list - we try the ones in the
  # top of the list before the ones later in the list.  Prefer clear
  # or very-space-saving abbreviations by putting them early in the
  # list.  Abbreviations may be regular expressions or fixed terms;
  # prefer fixed terms unless there's a clear benefit to regular
  # expressions.
  _ABBREVIATION_TABLE = [
      # Service abbreviations first.
      ('experiment', 'EXP'),
      ('wifi-radius', 'W-R'),
      ('customer', 'CUST'),
      ('server', 'SRV'),
      # Next, common routing terms
      ('global', 'GBL'),
      ('google', 'GOOG'),
      ('service', 'SVC'),
      ('router', 'RTR'),
      ('internal', 'INT'),
      ('external', 'EXT'),
      ('transit', 'TRNS'),
      ('management', 'MGMT'),
      # State info
      ('established', 'EST'),
      ('unreachable', 'UNR'),
      ('fragment', 'FRAG'),
      ('accept', 'ACC'),
      ('discard', 'DISC'),
      ('reject', 'REJ'),
      ('replies', 'RPL'),
      ('request', 'REQ'),
  ]
  # Maximum term length. Can be overridden by generator to enforce
  # platform specific restrictions.
  _TERM_MAX_LENGTH = 62

  def __init__(self, pol, exp_info):
    """Initialise an ACLGenerator.  Store policy structure for processing."""
    supported_tokens, supported_sub_tokens = self._GetSupportedTokens()

    self.policy = pol
    all_err = []
    all_warn = []
    for header, terms in pol.filters:
      if self._PLATFORM in header.platforms:
        # Verify valid keywords
        # error on unsupported optional keywords that could result
        # in dangerous or unexpected results
        for term in terms:
          if term.platform:
            if self._PLATFORM not in term.platform:
              continue
          if term.platform_exclude:
            if self._PLATFORM in term.platform_exclude:
              continue
          # Only verify optional keywords if the term is active on the platform.
          err = []
          warn = []
          for el, val in term.__dict__.items():
            # Private attributes do not need to be valid keywords.
            if (val and el not in supported_tokens and not
                el.startswith('flatten')):
              if val and el not in self.WARN_IF_UNSUPPORTED:
                err.append(el)
              else:
                warn.append(el)
            # ignore Liskov's rule.
            if (val and isinstance(val, list) and
                el in supported_sub_tokens):
              ns = set(val) - supported_sub_tokens[el]
              # hack support for ArbitraryOptions in junos. todo, add the
              # junos options into the lexer, then we can nuke .*
              # shenanigans.
              if ns and '.*' not in supported_sub_tokens[el]:
                err.append(' '.join(ns))
          if err:
            all_err.append(('%s contains unsupported keywords (%s) for target '
                            '%s in policy %s') % (term.name, ' '.join(err),
                                                  self._PLATFORM, pol.filename))
          if warn:
            all_warn.append(
                ('%s contains unimplemented keywords (%s) for '
                 'target %s in policy %s') % (term.name, ' '.join(warn),
                                              self._PLATFORM, pol.filename))
        continue
    if all_err:
      raise UnsupportedFilterError('\n %s' % '\n'.join(all_err))
    if all_warn:
      logging.debug('\n %s', '\n'.join(all_warn))
    self._TranslatePolicy(pol, exp_info)

  def _TranslatePolicy(self, pol, exp_info):
    # pylint: disable=unused-argument
    """Translate policy contents to platform specific data structures."""
    raise Error('%s does not implement _TranslatePolicies()' % self._PLATFORM)

  def _BuildTokens(self):
    """Provide a default for supported tokens and sub tokens.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    # Set of supported keywords for a given platform.  Values should be in
    # undercase form, eg, icmp_type (not icmp-type)
    supported_tokens = {'action',
                        'comment',
                        'destination_address',
                        'destination_address_exclude',
                        'destination_port',
                        'expiration',
                        'icmp_type',
                        'stateless_reply',
                        'name',  # obj attribute, not token
                        'option',
                        'protocol',
                        'platform',
                        'platform_exclude',
                        'source_address',
                        'source_address_exclude',
                        'source_port',
                        'translated',  # obj attribute, not token
                        'verbatim',
                        }

    # These keys must be also listed in supported_tokens.
    # Keys should be in undercase form, eg, icmp_type (not icmp-type). Values
    # should be in dash form, icmp-type (not icmp_type)
    supported_sub_tokens = {
        'option': {
            'established',
            'first-fragment',
            'is-fragment',
            'initial',
            'rst',
            'sample',
            'tcp-established',
        },
        'action': {
            'accept',
            'deny',
            'next',
            'reject',
            'reject-with-tcp-rst',
        },
        'icmp_type': set(list(Term.ICMP_TYPE[4].keys())
                         + list(Term.ICMP_TYPE[6].keys()))
    }
    return supported_tokens, supported_sub_tokens

  def _GetSupportedTokens(self):
    """Build our supported tokens and sub tokens.

    Returns:
      tuple containing the supported tokens and sub tokens.
    Raises:
      UnsupportedFilterError: Raised when token is not supported.
    """
    supported_tokens, supported_sub_tokens = self._BuildTokens()
    # make sure we don't have subtokens that are not listed. This should not
    # occur unless a platform's tokens/subtokens are changed.
    undefined_st = set(supported_sub_tokens) - supported_tokens
    if undefined_st:
      raise UnsupportedFilterError(
          'Found undefined sub tokens missing from the supported token list! '
          'These must match. (%s)' % ' '.join(undefined_st))
    # all good.
    return supported_tokens, supported_sub_tokens

  # TODO(robankeny) Fix this function, it no longer does what it says.
  def FixHighPorts(self, term, af='inet', all_protocols_stateful=False):
    """Evaluate protocol and ports of term, return sane version of term.

    Args:
      term: Term object to be checked
      af: String presenting the address family, inet, inet6
      all_protocols_stateful: Boolean suggesting if protocols are all stateful.

    Returns:
      Copy of term that has been fixed

    Raises:
      UnsupportedAFError: Address family provided but unsupported.
      UnsupportedFilter: Protocols do not match the address family.
      EstablishedError: Established option used with inappropriate protocol.
      UnsupportedFilterError: Filter does not support protocols with AF.
    """
    mod = term

    # Determine which protocols this term applies to.
    if term.protocol:
      protocols = set(term.protocol)
    else:
      protocols = set((self._DEFAULT_PROTOCOL,))

    # Check that the address family matches the protocols.
    if af not in self._SUPPORTED_AF:
      raise UnsupportedAFError(
          '\nAddress family %s, found in %s, unsupported '
          'by %s' % (af, term.name, self._PLATFORM))
    if af in self._FILTER_BLACKLIST:
      unsupported_protocols = self._FILTER_BLACKLIST[af].intersection(protocols)
      if unsupported_protocols:
        raise UnsupportedFilterError(
            '\n%s targets do not support protocol(s) %s '
            'with address family %s (in %s)' % (self._PLATFORM,
                                                unsupported_protocols,
                                                af,
                                                term.name))

    # Many renders expect high ports for terms with the established option.
    for opt in [str(x) for x in term.option]:
      if opt.find('established') == 0:
        unstateful_protocols = protocols.difference(set(('tcp', 'udp')))
        if not unstateful_protocols:
          # TCP/UDP: add in high ports then collapse to eliminate overlaps.
          mod = copy.deepcopy(term)
          if not all_protocols_stateful:
            mod.destination_port.append((1024, 65535))
          mod.destination_port = mod.CollapsePortList(mod.destination_port)
        elif not all_protocols_stateful:
          errmsg = 'Established option supplied with inappropriate protocol(s)'
          raise EstablishedError('%s %s %s %s' %
                                 (errmsg, unstateful_protocols,
                                  'in term', term.name))
        break

    return mod

  def FixTermLength(self,
                    term_name,
                    abbreviate=False,
                    truncate=False,
                    override_max_length=None):
    """Return a term name which is equal or shorter than _TERM_MAX_LENGTH.

       New term is obtained in two steps. First, if allowed, automatic
       abbreviation is performed using hardcoded abbreviation table. Second,
       if allowed, term name is truncated to specified limit.

    Args:
      term_name: Name to abbreviate if necessary.
      abbreviate: Whether to allow abbreviations to shorten the length.
      truncate: Whether to allow truncation to shorten the length.
      override_max_length: Override the _TERM_MAX_LENGTH to a different value.
    Returns:
       A string based on term_name, that is equal or shorter than
       _TERM_MAX_LENGTH abbreviated and truncated as necessary.
    Raises:
       TermNameTooLongError: term_name cannot be abbreviated
       to be shorter than _TERM_MAX_LENGTH, or truncation is disabled.
    """
    new_term = term_name
    if override_max_length is None:
      override_max_length = self._TERM_MAX_LENGTH
    if abbreviate:
      for word, abbrev in self._ABBREVIATION_TABLE:
        if len(new_term) <= override_max_length:
          return new_term
        new_term = re.sub(word, abbrev, new_term)
    if truncate:
      new_term = new_term[:override_max_length]
    if len(new_term) <= override_max_length:
      return new_term
    raise TermNameTooLongError('Term %s (originally %s) is '
                               'too long. Limit is %d characters (vs. %d) '
                               'and no abbreviations remain or abbreviations '
                               'disabled.' %
                               (new_term, term_name,
                                override_max_length,
                                len(new_term)))

  def HexDigest(self, name, truncation_length=None):
    """Return a hexadecimal digest of the name object.

    Args:
      name: Name to hash.
      truncation_length: Truncation to shorten the digest length if necessary.
    Returns:
      A hexadecimal digest of the input name.
    Raises:
      N/A
    """

    if truncation_length is None:
      truncation_length = 64
    name_bytes = name.encode('UTF-8')
    return hashlib.sha256(name_bytes).hexdigest()[:truncation_length]


def ProtocolNameToNumber(protocols, proto_to_num, name_to_num_map):
  """Convert a protocol name to a numeric value.

  Args:
    protocols: list of protocol names to inspect
    proto_to_num: list of protocol names that should be converted to numbers
    name_to_num_map: map of protocol names to protocol numbers

  Returns:
    return_proto: list of protocol names, converted if applicable
  """
  return_proto = []

  for protocol in protocols:
    if protocol in proto_to_num:
      return_proto.append(name_to_num_map[protocol])
    else:
      return_proto.append(protocol)

  return return_proto


def AddRepositoryTags(prefix='', rid=True, date=True, revision=True,
                      wrap=False):
  """Add repository tagging into the output.

  Args:
    prefix: comment delimiter, if needed, to appear before tags
    rid: bool; True includes the revision Id: repository tag.
    date: bool; True includes the Date: repository tag.
    revision: bool; True includes the Revision: repository tag.
    wrap: bool; True wraps the tag in double quotes.
  Returns:
    list of text lines containing revision data
  """
  tags = []
  wrapper = '"' if wrap else ''

  # Format print the '$' into the RCS tags in order prevent the tags from
  # being interpolated here.
  p4_id = '%s%sId:%s%s' % (wrapper, '$', '$', wrapper)
  p4_date = '%s%sDate:%s%s' % (wrapper, '$', '$', wrapper)
  p4_revision = '%s%sRevision:%s%s' % (wrapper, '$', '$', wrapper)
  if rid:
    tags.append('%s%s' % (prefix, p4_id))
  if date:
    tags.append('%s%s' % (prefix, p4_date))
  if revision:
    tags.append('%s%s' % (prefix, p4_revision))
  return tags


def WrapWords(textlist, size, joiner='\n'):
  r"""Insert breaks into the listed strings at specified width.

  Args:
    textlist: a list of text strings
    size: width of reformated strings
    joiner: text to insert at break.  eg. '\n  ' to add an indent.
  Returns:
    list of strings
  """
  # \S{%d}(?!\s|\Z) collets the max size for words that are larger than the max
  # (?<=\S{%d})\S+ collects the remaining text for overflow words in their own
  # line
  # \S.{1,%d}(?=\s|\Z)) collects all words and spaces up to max size, breaking
  # at the last space
  rval = []
  linelength_re = re.compile(
      r'(\S{%d}(?!\s|\Z)|(?<=\S{%d})\S+|\S.{1,%d}(?=\s|\Z))' %
      (size, size, size - 1))
  for index in range(len(textlist)):
    if len(textlist[index]) > size:
      # insert joiner into the string at appropriate places.
      textlist[index] = joiner.join(linelength_re.findall(textlist[index]))
    # avoid empty comment lines
    rval.extend(x.strip() for x in textlist[index].strip().split(joiner) if x)
  return rval

def TruncateWords(input_text, char_limit):
  """Shorten text strings to not exceed a specified limit.

  This function also removes any line breaks.

  Args:
    input_text: list or individual string values.
    char_limit: size limit of resulting string element.

  Returns:
    truncated single string element within double quotes.
  """
  CHAR_LIMIT = 126

  if isinstance(input_text, list):
    # handle multiple comments. Remove newline.
    sanitized_list = []
    for i in input_text:
      sanitized_list.append(i.replace('\n', ''))
    comment = ' '.join(sanitized_list)
  else:
    comment = input_text
  return '"' + comment[:char_limit] + '"'
