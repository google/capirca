#!/usr/bin/python2.4
#
# Copyright 2011 Google Inc. All Rights Reserved.

"""ACL Generator base class."""

import copy
import re


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


class EstablishedError(Error):
  """Raised when a term has established option with inappropriate protocol."""
  pass


class UnsupportedAF(Error):
  """Raised when provided an unsupported address family."""
  pass


class DuplicateTermError(Error):
  """Raised when duplication of term names are detected."""
  pass


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

  def __init__(self, pol):
    """Initialise an ACLGenerator.  Store policy structure for processing."""
    object.__init__(self)

    self.policy = pol

    for header in pol.headers:
      if self._PLATFORM in header.platforms:
        break
    else:
      raise NoPlatformPolicyError('\nNo %s policy found' % self._PLATFORM)

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
                          'unsupported by %s' %
                          (af, term.net, self._PLATFORM))
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
          mod.destination_port = mod._CollapsePortList(mod.destination_port)
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
  _re = re.compile(r'(\S*?.{1,%d}(?:\s|\Z))' % size)
  for index in range(len(textlist)):
    if len(textlist[index]) > size:
      # insert joiner into the string at appropriate places.
      textlist[index] = joiner.join(_re.findall(textlist[index]))
    # avoid empty comment lines
    rval.extend(x.strip() for x in textlist[index].strip().split(joiner) if x)
  return rval
