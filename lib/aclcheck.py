#!/usr/bin/python2.4
#
# Copyright 2009 Google Inc.
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


"""Check where hosts, ports and protocols are matched in a NAC policy.

   Design document:
     https://docs.google.com/a/google.com/Doc?docid=cc9mgcsg_85db9cmhfr&hl=en
"""

__author__ = 'watson@google.com (Tony Watson)'

import sys
from capirca import nacaddr
from capirca import policy
from capirca import port


class Error(Exception):
  """Base error class."""


class AddressError(Error):
  """Incorrect IP address or format."""


class BadPolicy(Error):
  """Item is not a valid policy object."""


class NoTargetError(Error):
  """Specified target platform not available in specified policy."""


class AclCheck(object):
  """Check where hosts, ports and protocols match in a NAC policy.

  Args:
    pol:
      policy.Policy object
    src:
      string, the source address
    dst:
      string: the destination address.
    dport:
      string, the destination port.
    sport:
      string, the source port.
    proto:
      string, the protocol.

  Returns:
    An AclCheck Object

  Raises:
    port.BarPortValue: An invalid source port is used
    port.BadPortRange: A port is outside of the acceptable range 0-65535
    AddressError: Incorrect ip address or format

  """

  def __init__(self,
               pol,
               src='any',
               dst='any',
               sport='any',
               dport='any',
               proto='any',
              ):

    self.pol_obj = pol
    self.proto = proto

    # validate source port
    if sport == 'any':
      self.sport = sport
    else:
      self.sport = port.Port(sport)

    # validate destination port
    if dport == 'any':
      self.dport = sport
    else:
      self.dport = port.Port(dport)

    # validate source address
    if src == 'any':
      self.src = src
    else:
      try:
        self.src = nacaddr.IP(src)
      except ValueError:
        raise AddressError('bad source address: %s\n' % src)

    # validate destination address
    if dst == 'any':
      self.dst = dst
    else:
      try:
        self.dst = nacaddr.IP(dst)
      except ValueError:
        raise AddressError('bad destination address: %s\n' % dst)

    if type(self.pol_obj) is not policy.Policy:
      raise BadPolicy('Policy object is not valid.')

    self.matches = []
    self.exact_matches = []
    for header, terms in self.pol_obj.filters:
      filtername = header.target[0].options[0]
      for term in terms:
        possible = []

        if self._AddrInside(self.src, term.source_address):
          if self._AddrInside(self.dst, term.destination_address):
            if (self.sport == 'any' or not term.source_port or
                self._PortInside(self.sport, term.source_port)):
              if (self.dport == 'any' or not term.destination_port or
                  self._PortInside(self.dport, term.destination_port)):
                if (self.proto == 'any' or not term.protocol or
                    self.proto in term.protocol):

                  possible = self._PossibleMatch(term)
                  if term.action:  # avoid any verbatim
                    self.matches.append(Match(filtername, term.name, possible,
                                              term.action, term.qos))

                    # so if we get here then we have a match, and if the action
                    # isn't next and there are no possibles, then this is a
                    # "definite" match and we needn't look for any further
                    # matches (i.e. later terms may match, but since we'll never
                    # get there we shouldn't report them)
                    if 'next' not in term.action and not possible:
                      self.exact_matches.append(Match(filtername, term.name, [],
                                                      term.action, term.qos))
                      break

  def Matches(self):
    """Return list of matched terms."""
    return self.matches

  def ExactMatches(self):
    """Return matched terms, but not terms with possibles or action next."""
    return self.exact_matches

  def ActionMatch(self, action='any'):
    """Return list of matched terms with specified actions."""
    match_list = []
    for next in self.matches:
      if next.action:
        if not next.possibles:
          if action is 'any' or action in next.action:
            match_list.append(next)
    return match_list

  def DescribeMatches(self):
    """Provide sentence descriptions of matches.

    Returns:
      ret_str: text sentences describing matches
    """
    ret_str = []
    for next in self.matches:
      text = str(next)
      ret_str.append(text)
    return '\n'.join(ret_str)

  def __str__(self):
    text = []
    last_filter = ''
    for next in self.matches:
      if next.filter != last_filter:
        last_filter = next.filter
        text.append('  filter: ' + next.filter)
      if next.possibles:
        text.append(' ' * 10 + 'term: ' + next.term + ' (possible match)')
      else:
        text.append(' ' * 10 + 'term: ' + next.term)
      if next.possibles:
        text.append(' ' * 16 + next.action + ' if ' + str(next.possibles))
      else:
        text.append(' ' * 16 + next.action)
    return '\n'.join(text)

  def _PossibleMatch(self, term):
    """Ignore some options and keywords that are edge cases.

    Args:
      term: term object to examine for edge-cases

    Returns:
      ret_str: a list of reasons this term may possible match
    """
    ret_str = []
    if 'first-fragment' in term.option:
      ret_str.append('first-frag')
    if term.fragment_offset:
      ret_str.append('frag-offset')
    if term.packet_length:
      ret_str.append('packet-length')
    if 'established' in term.option:
      ret_str.append('est')
    if 'tcp-established' in term.option and 'tcp' in term.protocol:
      ret_str.append('tcp-est')
    return ret_str

  def _AddrInside(self, addr, addresses):
    """Check if address is matched in another address or group of addresses.

    Args:
      addr: An ipaddr network or host address or text 'any'
      addresses: A list of ipaddr network or host addresses

    Returns:
      bool: True of false
    """
    if addr is 'any': return True   # always true if we match for any addr
    if not addresses: return True   # always true if term has nothing to match
    for next in addresses:
      # ipaddr can incorrectly report ipv4 as contained with ipv6 addrs
      if type(addr) is type(next):
        if addr in next:
          return True
    return False

  def _PortInside(self, myport, port_list):
    """Check if port matches in a port or group of ports.

    Args:
      myport: port number
      port_list: list of ports

    Returns:
      bool: True of false
    """
    if myport == 'any': return True
    if [x for x in port_list if x[0] <= myport <= x[1]]:
      return True
    return False


class Match(object):
  """A matching term and its associate values."""

  def __init__(self, filtername, term, possibles, action, qos=None):
    self.filter = filtername
    self.term = term
    self.possibles = possibles
    self.action = action[0]
    self.qos = qos

  def __str__(self):
    text = ''
    if self.possibles:
      text += 'possible ' + self.action
    else:
      text += self.action
    text += ' in term ' + self.term + ' of filter ' + self.filter
    if self.possibles:
      text += ' with factors: ' + str(', '.join(self.possibles))
    return text


def main(_):
  pass

if __name__ == '__main__':
  main(sys.argv)
