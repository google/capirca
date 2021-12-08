# Copyright 2014 Google Inc. All Rights Reserved.
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

"""Discontinuous subnet mask summarizer."""

import collections

from capirca.lib import nacaddr


class DSMNet:
  """Hold IP address information for the purposes of DSM summarization.

    ipaddr maintainers explicitly declared that they will not
    support discontinuous subnet masks, hence this is required.
  """

  def __init__(self, address, netmask, text=''):
    """Creates DSMNet.

    Args:
      address: network address as int.
      netmask: subnet mask as int.
      text: text comment.
    """
    self.address = address
    self.netmask = netmask
    self.text = text

  def __eq__(self, other):
    try:
      return (self.address == other.address and
              self.netmask == other.netmask)
    except AttributeError:
      return NotImplemented

  def __ne__(self, other):
    eq = self.__eq__(other)
    if eq is NotImplemented:
      return NotImplemented
    return not eq

  def __le__(self, other):
    gt = self.__gt__(other)
    if gt is NotImplemented:
      return NotImplemented
    return not gt

  def __ge__(self, other):
    lt = self.__lt__(other)
    if lt is NotImplemented:
      return NotImplemented
    return not lt

  def __lt__(self, other):
    try:
      if self.address != other.address:
        return self.address < other.address
    except AttributeError:
      return NotImplemented
    return False

  def __gt__(self, other):
    try:
      if self.address != other.address:
        return self.address > other.address
    except AttributeError:
      return NotImplemented
    return False

  def __str__(self):
    return ' '.join([self.address, self.netmask])

  def MergeText(self, text=''):
    """Returns self.text joined with optional text.

    Don't join the text if it's already contained in self.text.

    Args:
      text: text to be combined with self.text.

    Returns:
      Combined text.
    """
    if self.text:
      if text and text not in self.text:
        return ', '.join([self.text, text])
      return self.text
    else:
      return text


def ToDottedQuad(net, negate=False, nondsm=False):
  """Turns a DSMNet object into decimal dotted quad tuple.

  Args:
    net: DSMNet object.
    negate: if subnet mask should be negated (and become wildcard).
    nondsm: if mask should be generated in prefixlen when non-DSM.

  Returns:
    tuple (decimal dotted address, decimal dotted mask).

  Raises:
    ValueError: if address is larger than 32 bits or mask is not exactly
      0 or 32 bits.
  """
  if net.address.bit_length() > 32:
    raise ValueError('Addresses larger than 32 bits '
                     'are currently not supported.')
  if net.netmask.bit_length() not in (0, 32):
    raise ValueError('Subnet masks other than 0 or 32 '
                     'are currently not supported.')
  if negate:
    netmask = ~net.netmask
  else:
    netmask = net.netmask

  return (_Int32ToDottedQuad(net.address),
          _PrefixlenForNonDSM(netmask)) if nondsm else (
              _Int32ToDottedQuad(net.address), _Int32ToDottedQuad(netmask))


def _PrefixlenForNonDSM(intmask):
  """Turns 32 bit integer into dotted decimal with JunOS friendly.

  Args:
    intmask: 32 bit integer.

  Returns:
    A string in dotted decimal or prefixlen format.
  """
  dotmask = _Int32ToDottedQuad(intmask)

  if dotmask == '255.255.255.255':
    return '32'

  bitmask = '{:032b}'.format(intmask)

  prefixlen = 0
  while bitmask[prefixlen] == '1':
    prefixlen += 1

  return dotmask if int(bitmask[prefixlen:], 2) else str(prefixlen)


def _Int32ToDottedQuad(num):
  """Turns 32 bit integer into dotted decimal notation.

  Args:
    num: 32 bit integer.

  Returns:
    Integer as a string in dotted decimal notation.

  """
  octets = []
  for _ in range(4):
    octet = num & 0xFF
    octets.insert(0, str(octet))
    num >>= 8
  return '.'.join(octets)


def _NacaddrNetToDSMNet(net):
  """Converts nacaddr.IPv4 or nacaddr.IPv6 object into DSMNet object.

  Args:
    net: nacaddr.IPv4 or nacaddr.IPv6 object.

  Returns:
    DSMNet object.
  """

  # left shift number of subnet mask bits, then leftshift until
  # full length of address reached
  address_as_int = int(net.network_address)
  netmask_as_int = (((1 << net.prefixlen) - 1) <<
                    (net.max_prefixlen - net.prefixlen))
  return DSMNet(address_as_int, netmask_as_int, net.text)


def _ToPrettyBinaryFormat(num):
  """Prettily formatted string of binary representation of suplied number.

  Useful for debugging.

  Args:
    num: number to be prettily formatted

  Returns:
    prettily formatted string
  """
  # like ipaddr make assumption that this is ipv4
  byte_strings = []
  while num > 0 or len(byte_strings) < 4:
    byte_strings.append('{0:08b}'.format(num & 0xff))
    num >>= 8
  return ' '.join(reversed(byte_strings))


def Summarize(nets):
  """Summarizes networks while allowing for discontinuous subnet mask.

  Args:
    nets: list of nacaddr.IPv4 or nacaddr.IPv6 objects.
        Address family can be mixed, however there is no support for rendering
        anything other than IPv4.

  Returns:
    sorted list of DSMIPNet objects.
  """

  result = []
  optimized_nets = nacaddr.CollapseAddrList(nets)
  nets_by_netmask = collections.defaultdict(list)
  # group nets by subnet mask
  for net in optimized_nets:
    nets_by_netmask[net.prefixlen].append(_NacaddrNetToDSMNet(net))
  for nets in nets_by_netmask.values():
    result.extend(_SummarizeSameMask(nets))
  return sorted(result)


def _SummarizeSameMask(nets):
  """Summarizes networks while allowing for discontinuous subnet mask.

  Args:
    nets: list of unique, summarized DSMNet objects with the same netmask.

  Returns:
    sorted list of DSMNet objects that are discontinuously summarized.
  """

  # singletons can not possible be paired and are our result
  singletons = []
  # combinetons can potentially be paired
  combinetons = nets

  while combinetons:
    current_nets = combinetons
    combinetons = []
    while current_nets:
      current_net = current_nets.pop(0)
      # look for pair net, but keep index handy
      for pair_net_index, pair_net in enumerate(current_nets):
        xored_address = current_net.address ^ pair_net.address
        # For networks with the same network mask:
        # check if they have exactly one bit difference
        # or they are "a pair".
        if (current_net.netmask == pair_net.netmask and
            (xored_address & (xored_address - 1) == 0) and xored_address > 0):
          # if pair was found, remove both, add paired up network
          # to combinetons for next run and move along
          # otherwise this network can never be paired
          current_nets.pop(pair_net_index)
          new_netmask = current_net.netmask ^ xored_address
          # summarize supplied networks into one using discontinuous
          # subnet mask.
          combinetons.append(DSMNet(min(current_net.address, pair_net.address),
                                    new_netmask,
                                    current_net.MergeText(pair_net.text)))
          break
      else:
        singletons.append(current_net)
  return singletons
