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

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__author__ = 'vklimovs@google.com (Vjaceslavs Klimovs)'

import collections

import ipaddr


def ToDottedQuad(net, negate=False, nondsm=False):
  """Turns a int tuple into decimal dotted quad tuple.

  Args:
    net: tuple (network address as int, subnet mask as int).
    negate: if subnet mask should be negated (and become wildcard).
    nondsm: if mask should be generated in prefixlen when non-DSM

  Returns:
    tuple (decimal dotted address, decimal dotted mask).

  Raises:
    ValueError: if address is larger than 32 bits or mask is not exactly
      0 or 32 bits.
  """
  address, netmask = net
  if address.bit_length() > 32:
    raise ValueError('Addresses larger than 32 bits '
                     'are currently not supported.')
  if netmask.bit_length() not in (0, 32):
    raise ValueError('Subnet masks other than 0 or 32 '
                     'are currently not supported.')
  if negate:
    netmask = ~netmask

  return (_Int32ToDottedQuad(address),
          _PrefixlenForNonDSM(netmask)) if nondsm else (
              _Int32ToDottedQuad(address), _Int32ToDottedQuad(netmask))


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
  for _ in xrange(4):
    octet = num & 0xFF
    octets.insert(0, str(octet))
    num >>= 8
  return '.'.join(octets)


def _IpaddrToTuple(net):
  """Converts ipaddr networks object into tuple.

  Args:
    net: ipaddr.IPv4Network or ipaddr.IPv6Network object

  Returns:
    tuple (network address as int, subnet mask as int)
  """

  # left shift number of subnet mask bits, then leftshift until
  # full length of address reached
  address_as_int = int(net)
  netmask_as_int = (((1 << net.prefixlen) - 1) <<
                    (net.max_prefixlen - net.prefixlen))
  return (address_as_int, netmask_as_int)


def _ToPrettyBinaryFormat(num):
  """Prettily formated string of binary representation of suplied number.

  Useful for debugging.

  Args:
    num: number to be prettily formatted

  Returns:
    prettily formated string
  """
  # like ipaddr.py make assumption that this is ipv4
  byte_strings = []
  while num > 0 or len(byte_strings) < 4:
    byte_strings.append('{0:08b}'.format(num & 0xff))
    num >>= 8
  return ' '.join(reversed(byte_strings))


def Summarize(nets):
  """Summarizes networks while allowing for discontinuous subnet mask.

  Args:
    nets: list of ipaddr.IPv4Network or ipaddr.IPv6Network objects.
        Address family can be mixed, however there is no support for rendering
        anything other than IPv4.

  Returns:
    sorted list of tuples (network address as int, subnet mask as int)
  """

  result = []
  optimized_nets = ipaddr.CollapseAddrList(nets)
  nets_by_netmask = collections.defaultdict(list)
  # group nets by subnet mask
  for net in optimized_nets:
    nets_by_netmask[net.prefixlen].append(_IpaddrToTuple(net))
  for nets in nets_by_netmask.values():
    result.extend(_SummarizeSameMask(nets))
  return result


def _SummarizeSameMask(nets):
  """Summarizes networks while allowing for discontinuous subnet mask.

  ipaddr.py does not support discontinuous subnet masks, hence
  the format this method operates on is simple tuple
  (network address as int, subnet mask as int).

  Args:
    nets: list of tuples (network address as int, subnet mask as int).
    Must be already fully summarized as far as continuos subnet masks go.
    Subnet mask must be the same for all networks.

  Returns:
    sorted list of tuples (network address as int, subnet mask as int)
  """

  # singletons can not possible be paired and are our result
  singletons = []
  # combinetons can potentially be paired
  combinetons = sorted(nets)

  while combinetons:
    current_nets = combinetons
    combinetons = []
    while current_nets:
      current_net = current_nets.pop(0)
      # look for pair net, but keep index handy
      for pair_net_index, pair_net in enumerate(current_nets):
        current_address, current_netmask = current_net
        pair_address, _ = pair_net
        xored_address = current_address ^ pair_address
        # check if networks have exactly one bit difference, or are "a pair"
        if (xored_address & (xored_address - 1) == 0) and xored_address > 0:
          # if pair was found, remove both, add paired up network
          # to combinetons for next run and move along
          # otherwise this network can never be paired
          current_nets.pop(pair_net_index)
          new_netmask = current_netmask ^ xored_address
          # summarize supplied networks into one using discontinuous
          # subnet mask.
          combinetons.append((min(current_address, pair_address),
                              new_netmask))
          break
      else:
        singletons.append(current_net)
  return singletons
