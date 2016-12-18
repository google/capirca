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

"""A subclass of the ipaddr library that includes comments for ipaddr."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__author__ = 'watson@google.com (Tony Watson)'

import ipaddr


def IP(ipaddress, comment='', token=''):
  """Take an ip string and return an object of the correct type.

  Args:
    ipaddress: the ip address.
    comment: option comment field
    token: option token name where this address was extracted from

  Returns:
    ipaddr.IPv4 or ipaddr.IPv6 object or raises ValueError.

  Raises:
    ValueError: if the string passed isn't either a v4 or a v6 address.
  """
  a = ipaddr.IPNetwork(ipaddress)
  if a.version == 4:
    return IPv4(ipaddress, comment, token)
  elif a.version == 6:
    return IPv6(ipaddress, comment, token)


class IPv4(ipaddr.IPv4Network):
  """This subclass allows us to keep text comments related to each object."""

  def __init__(self, ip_string, comment='', token=''):
    ipaddr.IPv4Network.__init__(self, ip_string)
    self.text = comment
    self.token = token
    self.parent_token = token

  def AddComment(self, comment=''):
    """Append comment to self.text, comma seperated.

    Don't add the comment if it's the same as self.text.

    Args:
      comment: comment to be added.
    """
    if self.text:
      if comment and comment not in self.text:
        self.text += ', ' + comment
    else:
      self.text = comment

  def supernet(self, prefixlen_diff=1):
    """Override ipaddr.IPv4 supernet so we can maintain comments.

    See ipaddr.IPv4.Supernet for complete documentation.

    Args:
      prefixlen_diff: Prefix length difference.

    Returns:
      An IPv4 object

    Raises:
      PrefixlenDiffInvalidError: Raised when prefixlen - prefixlen_diff results
        in a negative number.
    """
    if self.prefixlen == 0:
      return self
    if self.prefixlen - prefixlen_diff < 0:
      raise PrefixlenDiffInvalidError(
          'current prefixlen is %d, cannot have a prefixlen_diff of %d' % (
              self.prefixlen, prefixlen_diff))
    ret_addr = IPv4(ipaddr.IPv4Network.supernet(self, prefixlen_diff),
                    comment=self.text, token=self.token)
    return ret_addr

  # Backwards compatibility name from v1.
  Supernet = supernet


class IPv6(ipaddr.IPv6Network):
  """This subclass allows us to keep text comments related to each object."""

  def __init__(self, ip_string, comment='', token=''):
    ipaddr.IPv6Network.__init__(self, ip_string)
    self.text = comment
    self.token = token
    self.parent_token = token

  def supernet(self, prefixlen_diff=1):
    """Override ipaddr.IPv6Network supernet so we can maintain comments.

    See ipaddr.IPv6Network.Supernet for complete documentation.
    Args:
      prefixlen_diff: Prefix length difference.

    Returns:
      An IPv4 object

    Raises:
      PrefixlenDiffInvalidError: Raised when prefixlen - prefixlen_diff results
        in a negative number.
    """
    if self.prefixlen == 0:
      return self
    if self.prefixlen - prefixlen_diff < 0:
      raise PrefixlenDiffInvalidError(
          'current prefixlen is %d, cannot have a prefixlen_diff of %d' % (
              self.prefixlen, prefixlen_diff))
    ret_addr = IPv6(ipaddr.IPv6Network.supernet(self, prefixlen_diff),
                    comment=self.text, token=self.token)
    return ret_addr

  # Backwards compatibility name from v1.
  Supernet = supernet

  def AddComment(self, comment=''):
    """Append comment to self.text, comma seperated.

    Don't add the comment if it's the same as self.text.

    Args:
      comment: comment to be added.
    """
    if self.text:
      if comment and comment not in self.text:
        self.text += ', ' + comment
    else:
      self.text = comment


def CollapseAddrListRecursive(addresses):
  """Recursively loops through the addresses, collapsing concurent netblocks.

   Example:

   ip1 = ipaddr.IPv4Network('1.1.0.0/24')
   ip2 = ipaddr.IPv4Network('1.1.1.0/24')
   ip3 = ipaddr.IPv4Network('1.1.2.0/24')
   ip4 = ipaddr.IPv4Network('1.1.3.0/24')
   ip5 = ipaddr.IPv4Network('1.1.4.0/24')
   ip6 = ipaddr.IPv4Network('1.1.0.1/22')

   CollapseAddrListRecursive([ip1, ip2, ip3, ip4, ip5, ip6]) ->
   [IPv4Network('1.1.0.0/22'), IPv4Network('1.1.4.0/24')]

   Note, this shouldn't be called directly, but is called via
   CollapseAddrList([])

  Args:
    addresses: List of IPv4 or IPv6 objects

  Returns:
    List of IPv4 or IPv6 objects (depending on what we were passed)
  """
  ret_array = []
  optimized = False

  for cur_addr in addresses:
    if not ret_array:
      ret_array.append(cur_addr)
      continue
    if ret_array[-1].Contains(cur_addr):
      # save the comment from the subsumed address
      ret_array[-1].AddComment(cur_addr.text)
      optimized = True
    elif (ret_array[-1].version == cur_addr.version and
          ret_array[-1].prefixlen == cur_addr.prefixlen and
          ret_array[-1].broadcast + 1 == cur_addr.network and
          ret_array[-1].Supernet().network == ret_array[-1].network):
      ret_array.append(ret_array.pop().Supernet())
      # save the text from the subsumed address
      ret_array[-1].AddComment(cur_addr.text)
      optimized = True
    else:
      ret_array.append(cur_addr)

  if optimized:
    return CollapseAddrListRecursive(ret_array)
  return ret_array


def CollapseAddrList(addresses):
  """Collapse an array of IP objects.

  Example:  CollapseAddrList(
    [IPv4('1.1.0.0/24'), IPv4('1.1.1.0/24')]) -> [IPv4('1.1.0.0/23')]
    Note: this works just as well with IPv6 addresses too.

  Args:
     addresses: list of ipaddr.IPNetwork objects

  Returns:
    list of ipaddr.IPNetwork objects
  """
  return CollapseAddrListRecursive(
      sorted(addresses, key=ipaddr._BaseNet._get_networks_key))


def SortAddrList(addresses):
  """Return a sorted list of nacaddr objects."""
  return sorted(addresses, key=ipaddr._BaseNet._get_networks_key)


def RemoveAddressFromList(superset, exclude):
  """Remove a single address from a list of addresses.

  Args:
    superset: a List of nacaddr IPv4 or IPv6 addresses
    exclude: a single nacaddr IPv4 or IPv6 address

  Returns:
    a List of nacaddr IPv4 or IPv6 addresses
  """
  ret_array = []
  for addr in superset:
    if exclude == addr or addr in exclude:
      pass
    elif exclude.version == addr.version and exclude in addr:
      # this could be optimized except that one group uses this
      # code with ipaddrs (instead of nacaddrs).
      ret_array.extend([IP(x) for x in addr.AddressExclude(exclude)])
    else:
      ret_array.append(addr)
  return ret_array


def AddressListExclude(superset, excludes):
  """Remove a list of addresses from another list of addresses.

  Args:
    superset: a List of nacaddr IPv4 or IPv6 addresses
    excludes: a List nacaddr IPv4 or IPv6 addresses

  Returns:
    a List of nacaddr IPv4 or IPv6 addresses
  """
  superset = CollapseAddrList(superset)
  excludes = CollapseAddrList(excludes)

  ret_array = []
  while superset and excludes:
    if superset[0].overlaps(excludes[0]):
      superset = (RemoveAddressFromList([superset[0]], excludes[0]) +
                  superset[1:])
    elif superset[0]._get_networks_key() < excludes[0]._get_networks_key():  # pylint: disable=protected-access
      ret_array.append(superset.pop(0))
    else:
      excludes.pop(0)
  return CollapseAddrList(ret_array + superset)


ExcludeAddrs = AddressListExclude


class PrefixlenDiffInvalidError(ipaddr.NetmaskValueError):
  """Holdover from ipaddr v1."""


if __name__ == '__main__':
  pass
