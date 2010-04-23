#!/usr/bin/python
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


"""A subclass of the ipaddr library that includes comments for ipaddr objects."""

__author__ = 'watson@google.com (Tony Watson)'

from third_party import ipaddr

def IP(ipaddress, comment='', token=''):
  """Take an ip string and return an object of the correct type.

  Args:
    ip_string: the ip address.
    comment:: option comment field
    token:: option token name where this address was extracted from

  Returns:
    ipaddr.IPv4 or ipaddr.IPv6 object or raises ValueError.

  Raises:
    ValueError: if the string passed isn't either a v4 or a v6 address.

  Notes:
    this is sort of a poor-mans factory method.
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

    Args: comment
    """
    if self.text:
      if comment and comment not in self.text:
        self.text += ', ' + comment
    else:
      self.text = comment

  def supernet(self, prefixlen_diff=1):
    """Override ipaddr.IPv4 supernet so we can maintain comments.

    See ipaddr.IPv4.Supernet for complete documentation.
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

    Args: comment
    """
    if self.text:
      if comment and comment not in self.text:
        self.text += ', ' + comment
    else:
      self.text = comment


def _CollapseAddrListRecursive(addresses):
  """Recursively loops through the addresses, collapsing concurent netblocks.

   Example:

   ip1 = ipaddr.IPv4Network('1.1.0.0/24')
   ip2 = ipaddr.IPv4Network('1.1.1.0/24')
   ip3 = ipaddr.IPv4Network('1.1.2.0/24')
   ip4 = ipaddr.IPv4Network('1.1.3.0/24')
   ip5 = ipaddr.IPv4Network('1.1.4.0/24')
   ip6 = ipaddr.IPv4Network('1.1.0.1/22')

   _CollapseAddrRecursive([ip1, ip2, ip3, ip4, ip5, ip6]) ->
   [IPv4Network('1.1.0.0/22'), IPv4Network('1.1.4.0/24')]

   Note, this shouldn't be called directly, but is called via
   CollapseAddr([])

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
    elif cur_addr == ret_array[-1].Supernet().Subnet()[1]:
      ret_array.append(ret_array.pop().Supernet())
      # save the text from the subsumed address
      ret_array[-1].AddComment(cur_addr.text)
      optimized = True
    else:
      ret_array.append(cur_addr)

  if optimized:
    return _CollapseAddrListRecursive(ret_array)
  return ret_array


def CollapseAddrList(addresses):
  """Collapse an array of IP objects.

  Example:  CollapseAddr(
    [IPv4('1.1.0.0/24'), IPv4('1.1.1.0/24')]) -> [IPv4('1.1.0.0/23')]
    Note: this works just as well with IPv6 addresses too.

  Args:
     addresses: list of ipaddr.IPNetwork objects

  Returns:
    list of ipaddr.IPNetwork objects
  """
  return _CollapseAddrListRecursive(
      sorted(addresses, key=ipaddr._BaseNet._get_networks_key))


def SortAddrList(addresses):
  """Return a sorted list of nacaddr objects."""
  return sorted(addresses, cmp=ipaddr._BaseNet._get_networks_key)


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
    if exclude == addr:
      # this is a bug in ipaddr v1. IP('1.1.1.1').AddressExclude(IP('1.1.1.1'))
      # raises an error.  Not tested in v2 yet.
      pass
    elif exclude.version == addr.version and exclude in addr:
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

  for ex in excludes:
    superset = RemoveAddressFromList(superset, ex)
  return CollapseAddrList(superset)


ExcludeAddrs = AddressListExclude


class PrefixlenDiffInvalidError(ipaddr.NetmaskValueError):
  """Holdover from ipaddr v1."""


if __name__ == '__main__':
  pass
