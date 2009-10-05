#!/usr/bin/python2.4
#
# Copyright 2008 Google Inc. All Rights Reserved.

"""A subclass of the google3.pyglib.net ipaddr library."""

__author__ = 'watson@google.com (Tony Watson)'

import ipaddr  # Available at http://code.google.com/p/ipaddr-py

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
  a = ipaddr.IP(ipaddress)
  if a.version == 4:
    return IPv4(ipaddress, comment, token)
  elif a.version == 6:
    return IPv6(ipaddress, comment, token)

class IPv4(ipaddr.IPv4):
  """This subclass allows us to keep text comments related to each object."""

  def __init__(self, ip_string, comment='', token=''):
    ipaddr.IPv4.__init__(self, ip_string)
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

  def Supernet(self, prefixlen_diff=1):
    """Override ipaddr.IPv4 supernet so we can maintain comments.

    See ipaddr.IPv4.Supernet for complete documentation.
    """
    if self.prefixlen == 0:
      return self
    if self.prefixlen - prefixlen_diff < 0:
      raise PrefixlenDiffInvalidError(
          'current prefixlen is %d, cannot have a prefixlen_diff of %d' % (
              self.prefixlen, prefixlen_diff))
    ret_addr = IPv4(self.ip_ext + '/' + str(self.prefixlen - prefixlen_diff),
                    token=self.token)
    ret_addr.text = self.text
    return ret_addr


class IPv6(ipaddr.IPv6):
  """This subclass allows us to keep text comments related to each object."""

  def __init__(self, ip_string, comment='', token=''):
    ipaddr.IPv6.__init__(self, ip_string)
    self.text = comment
    self.token = token
    self.parent_token = token

  def Supernet(self, prefixlen_diff=1):
    """Override ipaddr.IPv4 supernet so we can maintain comments.

    See ipaddr.IPv4.Supernet for complete documentation.
    """
    if self.prefixlen == 0:
      return self
    if self.prefixlen - prefixlen_diff < 0:
      raise PrefixlenDiffInvalidError(
          'current prefixlen is %d, cannot have a prefixlen_diff of %d' % (
              self.prefixlen, prefixlen_diff))
    ret_addr = IPv6(self.ip_ext + '/' + str(self.prefixlen - prefixlen_diff),
                    token=self.token)
    ret_addr.text = self.text
    return ret_addr

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

   ip1 = ipaddr.IPv4('1.1.0.0/24')
   ip2 = ipaddr.IPv4('1.1.1.0/24')
   ip3 = ipaddr.IPv4('1.1.2.0/24')
   ip4 = ipaddr.IPv4('1.1.3.0/24')
   ip5 = ipaddr.IPv4('1.1.4.0/24')
   ip6 = ipaddr.IPv4('1.1.0.1/22')

   _CollapseAddrRecursive([ip1, ip2, ip3, ip4, ip5, ip6]) ->
   [IPv4('1.1.0.0/22'), IPv4('1.1.4.0/24')]

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
    Note: this works just as well with Ipv6 addresses too.

  Args:
     addresses: list of ipaddr.IP objects

  Returns:
    list of ipaddr.IP objects
  """
  return _CollapseAddrListRecursive(sorted(addresses,
                                           cmp=ipaddr.BaseIP.CompareNetworks))


def SortAddrList(addresses):
  """Return a sorted list of nacaddr objects."""
  return sorted(addresses, cmp=ipaddr.BaseIP.CompareNetworks)


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
      # this is a bug in ipaddr. IP('1.1.1.1').AddressExclude(IP('1.1.1.1'))
      # raises an error.
      pass
    elif exclude in addr:
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


class IPAddressExclusionError(ipaddr.IPAddressExclusionError):
  """Subclassed from ipaddr."""


class IPTypeError(ipaddr.IPTypeError):
  """Subclassed from ipaddr."""


class PrefixlenDiffInvalidError(ipaddr.PrefixlenDiffInvalidError):
  """Subclassed from ipaddr."""


if __name__ == '__main__':
  pass
