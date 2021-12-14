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

"""A subclass of the ipaddress library that includes comments for ipaddress."""

import collections
import ipaddress
import itertools
from typing import Union

import capirca.utils.iputils as iputils


def IP(ip, comment='', token='', strict=True):
  """Take an ip string and return an object of the correct type.

  Args:
    ip: the ip address.
    comment: option comment field
    token: option token name where this address was extracted from
    strict: If strict should be used in ipaddress object.

  Returns:
    ipaddress.IPv4 or ipaddress.IPv6 object or raises ValueError.

  Raises:
    ValueError: if the string passed isn't either a v4 or a v6 address.
  """
  if isinstance(ip, ipaddress._BaseNetwork):  # pylint disable=protected-access
    imprecise_ip = ip
  else:
    imprecise_ip = ipaddress.ip_network(ip, strict=strict)
  if imprecise_ip.version == 4:
    return IPv4(ip, comment, token, strict=strict)
  elif imprecise_ip.version == 6:
    return IPv6(ip, comment, token, strict=strict)
  raise ValueError('Provided IP string "%s" is not a valid v4 or v6 address'
                   % ip)


# TODO(robankeny) remove once at 3.7
@staticmethod
def _is_subnet_of(a, b):  # pylint: disable=invalid-name
  try:
    # Always false if one is v4 and the other is v6.
    if a.version != b.version:
      raise TypeError('%s and %s are not of the same version' % (a, b))
    return (b.network_address <= a.network_address and
            b.broadcast_address >= a.broadcast_address)
  except AttributeError:
    raise TypeError(
        'Unable to test subnet containment between %s and %s' % (a, b))


class IPv4(ipaddress.IPv4Network):
  """This subclass allows us to keep text comments related to each object."""

  def __init__(self, ip_string, comment='', token='', strict=True):
    self.text = comment
    self.token = token
    self.parent_token = token

    # Using a tuple of IP integer/prefixlength is significantly faster than
    # using the BaseNetwork object for recreating the IP network
    if isinstance(ip_string, ipaddress._BaseNetwork):  # pylint disable=protected-access
      ip = (ip_string.network_address._ip, ip_string.prefixlen)  # pylint disable=protected-access # pytype: disable=attribute-error
    else:
      ip = ip_string
    super().__init__(ip, strict)

  def subnet_of(self, other):
    """Return True if this network is a subnet of other."""
    if self.version != other.version:
      return False
    return self._is_subnet_of(self, other)

  def supernet_of(self, other):
    """Return True if this network is a supernet of other."""
    if self.version != other.version:
      return False
    return self._is_subnet_of(other, self)

  def __deepcopy__(self, memo):
    result = self.__class__(self)
    result.text = self.text
    result.token = self.token
    result.parent_token = self.parent_token
    return result

  def AddComment(self, comment=''):
    """Append comment to self.text, comma separated.

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
    """Override ipaddress.IPv4 supernet so we can maintain comments.

    See ipaddress.IPv4.Supernet for complete documentation.

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
    ret_addr = IPv4(ipaddress.IPv4Network.supernet(self, prefixlen_diff),
                    comment=self.text, token=self.token)
    return ret_addr

  # Backwards compatibility name from v1.
  Supernet = supernet
  _is_subnet_of = _is_subnet_of


class IPv6(ipaddress.IPv6Network):
  """This subclass allows us to keep text comments related to each object."""

  def __init__(self, ip_string, comment='', token='', strict=True):
    self.text = comment
    self.token = token
    self.parent_token = token

    # Using a tuple of IP integer/prefixlength is significantly faster than
    # using the BaseNetwork object for recreating the IP network
    if isinstance(ip_string, ipaddress._BaseNetwork):  # pylint disable=protected-access
      ip = (ip_string.network_address._ip, ip_string.prefixlen)  # pylint disable=protected-access # pytype: disable=attribute-error
    else:
      ip = ip_string
    super().__init__(ip, strict)

  def subnet_of(self, other):
    """Return True if this network is a subnet of other."""
    if self.version != other.version:
      return False
    return self._is_subnet_of(self, other)

  def supernet_of(self, other):
    """Return True if this network is a supernet of other."""
    if self.version != other.version:
      return False
    return self._is_subnet_of(other, self)

  def __deepcopy__(self, memo):
    result = self.__class__(self)
    result.text = self.text
    result.token = self.token
    result.parent_token = self.parent_token
    return result

  def supernet(self, prefixlen_diff=1):
    """Override ipaddress.IPv6Network supernet so we can maintain comments.

    See ipaddress.IPv6Network.Supernet for complete documentation.
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
    ret_addr = IPv6(ipaddress.IPv6Network.supernet(self, prefixlen_diff),
                    comment=self.text, token=self.token)
    return ret_addr

  # Backwards compatibility name from v1.
  Supernet = supernet
  _is_subnet_of = _is_subnet_of

  def AddComment(self, comment=''):
    """Append comment to self.text, comma separated.

    Don't add the comment if it's the same as self.text.

    Args:
      comment: comment to be added.
    """
    if self.text:
      if comment and comment not in self.text:
        self.text += ', ' + comment
    else:
      self.text = comment


IPType = Union[IPv4, IPv6]


def _InNetList(adders, ip):
  """Returns True if ip is contained in adders."""
  for addr in adders:
    if ip.subnet_of(addr):
      return True
  return False


def IsSuperNet(supernets, subnets):
  """Returns True if subnets are fully consumed by supernets."""
  for net in subnets:
    if not _InNetList(supernets, net):
      return False
  return True


def CollapseAddrListPreserveTokens(addresses):
  """Collapse an array of IPs only when their tokens are the same.

  Args:
     addresses: list of ipaddress.IPNetwork objects.

  Returns:
    list of ipaddress.IPNetwork objects.
  """
  ret_array = []
  for grp in itertools.groupby(sorted(addresses, key=lambda x: x.parent_token),
                               lambda x: x.parent_token):
    ret_array.append(CollapseAddrList(list(grp[1])))
  dedup_array = []
  i = 0
  while len(ret_array) > i:
    ip = ret_array.pop(0)
    k = 0
    to_add = True
    while k < len(dedup_array):
      if IsSuperNet(dedup_array[k], ip):
        to_add = False
        break
      elif IsSuperNet(ip, dedup_array[k]):
        del dedup_array[k]
      k += 1
    if to_add:
      dedup_array.append(ip)
  return [i for sublist in dedup_array for i in sublist]


def _SafeToMerge(address, merge_target, check_addresses):
  """Determine if it's safe to merge address into merge target.

  Checks given address against merge target and a list of check_addresses
  if it's OK to roll address into merge target such that it not less specific
  than any of the check_addresses. See description of why ir is important
  within public function CollapseAddrList.

  Args:
    address: Address that is being merged.
    merge_target: Merge candidate address.
    check_addresses: A dict networks_address->addrs to compare specificity with.

  Returns:
    True if safe to merge, False otherwise.
  """
  for check_address in check_addresses.get(address.network_address, []):
    if merge_target.netmask <= check_address.netmask < address.netmask:
      return False
  return True


def _CollapseAddrListInternal(addresses, complements_by_network):
  """Collapses consecutive netblocks until reaching a fixed point.

   Example:

   ip1 = ipaddress.IPv4Network('1.1.0.0/24')
   ip2 = ipaddress.IPv4Network('1.1.1.0/24')
   ip3 = ipaddress.IPv4Network('1.1.2.0/24')
   ip4 = ipaddress.IPv4Network('1.1.3.0/24')
   ip5 = ipaddress.IPv4Network('1.1.4.0/24')
   ip6 = ipaddress.IPv4Network('1.1.0.1/22')

   _CollapseAddrListInternal([ip1, ip2, ip3, ip4, ip5, ip6]) ->
   [IPv4Network('1.1.0.0/22'), IPv4Network('1.1.4.0/24')]

   Note, this shouldn't be called directly, but is called via
   CollapseAddrList([])

  Args:
    addresses: List of IPv4 or IPv6 objects
    complements_by_network: Dict of IPv4 or IPv6 objects indexed by
      network_address, that if present will be considered to avoid harmful
      optimizations.

  Returns:
    List of IPv4 or IPv6 objects (depending on what we were passed)
  """
  ret_array = []
  for addr in addresses:
    addr_is_fresh = True
    while addr_is_fresh:
      addr_is_fresh = False
      if not ret_array:
        ret_array.append(addr)
        continue

      prev_addr = ret_array[-1]
      if not _SafeToMerge(addr, prev_addr, complements_by_network):
        ret_array.append(addr)
      elif prev_addr.supernet_of(addr):
        # Preserve addr's comment, then subsume it.
        prev_addr.AddComment(addr.text)
      elif (prev_addr.version == addr.version and
            prev_addr.prefixlen == addr.prefixlen and
            # It's faster to compare integers than IP objects
            prev_addr.broadcast_address._ip + 1 == addr.network_address._ip and  # pylint disable=protected-access
            # Generating Supernet is relatively intensive compared to doing bit
            # operations
            (prev_addr.netmask._ip << 1) & prev_addr.network_address._ip ==      # pylint disable=protected-access
            prev_addr.network_address._ip):                                      # pylint disable=protected-access
        # Preserve addr's comment, then merge with it.
        prev_addr.AddComment(addr.text)
        addr = ret_array.pop().Supernet()
        addr_is_fresh = True
      else:
        ret_array.append(addr)

  return ret_array


def CollapseAddrList(addresses, complement_addresses=None):
  """Collapse an array of IP objects.

  Example:  CollapseAddrList(
    [IPv4('1.1.0.0/24'), IPv4('1.1.1.0/24')]) -> [IPv4('1.1.0.0/23')]
    Note: this works just as well with IPv6 addresses too.

  On platforms that support exclude semantics with most specific match,
  this method should _always_ be called with complement addresses supplied.
  Not doing so can lead to *reversal* of intent. Consider this case:

    destination-address:: 10.0.0.0/8, 10.0.0.0/10
    destination-exclude:: 10.0.0.0/9

  Without optimization, 10.0.0.1 will _match_. With optimization, most specific
  prefix will _not_ match, reversing the intent. Supplying complement_addresses
  allows this method to consider those implications.

  Args:
     addresses: list of ipaddress.IPNetwork objects
     complement_addresses: list of ipaddress.IPNetwork objects that, if present,
      will be considered to avoid harmful optimizations.

  Returns:
    list of ipaddress.IPNetwork objects
  """
  complements_dict = collections.defaultdict(list)
  address_set = set([a.network_address for a in addresses])
  for ca in complement_addresses or []:
    if ca.network_address in address_set:
      complements_dict[ca.network_address].append(ca)
  return _CollapseAddrListInternal(
      sorted(addresses, key=ipaddress.get_mixed_type_key), complements_dict)


def SortAddrList(addresses):
  """Return a sorted list of nacaddr objects."""
  return sorted(addresses, key=ipaddress.get_mixed_type_key)


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
    if exclude == addr or addr.subnet_of(exclude):
      pass
    elif exclude.version == addr.version and exclude.subnet_of(addr):
      # this could be optimized except that one group uses this
      # code with ipaddrs (instead of nacaddrs).
      ret_array.extend(IP(x) for x in iputils.exclude_address(addr, exclude))
    else:
      ret_array.append(addr)
  return SortAddrList(ret_array)


def AddressListExclude(superset, excludes, collapse_addrs=True):
  """Remove a list of addresses from another list of addresses.

  Args:
    superset: a List of nacaddr IPv4 or IPv6 addresses
    excludes: a List nacaddr IPv4 or IPv6 addresses
    collapse_addrs: whether or not to collapse contiguous CIDRs togethe

  Returns:
    a List of nacaddr IPv4 or IPv6 addresses
  """
  if collapse_addrs:
    superset = CollapseAddrList(superset)[::-1]
    excludes = CollapseAddrList(excludes)[::-1]
  else:
    superset = sorted(superset, reverse=True)
    excludes = sorted(excludes, reverse=True)

  ret_array = []
  while superset and excludes:
    if superset[-1].overlaps(excludes[-1]):
      ip = superset.pop()
      superset.extend(
          reversed(RemoveAddressFromList([ip], excludes[-1])))
    elif superset[-1]._get_networks_key() < excludes[-1]._get_networks_key():  # pylint: disable=protected-access
      ret_array.append(superset.pop())
    else:
      excludes.pop()
  if collapse_addrs:
    return CollapseAddrList(ret_array + superset)
  else:
    return sorted(set(ret_array + superset))


ExcludeAddrs = AddressListExclude


class PrefixlenDiffInvalidError(ipaddress.NetmaskValueError):
  """Holdover from ipaddr v1."""


if __name__ == '__main__':
  pass
