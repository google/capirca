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

"""Parses the generic policy files and return a policy object for acl rendering.
"""

__author__ = ['pmoody@google.com',
              'watson@google.com']

import datetime
import os
import sys
import logging
from lib import nacaddr

class Error(Exception):
  """Generic error class."""


class PolicyTargetPlatformInvalidError(Error):
  """Attempt to generate an ACL for a platform not specified in policy header should fail."""


class HeaderDuplicateTargetPlatformError(Error):
  """Same target platform added to Header, resulting in ambiguity for options."""


class ShadingError(Error):
  """Error when a term is shaded by a prior term."""


class TermInvalidIcmpType(Error):
  """Error when a term has invalid icmp-types specified."""


class TermProtocolEtherTypeError(Error):
  """Error when both ether-type & upper-layer protocol matches are requested."""


class VerbatimError(Error):
  """Error when both verbatim and non-verbatim terms are used in a Policy."""

# classes for storing the object types in the policy files.
class Policy(object):
  """The policy object contains everything found in a given policy file."""

  def __init__(self, header, terms, shade_check):
    """Initiator for the Policy object.

    Args:
      header: __main__.Header object. contains comments which should be passed
        on to the rendered acls as well as the type of acls this policy file
        should render to.

      terms: list __main__.Term. an array of Term objects which must be rendered
        in each of the rendered acls.

      shade_check: True/False: if terms should be checked for shading.

    Attributes:
      filters: list of tuples containing (header, terms).
    """
    self.filters = []

    self.shade_check = shade_check

    self.AddFilter(header, terms)

  def AddFilter(self, header, terms):
    """Add another header & filter."""
    self.filters.append((header, terms))
    if self.shade_check:
      self._DetectShading(terms)

  @property
  def headers(self):
    """Returns the headers from each of the configured filters.

    Returns:
      headers
    """
    return [x[0] for x in self.filters]

  @property
  def platforms(self):
    """Returns platforms from each of the headers.

    Returns:
      array of unique strings."""
    ret = set()
    for h in self.headers:
      for t in h.target:
        ret.add(t.platform)
    ret = list(ret)
    ret.sort()
    return ret

  def _DetectShading(self, terms):
    """Finds terms which are shaded (impossible to reach).

    Iterate through each term, looking at each prior term. If a prior term
    contains every component of the current term then the current term would
    never be hit and is thus shaded. This can be a mistake.

    Args:
      terms: list of Term objects.

    Raises:
      ShadingError: When a term is impossible to reach.
    """
    shading_errors = []
    for index, term in enumerate(terms):
      for prior_index in xrange(index):
        # Check each term that came before for shading. Terms with next as an
        # action do not terminate evaluation, so cannot shade.
        if (term in terms[prior_index]
            and 'next' not in terms[prior_index].action):
          shading_errors.append(
              '  %s is shaded by %s.' % (
                  term.name, terms[prior_index].name))
    if shading_errors:
      raise ShadingError('\n'.join(shading_errors))

  def __eq__(self, obj):
    """Compares for equality against another Policy object.

    Note that it is picky and requires the list contents to be in the
    same order.

    Args:
      obj: object to be compared to for equality.
    Returns:
      True if the list of filters in this policy object is equal to the list
      in obj and False otherwise.
    """
    if not isinstance(obj, Policy):
      return False
    return self.filters == obj.filters

  def __str__(self):
    def tuple_str(tup):
      return '%s:%s' % (tup[0], tup[1])
    return 'Policy: {%s}' % ', '.join(map(tuple_str, self.filters))

  def __repr__(self):
    return self.__str__()



class Term(object):
  """The Term object is used to store each of the terms.

  Args:
    obj: an object of type VarType or a list of objects of type VarType

  members:
    address/source_address/destination_address/: list of
      VarType.(S|D)?ADDRESS's
    address_exclude/source_address_exclude/destination_address_exclude: list of
      VarType.(S|D)?ADDEXCLUDE's
    port/source_port/destination_port: list of VarType.(S|D)?PORT's
    options: list of VarType.OPTION's.
    protocol: list of VarType.PROTOCOL's.
    counter: VarType.COUNTER
    action: list of VarType.ACTION's
    dscp-set: VarType.DSCP_SET
    dscp-match: VarType.DSCP_MATCH
    dscp-except: VarType.DSCP_EXCEPT
    comments: VarType.COMMENT
    forwarding-class: VarType.FORWARDING_CLASS
    expiration: VarType.EXPIRATION
    verbatim: VarType.VERBATIM
    logging: VarType.LOGGING
    next-ip: VarType.NEXT_IP
    qos: VarType.QOS
    policer: VarType.POLICER
    vpn: VarType.VPN
  """
  ICMP_TYPE = {4: {'echo-reply': 0,
                   'unreachable': 3,
                   'source-quench': 4,
                   'redirect': 5,
                   'alternate-address': 6,
                   'echo-request': 8,
                   'router-advertisement': 9,
                   'router-solicitation': 10,
                   'time-exceeded': 11,
                   'parameter-problem': 12,
                   'timestamp-request': 13,
                   'timestamp-reply': 14,
                   'information-request': 15,
                   'information-reply': 16,
                   'mask-request': 17,
                   'mask-reply': 18,
                   'conversion-error': 31,
                   'mobile-redirect': 32,
                  },
               6: {'destination-unreachable': 1,
                   'packet-too-big': 2,
                   'time-exceeded': 3,
                   'parameter-problem': 4,
                   'echo-request': 128,
                   'echo-reply': 129,
                   'multicast-listener-query': 130,
                   'multicast-listener-report': 131,
                   'multicast-listener-done': 132,
                   'router-solicit': 133,
                   'router-advertisement': 134,
                   'neighbor-solicit': 135,
                   'neighbor-advertisement': 136,
                   'redirect-message': 137,
                   'router-renumbering': 138,
                   'icmp-node-information-query': 139,
                   'icmp-node-information-response': 140,
                   'inverse-neighbor-discovery-solicitation': 141,
                   'inverse-neighbor-discovery-advertisement': 142,
                   'version-2-multicast-listener-report': 143,
                   'home-agent-address-discovery-request': 144,
                   'home-agent-address-discovery-reply': 145,
                   'mobile-prefix-solicitation': 146,
                   'mobile-prefix-advertisement': 147,
                   'certification-path-solicitation': 148,
                   'certification-path-advertisement': 149,
                   'multicast-router-advertisement': 151,
                   'multicast-router-solicitation': 152,
                   'multicast-router-termination': 153,
                  },
              }
  _IPV6_BYTE_SIZE = 4

  def __init__(self):
    self.name = None

    self.action = []
    self.address = []
    self.address_exclude = []
    self.comment = []
    self.counter = None
    self.expiration = None
    self.destination_address = []
    self.destination_address_exclude = []
    self.destination_port = []
    self.destination_prefix = []
    self.forwarding_class = None
    self.logging = []
    self.loss_priority = None
    self.option = []
    self.owner = None
    self.policer = None
    self.port = []
    self.precedence = []
    self.principals = []
    self.protocol = []
    self.protocol_except = []
    self.qos = None
    self.routing_instance = None
    self.source_address = []
    self.source_address_exclude = []
    self.source_port = []
    self.source_prefix = []
    self.verbatim = []
    # juniper specific.
    self.packet_length = None
    self.fragment_offset = None
    self.hop_limit = None
    self.icmp_type = []
    self.ether_type = []
    self.traffic_type = []
    self.translated = False
    self.dscp_set = None
    self.dscp_match = []
    self.dscp_except = []
    self.next_ip = None
    # srx specific
    self.vpn = None
    # gce specific
    self.source_tag = []
    self.destination_tag = []
    # iptables specific
    self.source_interface = None
    self.destination_interface = None
    self.platform = []
    self.platform_exclude = []
    self.timeout = None
    self.flattened = False
    self.flattened_addr = None
    self.flattened_saddr = None
    self.flattened_daddr = None

  def __contains__(self, other):
    """Determine if other term is contained in this term."""
    if self.verbatim or other.verbatim:
      # short circuit these
      if sorted(self.verbatim) != sorted(other.verbatim):
        return False

    # check protocols
    # either protocol or protocol-except may be used, not both at the same time.
    if self.protocol:
      if other.protocol:
        if not self.CheckProtocolIsContained(other.protocol, self.protocol):
          return False
      # this term has protocol, other has protocol_except.
      elif other.protocol_except:
        return False
      else:
        # other does not have protocol or protocol_except. since we do other
        # cannot be contained in self.
        return False
    elif self.protocol_except:
      if other.protocol_except:
        if self.CheckProtocolIsContained(
            self.protocol_except, other.protocol_except):
          return False
      elif other.protocol:
        for proto in other.protocol:
          if proto in self.protocol_except:
            return False
      else:
        return False

    # combine addresses with exclusions for proper contains comparisons.
    if not self.flattened:
      self.FlattenAll()
    if not other.flattened:
      other.FlattenAll()

    # flat 'address' is compared against other flat (saddr|daddr).
    # if NONE of these evaluate to True other is not contained.
    if not (
        self.CheckAddressIsContained(
            self.flattened_addr, other.flattened_addr)
        or self.CheckAddressIsContained(
            self.flattened_addr, other.flattened_saddr)
        or self.CheckAddressIsContained(
            self.flattened_addr, other.flattened_daddr)):
      return False

    # compare flat address from other to flattened self (saddr|daddr).
    if not (
        # other's flat address needs both self saddr & daddr to contain in order
        # for the term to be contained. We already compared the flattened_addr
        # attributes of both above, which was not contained.
        self.CheckAddressIsContained(
            other.flattened_addr, self.flattened_saddr)
        and self.CheckAddressIsContained(
            other.flattened_addr, self.flattened_daddr)):
      return False

    # basic saddr/daddr check.
    if not (
        self.CheckAddressIsContained(
            self.flattened_saddr, other.flattened_saddr)):
      return False
    if not (
        self.CheckAddressIsContained(
            self.flattened_daddr, other.flattened_daddr)):
      return False

    if not (
        self.CheckPrincipalsContained(
            self.principals, other.principals)):
      return False

    # check ports
    # like the address directive, the port directive is special in that it can
    # be either source or destination.
    if self.port:
      if not (self.CheckPortIsContained(self.port, other.port) or
              self.CheckPortIsContained(self.port, other.sport) or
              self.CheckPortIsContained(self.port, other.dport)):
        return False
    if not self.CheckPortIsContained(self.source_port, other.source_port):
      return False
    if not self.CheckPortIsContained(self.destination_port,
                                     other.destination_port):
      return False

    # prefix lists
    if self.source_prefix:
      if sorted(self.source_prefix) != sorted(other.source_prefix):
        return False
    if self.destination_prefix:
      if sorted(self.destination_prefix) != sorted(
          other.destination_prefix):
        return False

    # check source and destination tags
    if self.source_tag:
      if sorted(self.source_tag != sorted(other.source_tag)):
        return False
      if sorted(self.destination_tag != sorted(other.destination_tag)):
        return False

    # check precedence
    if self.precedence:
      if not other.precedence:
        return False
      for precedence in other.precedence:
        if precedence not in self.precedence:
          return False
    # check various options
    if self.option:
      if not other.option:
        return False
      for opt in other.option:
        if opt not in self.option:
          return False
    # check forwarding-class
    if self.forwarding_class:
      if not other.forwarding_class:
        return False
    if self.next_ip:
      if not other.next_ip:
        return False
    if self.fragment_offset:
      # fragment_offset looks like 'integer-integer' or just, 'integer'
      sfo = [int(x) for x in self.fragment_offset.split('-')]
      if other.fragment_offset:
        ofo = [int(x) for x in other.fragment_offset.split('-')]
        if sfo[0] < ofo[0] or sorted(sfo[1:]) > sorted(ofo[1:]):
          return False
      else:
        return False
    if self.hop_limit:
      # hop_limit looks like 'integer-integer' or just, 'integer'
      shl = [int(x) for x in self.hop_limit.split('-')]
      if other.hop_limit:
        ohl = [int(x) for x in other.hop_limit.split('-')]
        if shl[0] < ohl[0]:
          return False
        shll, ohll = shl[1:2], ohl[1:2]
        if shll and ohll:
          if shl[0] > ohl[0]:
            return False
      else:
        return False
    if self.packet_length:
      # packet_length looks like 'integer-integer' or just, 'integer'
      spl = [int(x) for x in self.packet_length.split('-')]
      if other.packet_length:
        opl = [int(x) for x in other.packet_length.split('-')]
        if spl[0] < opl[0] or sorted(spl[1:]) > sorted(opl[1:]):
          return False
      else:
        return False
    if self.icmp_type:
      if sorted(self.icmp_type) is not sorted(other.icmp_type):
        return False

    # check platform
    if self.platform:
      if sorted(self.platform) is not sorted(other.platform):
        return False
    if self.platform_exclude:
      if sorted(self.platform_exclude) is not sorted(other.platform_exclude):
        return False

    # we have containment
    return True

  def __str__(self):
    ret_str = []
    ret_str.append(' name: %s' % self.name)
    if self.address:
      ret_str.append('  address: %s' % self.address)
    if self.address_exclude:
      ret_str.append('  address_exclude: %s' % self.address_exclude)
    if self.source_address:
      ret_str.append('  source_address: %s' % self.source_address)
    if self.source_address_exclude:
      ret_str.append('  source_address_exclude: %s' %
                     self.source_address_exclude)
    if self.source_tag:
      ret_str.append('  source_tag: %s' % self.source_tag)
    if self.destination_address:
      ret_str.append('  destination_address: %s' % self.destination_address)
    if self.destination_address_exclude:
      ret_str.append('  destination_address_exclude: %s' %
                     self.destination_address_exclude)
    if self.destination_tag:
      ret_str.append('  destination_tag: %s' % self.destination_tag)
    if self.source_prefix:
      ret_str.append('  source_prefix: %s' % self.source_prefix)
    if self.destination_prefix:
      ret_str.append('  destination_prefix: %s' % self.destination_prefix)
    if self.forwarding_class:
      ret_str.append('  forwarding_class: %s' % self.forwarding_class)
    if self.next_ip:
      ret_str.append('  next_ip: %s' % self.next_ip)
    if self.protocol:
      ret_str.append('  protocol: %s' % self.protocol)
    if self.protocol_except:
      ret_str.append('  protocol-except: %s' % self.protocol_except)
    if self.owner:
      ret_str.append('  owner: %s' % self.owner)
    if self.port:
      ret_str.append('  port: %s' % self.port)
    if self.source_port:
      ret_str.append('  source_port: %s' % self.source_port)
    if self.destination_port:
      ret_str.append('  destination_port: %s' % self.destination_port)
    if self.action:
      ret_str.append('  action: %s' % self.action)
    if self.option:
      ret_str.append('  option: %s' % self.option)
    if self.qos:
      ret_str.append('  qos: %s' % self.qos)
    if self.logging:
      ret_str.append('  logging: %s' % self.logging)
    if self.counter:
      ret_str.append('  counter: %s' % self.counter)
    if self.source_interface:
      ret_str.append('  source_interface: %s' % self.source_interface)
    if self.destination_interface:
      ret_str.append('  destination_interface: %s' % self.destination_interface)
    if self.expiration:
      ret_str.append('  expiration: %s' % self.expiration)
    if self.platform:
      ret_str.append('  platform: %s' % self.platform)
    if self.platform_exclude:
      ret_str.append('  platform_exclude: %s' % self.platform_exclude)
    if self.timeout:
      ret_str.append('  timeout: %s' % self.timeout)
    if self.vpn:
      vpn_name, pair_policy = self.vpn
      if pair_policy:
        ret_str.append('  vpn: name = %s, pair_policy = %s' %
                       (vpn_name, pair_policy))
      else:
        ret_str.append('  vpn: name = %s' % vpn_name)

    return '\n'.join(ret_str)

  def __repr__(self):
    return self.__str__()

  def __eq__(self, other):
    # action
    if sorted(self.action) != sorted(other.action):
      return False

    # addresses.
    if not (sorted(self.address) == sorted(other.address) and
            sorted(self.source_address) == sorted(other.source_address) and
            sorted(self.source_address_exclude) ==
            sorted(other.source_address_exclude) and
            sorted(self.destination_address) ==
            sorted(other.destination_address) and
            sorted(self.destination_address_exclude) ==
            sorted(other.destination_address_exclude)):
      return False

    # prefix lists
    if not (sorted(self.source_prefix) == sorted(other.source_prefix) and
            sorted(self.destination_prefix) ==
            sorted(other.destination_prefix)):
      return False

    # ports
    if not (sorted(self.port) == sorted(other.port) and
            sorted(self.source_port) == sorted(other.source_port) and
            sorted(self.destination_port) == sorted(other.destination_port)):
      return False

    # protocol
    if not (sorted(self.protocol) == sorted(other.protocol) and
            sorted(self.protocol_except) == sorted(other.protocol_except)):
      return False

    # option
    if sorted(self.option) != sorted(other.option):
      return False

    # qos
    if self.qos != other.qos:
      return False

    # verbatim
    if self.verbatim != other.verbatim:
      return False

    # policer
    if self.policer != other.policer:
      return False

    # interface
    if self.source_interface != other.source_interface:
      return False

    if self.destination_interface != other.destination_interface:
      return False

    # tags
    if not (sorted(self.source_tag) == sorted(other.source_tag) and
            sorted(self.destination_tag) == sorted(other.destination_tag)):
      return False

    if sorted(self.logging) != sorted(other.logging):
      return False
    if self.qos != other.qos:
      return False
    if self.packet_length != other.packet_length:
      return False
    if self.fragment_offset != other.fragment_offset:
      return False
    if self.hop_limit != other.hop_limit:
      return False
    if sorted(self.icmp_type) != sorted(other.icmp_type):
      return False
    if sorted(self.ether_type) != sorted(other.ether_type):
      return False
    if sorted(self.traffic_type) != sorted(other.traffic_type):
      return False

    # vpn
    if self.vpn != other.vpn:
      return False

    # platform
    if not (sorted(self.platform) == sorted(other.platform) and
            sorted(self.platform_exclude) == sorted(other.platform_exclude)):
      return False

    # timeout
    if self.timeout != other.timeout:
      return False

    # precedence
    if self.precedence != other.precedence:
      return False

    # forwarding-class
    if self.forwarding_class != other.forwarding_class:
      return False

    # next_ip
    if self.next_ip != other.next_ip:
      return False

    return True

  def __ne__(self, other):
    return not self.__eq__(other)

  def AddressesByteLength(self):
    """Returns the byte length of all IP addresses in the term.

    This is used in the srx generator due to a address size limitation.

    Returns:
      counter: Byte length of the sum of both source and destination IPs.
    """
    counter = 0
    for i in self.source_address:
      if i.version == 6:
        counter += self._IPV6_BYTE_SIZE
      else:
        counter += 1
    for i in self.destination_address:
      if i.version == 6:
        counter += self._IPV6_BYTE_SIZE
      else:
        counter += 1
    return counter

  def FlattenAll(self):
    """Reduce source, dest, and address fields to their post-exclude state.

    Populates the self.flattened_addr, self.flattened_saddr,
    self.flattened_daddr by removing excludes from includes.
    """
    # No excludes, set flattened attributes and move along.
    self.flattened = True
    if not (self.source_address_exclude or self.destination_address_exclude or
            self.address_exclude):
      self.flattened_saddr = self.source_address
      self.flattened_daddr = self.destination_address
      self.flattened_addr = self.address
      return

    if self.source_address_exclude:
      self.flattened_saddr = self._FlattenAddresses(
          self.source_address, self.source_address_exclude)
    if self.destination_address_exclude:
      self.flattened_daddr = self._FlattenAddresses(
          self.destination_address, self.destination_address_exclude)
    if self.address_exclude:
      self.flattened_addr = self._FlattenAddresses(
          self.address, self.address_exclude)


  @staticmethod
  def _FlattenAddresses(include, exclude):
    """Reduce an include and exclude list to a single include list.

    Using recursion, whittle away exclude addresses from address include
    addresses which contain the exclusion.

    Args:
      include: list of include addresses.
      exclude: list of exclude addresses.
    Returns:
      a single flattened list of nacaddr objects.
    """
    if not exclude:
      return include

    for index, in_addr in enumerate(include):
      for ex_addr in exclude:
        if ex_addr in in_addr:
          reduced_list = in_addr.address_exclude(ex_addr)
          include[index] = None
          for term in Term._FlattenAddresses(reduced_list, exclude[1:]):
            if term not in include:
              include.append(term)
        elif in_addr in ex_addr:
          include[index] = None

    # Remove items from include outside of the enumerate loop
    while None in include:
      include.remove(None)

    return include

  def GetAddressOfVersion(self, addr_type, af=None):
    """Returns addresses of the appropriate Address Family.

    Args:
      addr_type: string, this will be either
        'source_address', 'source_address_exclude',
        'destination_address' or 'destination_address_exclude'
      af: int or None, either Term.INET4 or Term.INET6

    Returns:
      list of addresses of the correct family.
    """
    if not af:
      return getattr(self, addr_type)

    return filter(lambda x: x.version == af, getattr(self, addr_type))


  def SanityCheck(self):
    """Sanity check the definition of the term.

    Raises:
      VerbatimError: if term has both verbatim and non-verbatim tokens
      TermInvalidIcmpType: if term has invalid icmp-types specified
      TermNoActionError: if the term doesn't have an action defined.
      TermPortProtocolError: if the term has a service/protocol definition pair
        which don't match up, eg. SNMP and tcp
      TermAddressExclusionError: if one of the *-exclude directives is defined,
        but that address isn't contained in the non *-exclude directive. eg:
        source-address::CORP_INTERNAL source-exclude:: LOCALHOST
      TermProtocolEtherTypeError: if the term has both ether-type and
        upper-layer protocol restrictions
      InvalidTermActionError: action and routing-instance both defined

    This should be called when the term is fully formed, and
    all of the options are set.

    """
    if self.verbatim:
      if (self.action or self.source_port or self.destination_port or
          self.port or self.protocol or self.option):
        raise VerbatimError(
            'term "%s" has both verbatim and non-verbatim tokens.' % self.name)
    else:
      if not self.action and not self.routing_instance and not self.next_ip:
        raise TermNoActionError('no action specified for term %s' % self.name)
      # have we specified a port with a protocol that doesn't support ports?
      if self.source_port or self.destination_port or self.port:
        if not any(proto in self.protocol for proto in ['tcp', 'udp', 'sctp']):
          raise TermPortProtocolError(
              'ports specified with a protocol that doesn\'t support ports. '
              'Term: %s ' % self.name)
    # TODO(pmoody): do we have mutually exclusive options?
    # eg. tcp-established + tcp-initial?

    if self.ether_type and (
        self.protocol or
        self.address or
        self.destination_address or
        self.destination_address_exclude or
        self.destination_port or
        self.destination_prefix or
        self.source_address or
        self.source_address_exclude or
        self.source_port or
        self.source_prefix):
      raise TermProtocolEtherTypeError(
          'ether-type not supported when used with upper-layer protocol '
          'restrictions. Term: %s' % self.name)
    # validate icmp-types if specified, but addr_family will have to be checked
    # in the generators as policy module doesn't know about that at this point.
    if self.icmp_type:
      for icmptype in self.icmp_type:
        if (icmptype not in self.ICMP_TYPE[4] and icmptype not in
            self.ICMP_TYPE[6]):
          raise TermInvalidIcmpType('Term %s contains an invalid icmp-type:'
                                    '%s' % (self.name, icmptype))

  def AddressCleanup(self, optimize=True):
    """Do Address and Port collapsing.

    Notes:
      Collapses both the address definitions and the port definitions
      to their smallest possible length.

    Args:
      optimize: boolean value indicating whether to optimize addresses
    """
    if optimize:
      cleanup = nacaddr.CollapseAddrList
    else:
      cleanup = nacaddr.SortAddrList

    # address collapsing.
    if self.address:
      self.address = cleanup(self.address)
    if self.source_address:
      self.source_address = cleanup(self.source_address)
    if self.source_address_exclude:
      self.source_address_exclude = cleanup(self.source_address_exclude)
    if self.destination_address:
      self.destination_address = cleanup(self.destination_address)
    if self.destination_address_exclude:
      self.destination_address_exclude = cleanup(
          self.destination_address_exclude)

    # port collapsing.
    if self.port:
      self.port = self.CollapsePortList(self.port)
    if self.source_port:
      self.source_port = self.CollapsePortList(self.source_port)
    if self.destination_port:
      self.destination_port = self.CollapsePortList(self.destination_port)

  def CollapsePortListRecursive(self, ports):
    """Given a sorted list of ports, collapse to the smallest required list.

    Args:
      ports: sorted list of port tuples

    Returns:
      ret_ports: collapsed list of ports
    """
    optimized = False
    ret_ports = []
    for port in ports:
      if not ret_ports:
        ret_ports.append(port)
      # we should be able to count on ret_ports[-1][0] <= port[0]
      elif ret_ports[-1][1] >= port[1]:
        # (10, 20) and (12, 13) -> (10, 20)
        optimized = True
      elif port[0] < ret_ports[-1][1] < port[1]:
        # (10, 20) and (15, 30) -> (10, 30)
        ret_ports[-1] = (ret_ports[-1][0], port[1])
        optimized = True
      elif ret_ports[-1][1] + 1 == port[0]:
        # (10, 20) and (21, 30) -> (10, 30)
        ret_ports[-1] = (ret_ports[-1][0], port[1])
        optimized = True
      else:
        # (10, 20) and (22, 30) -> (10, 20), (22, 30)
        ret_ports.append(port)

    if optimized:
      return self.CollapsePortListRecursive(ret_ports)
    return ret_ports

  def CollapsePortList(self, ports):
    """Given a list of ports, Collapse to the smallest required.

    Args:
      ports: a list of port strings eg: [(80,80), (53,53) (2000, 2009),
                                         (1024,65535)]

    Returns:
      ret_array: the collapsed sorted list of ports, eg: [(53,53), (80,80),
                                                          (1024,65535)]
    """
    return self.CollapsePortListRecursive(sorted(ports))

  def CheckPrincipalsContained(self, superset, subset):
    """Check to if the given list of principals is wholly contained.

    Args:
      superset: list of principals
      subset: list of principals

    Returns:
      bool: True if subset is contained in superset. false otherwise.
    """
    # Skip set comparison if neither term has principals.
    if not superset and not subset:
      return True

    # Convert these lists to sets to use set comparison.
    sup = set(superset)
    sub = set(subset)
    return sub.issubset(sup)

  def CheckProtocolIsContained(self, superset, subset):
    """Check if the given list of protocols is wholly contained.

    Args:
      superset: list of protocols
      subset: list of protocols

    Returns:
      bool: True if subset is contained in superset. false otherwise.
    """
    if not superset:
      return True
    if not subset:
      return False

    # Convert these lists to sets to use set comparison.
    sup = set(superset)
    sub = set(subset)
    return sub.issubset(sup)

  def CheckPortIsContained(self, superset, subset):
    """Check if the given list of ports is wholly contained.

    Args:
      superset: list of port tuples
      subset: list of port tuples

    Returns:
      bool: True if subset is contained in superset, false otherwise
    """
    if not superset:
      return True
    if not subset:
      return False

    for sub_port in subset:
      not_contains = True
      for sup_port in superset:
        if (int(sub_port[0]) >= int(sup_port[0])
            and int(sub_port[1]) <= int(sup_port[1])):
          not_contains = False
          break
      if not_contains:
        return False
    return True

  def CheckAddressIsContained(self, superset, subset):
    """Check if subset is wholey contained by superset.

    Args:
      superset: list of the superset addresses
      subset: list of the subset addresses

    Returns:
      True or False.
    """
    if not superset:
      return True
    if not subset:
      return False

    for sub_addr in subset:
      sub_contained = False
      for sup_addr in superset:
        # ipaddr ensures that version numbers match for inclusion.
        if sub_addr in sup_addr:
          sub_contained = True
          break
      if not sub_contained:
        return False
    return True


class Header(object):
  """The header of the policy file contains the targets and a global comment."""

  def __init__(self):
    self.target = []
    self.comment = []
    self.apply_groups = []
    self.apply_groups_except = []
    self.Name = None

  def __set_target(self, value):
    self.__target = value

  def __get_target(self):
    """Check all target platforms for duplicates (which will break other methods).

    Note: other methods for protecting against duplicates are possible.  Preferable
    would be to check for duplicates at the time of self.target.append(potential_dup),
    but that would require subclassing list (inadvisable), or creating a new container
    class (much code for little benefit).  Adding a self.add_target(t) is also possible,
    but that means that all clients need to know about the new method, which deviates
    from the existing code standard of straight member access.

    Raises:
      HeaderDuplicateTargetPlatformError if duplicate found."""
    platforms = map(lambda x: x.platform, self.__target)
    dups = set([x for x in platforms if platforms.count(x) > 1])
    if len(dups) > 0:
      msg = 'Duplicate platforms {0}'.format(', '.join(dups))
      raise HeaderDuplicateTargetPlatformError(msg)
    return self.__target

  target = property(__get_target, __set_target)
  """Public API method, adds data checks."""

  @property
  def platforms(self):
    """The platform targets of this particular header."""
    return map(lambda x: x.platform, self.target)

  def FilterOptions(self, platform):
    """Given a platform return the options.

    Args:
      platform: string

    Returns:
      list or None
    """
    for target in self.target:
      if target.platform == platform:
        return target.options
    return []

  def FilterName(self, platform):
    """Returns self.Name if set, or given a filter_type, return the filter name.

    Args:
      platform: string

    Returns:
      filter_name: string or None

    Notes:
      !! Deprecated in favor of Header.FilterOptions(platform) !!
      # TODO fix: remove this deprecated function.
    """
    if self.Name is not None:
      return self.Name
    for target in self.target:
      if target.platform == platform:
        if target.options:
          return target.options[0]
    return None

  def __str__(self):
    return 'Target[%s], Comments [%s], Apply groups: [%s], except: [%s]' % (
        ', '.join(map(str, self.target)),
        ', '.join(self.comment),
        ', '.join(self.apply_groups),
        ', '.join(self.apply_groups_except))

  def __repr__(self):
    return self.__str__()

  def __eq__(self, obj):
    """Compares for equality against another Header object.

    Note that it is picky and requires the list contents to be in the
    same order.

    Args:
      obj: object to be compared to for equality.
    Returns:
      True if all the list member variables of this object are equal to the list
      member variables of obj and False otherwise.
    """
    if not isinstance(obj, Header):
      return False
    if self.target != obj.target:
      return False
    if self.comment != obj.comment:
      return False
    if self.apply_groups != obj.apply_groups:
      return False
    if self.apply_groups_except != obj.apply_groups_except:
      return False
    return True


# This could be a VarType object, but I'm keeping it as it's class
# b/c we're almost certainly going to have to do something more exotic with
# it shortly to account for various rendering options like default iptables
# policies or output file names, etc. etc.
class Target(object):
  """The type of acl to be rendered from this policy file."""

  def __init__(self, target):
    self.platform = target[0]
    if len(target) > 1:
      self.options = target[1:]
    else:
      self.options = None

  def __str__(self):
    return self.platform

  def __repr__(self):
    return self.__str__()

  def __eq__(self, other):
    return self.platform == other.platform and self.options == other.options

  def __ne__(self, other):
    return not self.__eq__(other)


