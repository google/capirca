# Copyright 2015 The Capirca Project Authors All Rights Reserved.
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

"""Nsxv generator."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import datetime
import re
import xml.dom.minidom

from capirca.lib import aclgenerator
from capirca.lib import nacaddr
from six.moves import map
from six.moves import range
from absl import logging


_ACTION_TABLE = {
    'accept': 'allow',
    'deny': 'deny',
    'reject': 'reject',
    'reject-with-tcp-rst': 'reject',  # tcp rst not supported
}

_XML_TABLE = {
    'actionStart': '<action>',
    'actionEnd': '</action>',
    'srcIpv4Start': '<source><type>Ipv4Address</type><value>',
    'srcIpv4End': '</value></source>',
    'destIpv4Start': '<destination><type>Ipv4Address</type><value>',
    'destIpv4End': '</value></destination>',
    'protocolStart': '<protocol>',
    'protocolEnd': '</protocol>',
    'serviceStart': '<service>',
    'serviceEnd': '</service>',
    'appliedToStart': '<appliedTo><type>SecurityGroup</type><value>',
    'appliedToEnd': '</value></appliedTo>',
    'srcPortStart': '<sourcePort>',
    'srcPortEnd': '</sourcePort>',
    'destPortStart': '<destinationPort>',
    'destPortEnd': '</destinationPort>',
    'icmpTypeStart': '<subProtocol>',
    'icmpTypeEnd': '</subProtocol>',
    'logTrue': '<loggingEnabled>true</loggingEnabled>',
    'logFalse': '<loggingEnabled>false</loggingEnabled>',
    'sectionStart': '<section>',
    'sectionEnd': '</section>',
    'nameStart': '<name>',
    'nameEnd': '</name>',
    'srcIpv6Start': '<source><type>Ipv6Address</type><value>',
    'srcIpv6End': '</value></source>',
    'destIpv6Start': '<destination><type>Ipv6Address</type><value>',
    'destIpv6End': '</value></destination>',
    'noteStart': '<notes>',
    'noteEnd': '</notes>',
}

_NSXV_SUPPORTED_KEYWORDS = [
    'name',
    'action',
    'comment',
    'destination_address',
    'destination_address_exclude',
    'destination_port',
    'expiration',
    'icmp_type',
    'protocol',
    'source_address',
    'source_address_exclude',
    'source_port',
    'expiration',
    'logging'
]


# generic error class
class Error(Exception):
  """Generic error class."""
  pass


class UnsupportedNsxvAccessListError(Error):
  """Raised when we're give a non named access list."""
  pass


class NsxvAclTermError(Error):
  """Raised when there is a problem in a nsxv access list."""
  pass


class NsxvDuplicateTermError(Error):
  """Raised when there is a duplicate."""
  pass


class Term(aclgenerator.Term):
  """Creates a  single ACL Term for Nsxv."""

  def __init__(self, term, filter_type, applied_to=None, af=4):
    self.term = term
    # Our caller should have already verified the address family.
    assert af in (4, 6)
    self.af = af
    self.filter_type = filter_type
    self.applied_to = applied_to

  def __str__(self):
    """Convert term to a rule string.

    Returns:
      A rule as a string.

    Raises:
      NsxvAclTermError: When unknown icmp-types are specified

    """
    # Verify platform specific terms. Skip whole term if platform does not
    # match.
    if self.term.platform:
      if 'nsxv' not in self.term.platform:
        return ''
    if self.term.platform_exclude:
      if 'nsxv' in self.term.platform_exclude:
        return ''

    ret_str = ['']

    # Don't render icmpv6 protocol terms under inet, or icmp under inet6
    if ((self.af == 6 and 'icmp' in self.term.protocol) or
        (self.af == 4 and 'icmpv6' in self.term.protocol)):
      logging.debug(self.NO_AF_LOG_PROTO.substitute(term=self.term.name,
                                                    proto=self.term.protocol,
                                                    af=self.filter_type))
      return ''

    # Term verbatim is not supported
    if self.term.verbatim:
      raise NsxvAclTermError(
          'Verbatim are not implemented in standard ACLs')

    # Term option is not supported
    if self.term.option:
      for opt in [str(single_option) for single_option in self.term.option]:
        if((opt.find('tcp-established') == 0)
           or (opt.find('established') == 0)):
          return ''
        else:
          raise NsxvAclTermError(
              'Option are not implemented in standard ACLs')

    # check for keywords Nsxv does not support
    term_keywords = self.term.__dict__
    unsupported_keywords = []
    for key  in term_keywords:
      if term_keywords[key]:
        # translated is obj attribute not keyword
        if ('translated' not in key) and (key not in _NSXV_SUPPORTED_KEYWORDS):
          unsupported_keywords.append(key)
    if unsupported_keywords:
      logging.warn('WARNING: The keywords %s in Term %s are not supported in '
                   'Nsxv ', unsupported_keywords, self.term.name)

    name = '%s%s%s' % (_XML_TABLE.get('nameStart'), self.term.name,
                       _XML_TABLE.get('nameEnd'))

    notes = ''
    if self.term.comment:
      for comment in self.term.comment:
        notes = '%s%s' %(notes, comment)
      notes = '%s%s%s' % (_XML_TABLE.get('noteStart'), notes,
                          _XML_TABLE.get('noteEnd'))

    # protocol
    protocol = None

    if self.term.protocol:
      protocol = list(map(self.PROTO_MAP.get, self.term.protocol, self.term.protocol))

      # icmp-types
      icmp_types = ['']
      if self.term.icmp_type:
        icmp_types = self.NormalizeIcmpTypes(self.term.icmp_type,
                                             self.term.protocol,
                                             self.af)

    # for mixed filter type get both IPV4address and IPv6Address
    af_list = []
    if self.filter_type == 'mixed':
      af_list = [4, 6]
    else:
      af_list = [self.af]

    source_address = None
    destination_address = None
    source_addr = []
    destination_addr = []

    source_v4_addr = []
    source_v6_addr = []
    dest_v4_addr = []
    dest_v6_addr = []

    for af in af_list:
      # source address
      if self.term.source_address:
        source_address = self.term.GetAddressOfVersion('source_address', af)
        source_address_exclude = self.term.GetAddressOfVersion(
            'source_address_exclude', af)
        if source_address_exclude:
          source_address = nacaddr.ExcludeAddrs(
              source_address,
              source_address_exclude)

        if source_address:
          if af == 4:
            source_v4_addr = source_address
          else:
            source_v6_addr = source_address
        source_addr = source_v4_addr + source_v6_addr

      # destination address
      if self.term.destination_address:
        destination_address = self.term.GetAddressOfVersion(
            'destination_address', af)
        destination_address_exclude = self.term.GetAddressOfVersion(
            'destination_address_exclude', af)
        if destination_address_exclude:
          destination_address = nacaddr.ExcludeAddrs(
              destination_address,
              destination_address_exclude)

        if destination_address:
          if af == 4:
            dest_v4_addr = destination_address
          else:
            dest_v6_addr = destination_address
        destination_addr = dest_v4_addr + dest_v6_addr

    # Check for mismatch IP for source and destination address for mixed filter
    if self.filter_type == 'mixed':
      if source_addr and destination_addr:
        if source_v4_addr and not dest_v4_addr:
          source_addr = source_v6_addr
        elif source_v6_addr and not dest_v6_addr:
          source_addr = source_v4_addr
        elif dest_v4_addr and not source_v4_addr:
          destination_addr = dest_v6_addr
        elif dest_v6_addr and not source_v6_addr:
          destination_addr = dest_v4_addr

        if not source_addr or not destination_addr:
          logging.warn('Term %s will not be rendered as it has IPv4/IPv6 '
                       'mismatch for source/destination for mixed address '
                       'family.', self.term.name)
          return ''

    # ports
    source_port = None
    destination_port = None
    if self.term.source_port:
      source_port = self.term.source_port
    if self.term.destination_port:
      destination_port = self.term.destination_port

    # logging
    log = 'false'
    if self.term.logging:
      log = 'true'

    sources = ''
    if source_addr:
      sources = '<sources excluded="false">'
      for saddr in source_addr:

        # inet4
        if isinstance(saddr, nacaddr.IPv4):
          if saddr.numhosts > 1:
            saddr = '%s%s%s' % (_XML_TABLE.get('srcIpv4Start'),
                                saddr.with_prefixlen,
                                _XML_TABLE.get('srcIpv4End'),)
          else:
            saddr = '%s%s%s' % (_XML_TABLE.get('srcIpv4Start'),
                                saddr.ip,
                                _XML_TABLE.get('srcIpv4End'))
          sources = '%s%s' %(sources, saddr)
        # inet6
        if isinstance(saddr, nacaddr.IPv6):
          if saddr.numhosts > 1:
            saddr = '%s%s%s' % (_XML_TABLE.get('srcIpv6Start'),
                                saddr.with_prefixlen,
                                _XML_TABLE.get('srcIpv6End'),)
          else:
            saddr = '%s%s%s' % (_XML_TABLE.get('srcIpv6Start'),
                                saddr.ip, _XML_TABLE.get('srcIpv6End'))
          sources = '%s%s' %(sources, saddr)
      sources = '%s%s' %(sources, '</sources>')

    destinations = ''
    if destination_addr:
      destinations = '<destinations excluded="false">'
      for daddr in destination_addr:
        # inet4
        if isinstance(daddr, nacaddr.IPv4):
          if daddr.numhosts > 1:
            daddr = '%s%s%s' % (_XML_TABLE.get('destIpv4Start'),
                                daddr.with_prefixlen,
                                _XML_TABLE.get('destIpv4End'),)
          else:
            daddr = '%s%s%s' % (_XML_TABLE.get('destIpv4Start'),
                                daddr.ip,
                                _XML_TABLE.get('destIpv4End'))
          destinations = '%s%s' %(destinations, daddr)
        # inet6
        if isinstance(daddr, nacaddr.IPv6):
          if daddr.numhosts > 1:
            daddr = '%s%s%s' % (_XML_TABLE.get('destIpv6Start'),
                                daddr.with_prefixlen,
                                _XML_TABLE.get('destIpv6End'),)
          else:
            daddr = '%s%s%s' % (_XML_TABLE.get('destIpv6Start'),
                                daddr.ip,
                                _XML_TABLE.get('destIpv6End'))
          destinations = '%s%s' %(destinations, daddr)
      destinations = '%s%s' %(destinations, '</destinations>')

    services = []
    if protocol:
      services.append('<services>')
      for proto in protocol:
        if proto != 'any':
          services.append(self._ServiceToString(proto,
                                                source_port,
                                                destination_port,
                                                icmp_types))
      services.append('</services>')

    service = ''
    for s in services:
      service = '%s%s' % (service, s)

    # applied_to
    applied_to_list = ''
    if self.applied_to:
      applied_to_list = '<appliedToList>'
      applied_to_element = '%s%s%s' % (_XML_TABLE.get('appliedToStart'),
                                       self.applied_to,
                                       _XML_TABLE.get('appliedToEnd'))
      applied_to_list = '%s%s' %(applied_to_list, applied_to_element)
      applied_to_list = '%s%s' %(applied_to_list, '</appliedToList>')

    # action
    action = '%s%s%s' % (_XML_TABLE.get('actionStart'),
                         _ACTION_TABLE.get(str(self.term.action[0])),
                         _XML_TABLE.get('actionEnd'))

    ret_lines = []
    ret_lines.append('<rule logged="%s">%s%s%s%s%s%s%s</rule>' %
                     (log, name, action, sources, destinations, service,
                      applied_to_list, notes))

    # remove any trailing spaces and replace multiple spaces with singles
    stripped_ret_lines = [re.sub(r'\s+', ' ', x).rstrip() for x in ret_lines]
    ret_str.extend(stripped_ret_lines)
    return ''.join(ret_str)

  def _ServiceToString(self, proto, sports, dports, icmp_types):
    """Converts service to string.

    Args:
      proto: str, protocl
      sports: str list or none, the source port
      dports: str list or none, the destination port
      icmp_types: icmp-type numeric specification (if any)

    Returns:
      Service definition.

    """
    service = ''
    # for icmp and icmpv6
    if proto == 1 or proto == 58:
      # handle icmp protocol
      for icmp_type in icmp_types:
        icmp_service = '%s%s%s%s' % (_XML_TABLE.get('serviceStart'),
                                     _XML_TABLE.get('protocolStart'), proto,
                                     _XML_TABLE.get('protocolEnd'))
        # handle icmp types
        if icmp_type:
          icmp_type = '%s%s%s' %(_XML_TABLE.get('icmpTypeStart'),
                                 str(icmp_type),
                                 _XML_TABLE.get('icmpTypeEnd'))
          icmp_service = '%s%s' % (icmp_service, icmp_type)
        icmp_service = '%s%s' % (icmp_service, _XML_TABLE.get('serviceEnd'))
        service = '%s%s' % (service, icmp_service)
    else:
      # handle other protocols
      service = '%s%s%s%s' % (_XML_TABLE.get('serviceStart'),
                              _XML_TABLE.get('protocolStart'), proto,
                              _XML_TABLE.get('protocolEnd'))

      # handle source ports
      if sports:
        str_sport = []
        for sport in sports:
          if sport[0] != sport[1]:
            str_sport.append('%s-%s' % (sport[0], sport[1]))
          else:
            str_sport.append('%s' % (sport[0]))
        service = '%s%s%s%s' % (service, _XML_TABLE.get('srcPortStart'),
                                ', '.join(str_sport),
                                _XML_TABLE.get('srcPortEnd'))

      # handle destination ports
      if dports:
        str_dport = []
        for dport  in dports:
          if dport[0] != dport[1]:
            str_dport.append('%s-%s' % (dport[0], dport[1]))
          else:
            str_dport.append('%s' % (dport[0]))
        service = '%s%s%s%s' % (service, _XML_TABLE.get('destPortStart'),
                                ', '.join(str_dport),
                                _XML_TABLE.get('destPortEnd'))
      service = '%s%s' % (service, _XML_TABLE.get('serviceEnd'))

    return service


class Nsxv(aclgenerator.ACLGenerator):
  """Nsxv rendering class.

    This class takes a policy object and renders the output into a syntax
    which is understood by nsxv policy.

  Args:
    pol: policy.Policy object

  Raises:
  UnsupportedNsxvAccessListError: Raised when we're give a non named access
  list.

  """

  _PLATFORM = 'nsxv'
  _DEFAULT_PROTOCOL = 'ip'
  SUFFIX = '.nsx'

  _OPTIONAL_SUPPORTED_KEYWORDS = set(['expiration',
                                      'logging',
                                     ])
  _FILTER_OPTIONS_DICT = {}

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    supported_tokens, supported_sub_tokens = super(Nsxv, self)._BuildTokens()

    supported_tokens |= {'logging'}
    supported_sub_tokens.update({'action': {'accept', 'deny', 'reject',
                                            'reject-with-tcp-rst'}})
    del supported_sub_tokens['option']
    return supported_tokens, supported_sub_tokens

  def _TranslatePolicy(self, pol, exp_info):
    self.nsxv_policies = []
    current_date = datetime.datetime.utcnow().date()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)

    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue

      filter_options = header.FilterOptions(self._PLATFORM)
      if len(filter_options) >= 2:
        filter_name = filter_options[1]

      # get filter type, section id and applied To
      self._ParseFilterOptions(filter_options)

      filter_type = self._FILTER_OPTIONS_DICT['filter_type']
      applied_to = self._FILTER_OPTIONS_DICT['applied_to']

      term_names = set()
      new_terms = []
      for term in terms:
        # Check for duplicate terms
        if term.name in term_names:
          raise NsxvDuplicateTermError('There are multiple terms named: %s' %
                                       term.name)
        term_names.add(term.name)

        if term.expiration:
          if term.expiration <= exp_info_date:
            logging.info('INFO: Term %s in policy %s expires '
                         'in less than two weeks.', term.name, filter_name)
          if term.expiration <= current_date:
            logging.warn('WARNING: Term %s in policy %s is expired and '
                         'will not be rendered.', term.name, filter_name)
            continue
        # Get the mapped action value
        # If there is no mapped action value term is not rendered
        mapped_action = _ACTION_TABLE.get(str(term.action[0]))
        if not mapped_action:
          logging.warn('WARNING: Action %s in Term %s is not valid and '
                       'will not be rendered.', term.action, term.name)
          continue

        term.name = self.FixTermLength(term.name)

        if filter_type == 'inet':
          af = 'inet'
          term = self.FixHighPorts(term, af=af)
          if not term:
            continue
          new_terms.append(Term(term, filter_type, applied_to, 4))

        if filter_type == 'inet6':
          af = 'inet6'
          term = self.FixHighPorts(term, af=af)
          if not term:
            continue
          new_terms.append(Term(term, filter_type, applied_to, 6))

        if filter_type == 'mixed':
          if 'icmpv6' not in term.protocol:
            inet_term = self.FixHighPorts(term, 'inet')
            if not inet_term:
              continue
            new_terms.append(Term(inet_term, filter_type, applied_to, 4))
          else:
            inet6_term = self.FixHighPorts(term, 'inet6')
            if not inet6_term:
              continue
            new_terms.append(Term(inet6_term, filter_type, applied_to, 6))

      self.nsxv_policies.append((header, filter_name, [filter_type],
                                 new_terms))

  def _ParseFilterOptions(self, filter_options):
    """Parses the target in header for filter type, section_id and applied_to.

    Args:
      filter_options: list of remaining target options

    Returns:
      A dictionary that contains fields necessary to create the firewall
      rule.

    Raises:
      UnsupportedNsxvAccessListError: Raised when we're give a non named access
      list.
    """
    # check for filter type
    if not 2 <= len(filter_options) <= 5:
      raise UnsupportedNsxvAccessListError(
          'Invalid Number of options specified: %d. Required options '
          'are: filter type and section name. Platform: %s' % (
              len(filter_options), self._PLATFORM))
    # mandatory section_name
    section_name = filter_options[0]
    # mandatory
    filter_type = filter_options[1]

    # a mixed filter outputs both ipv4 and ipv6 acls in the same output file
    good_filters = ['inet', 'inet6', 'mixed']

    # check if filter type is renderable
    if filter_type not in good_filters:
      raise UnsupportedNsxvAccessListError(
          'Access list type %s not supported by %s (good types: %s)' % (
              filter_type, self._PLATFORM, str(good_filters)))

    section_id = 0
    applied_to = None
    filter_opt_len = len(filter_options)

    if filter_opt_len > 2:
      for index in range(2, filter_opt_len):
        if index == 2 and filter_options[2] != 'securitygroup':
          section_id = filter_options[2]
          continue
        if filter_options[index] == 'securitygroup':
          if index + 1 <= filter_opt_len - 1:
            applied_to = filter_options[index + 1]
            break
          else:
            raise UnsupportedNsxvAccessListError(
                'Security Group Id is not provided for %s' % (self._PLATFORM))

    self._FILTER_OPTIONS_DICT['section_name'] = section_name
    self._FILTER_OPTIONS_DICT['filter_type'] = filter_type
    self._FILTER_OPTIONS_DICT['section_id'] = section_id
    self._FILTER_OPTIONS_DICT['applied_to'] = applied_to

  def __str__(self):
    """Render the output of the Nsxv policy."""

    target_header = []
    target = []

    # add the p4 tags
    target.append('<!--')
    target.extend(aclgenerator.AddRepositoryTags('\n'))
    target.append('\n')
    target.append('-->')

    for (_, _, _, terms) in self.nsxv_policies:
      section_name = self._FILTER_OPTIONS_DICT['section_name']
      # check section id value
      section_id = self._FILTER_OPTIONS_DICT['section_id']
      if not section_id or section_id == 0:
        logging.warn('WARNING: Section-id is 0. A new Section is created for%s.'
                     ' If there is any existing section, it will remain '
                     'unreferenced and should be removed manually.',
                     section_name)
        target.append('<section name="%s">' % (section_name.strip(' \t\n\r')))
      else:
        target.append('<section id="%s" name="%s">' %
                      (section_id, section_name.strip(' \t\n\r')))

      # now add the terms
      for term in terms:
        term_str = str(term)
        if term_str:
          target.append(term_str)

      # ensure that the header is always first
      target = target_header + target
      target.append('%s' % (_XML_TABLE.get('sectionEnd')))
      target.append('\n')

      target_as_xml = xml.dom.minidom.parseString(''.join(target))
    return target_as_xml.toprettyxml(indent='  ', encoding='UTF-8')
