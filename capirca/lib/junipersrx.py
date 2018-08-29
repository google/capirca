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

"""SRX generator."""
# pylint: disable=super-init-not-called

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import collections
import copy
import datetime
import itertools

from capirca.lib import aclgenerator
from capirca.lib import nacaddr
import six
from absl import logging


def JunipersrxList(name, data):
  return '%s [ %s ];' % (name, ' '.join(data))


class Error(Exception):
  """generic error class."""


class UnsupportedFilterError(Error):
  pass


class UnsupportedHeader(Error):
  pass


class SRXDuplicateTermError(Error):
  pass


class SRXVerbatimError(Error):
  pass


class SRXOptionError(Error):
  pass


class MixedAddrBookTypes(Error):
  pass


class ConflictingTargetOptions(Error):
  pass


class ConflictingApplicationSets(Error):
  pass


class IndentList(list):

  def __init__(self, indent, *args, **kwargs):
    self._indent = indent
    super(IndentList, self).__init__(*args, **kwargs)

  def IndentAppend(self, size, data):
    self.append('%s%s' % (self._indent * size, data))


class Term(aclgenerator.Term):
  """Representation of an individual SRX term.

     This is mostly useful for the __str__() method.

     Args:
       obj: a policy.Term object
       filter_options: list of remaining target options (zones)
  """

  ACTIONS = {'accept': 'permit',
             'deny': 'deny',
             'reject': 'reject',
             'count': 'count',
             'log': 'log',
             'expresspath': 'services-offload',
             'dscp': 'dscp'}

  def __init__(self, term, from_zone, to_zone, expresspath=False):
    super(Term, self).__init__(term)
    self.term = term
    self.from_zone = from_zone
    self.to_zone = to_zone
    if expresspath:
      self.term.action = [
          a.replace('accept', 'expresspath') for a in self.term.action]

  def __str__(self):
    """Render config output from this term object."""
    # Verify platform specific terms. Skip whole term if platform does not
    # match.
    if self.term.platform:
      if 'srx' not in self.term.platform:
        return ''
    if self.term.platform_exclude:
      if 'srx' in self.term.platform_exclude:
        return ''
    ret_str = IndentList(JuniperSRX.INDENT)

    # COMMENTS
    comment_max_width = 68
    if self.term.owner:
      self.term.comment.append('Owner: %s' % self.term.owner)
    comments = aclgenerator.WrapWords(self.term.comment, comment_max_width)
    if comments and comments[0]:
      ret_str.IndentAppend(3, '/*')
      for line in comments:
        ret_str.IndentAppend(3, line)
      ret_str.IndentAppend(3, '*/')

    ret_str.IndentAppend(3, 'policy ' + self.term.name + ' {')
    ret_str.IndentAppend(4, 'match {')
    # SOURCE-ADDRESS
    if self.term.source_address:
      saddr_check = set()
      for saddr in self.term.source_address:
        saddr_check.add(saddr.parent_token)
      saddr_check = sorted(saddr_check)
      ret_str.IndentAppend(5, JunipersrxList('source-address', saddr_check))
    else:
      ret_str.IndentAppend(5, 'source-address any;')

    # DESTINATION-ADDRESS
    if self.term.destination_address:
      daddr_check = []
      for daddr in self.term.destination_address:
        daddr_check.append(daddr.parent_token)
      daddr_check = set(daddr_check)
      daddr_check = list(daddr_check)
      daddr_check.sort()
      ret_str.IndentAppend(5, JunipersrxList('destination-address',
                                             daddr_check))
    else:
      ret_str.IndentAppend(5, 'destination-address any;')

    # APPLICATION
    if (not self.term.source_port and not self.term.destination_port and not
        self.term.icmp_type and not self.term.protocol):
      ret_str.IndentAppend(5, 'application any;')
    else:
      if hasattr(self.term, 'replacement_application_name'):
        ret_str.IndentAppend(5, 'application ' +
                             self.term.replacement_application_name + '-app;')
      else:
        ret_str.IndentAppend(5, 'application ' + self.term.name + '-app;')

    # DSCP MATCH
    if self.term.dscp_match:
      ret_str.IndentAppend(5, JunipersrxList('dscp', self.term.dscp_match))

    # DSCP EXCEPT
    if self.term.dscp_except:
      ret_str.IndentAppend(5, JunipersrxList('dscp-except',
                                             self.term.dscp_except))

    ret_str.IndentAppend(4, '}')

    # ACTIONS
    for action in self.term.action:
      ret_str.IndentAppend(4, 'then {')

      # VPN target can be only specified when ACTION is accept
      if str(action) == 'accept' and self.term.vpn:
        ret_str.IndentAppend(5, self.ACTIONS.get(
            str(action)) + ' {')
        ret_str.IndentAppend(6, 'tunnel {')
        ret_str.IndentAppend(7, 'ipsec-vpn %s;' % self.term.vpn[0])
        if self.term.vpn[1]:
          ret_str.IndentAppend(7, 'pair-policy %s;' % self.term.vpn[1])

        ret_str.IndentAppend(6, '}')
        ret_str.IndentAppend(5, '}')
      else:
        ret_str.IndentAppend(5, self.ACTIONS.get(str(action)) + ';')

      # DSCP SET
      if self.term.dscp_set:
        ret_str.IndentAppend(5, 'dscp ' + self.term.dscp_set + ';')

      # LOGGING
      if self.term.logging:
        ret_str.IndentAppend(5, 'log {')
        ret_str.IndentAppend(6, 'session-init;')
        for log_target in self.term.logging:
          if str(log_target) == 'log-both':
            ret_str.IndentAppend(6, 'session-close;')
        ret_str.IndentAppend(5, '}')

      ret_str.IndentAppend(4, '}')

      ret_str.IndentAppend(3, '}')

    return '\n'.join(ret_str)

  def _Group(self, group):
    """If 1 item return it, else return [ item1 item2 ].

    Args:
      group: a list.  could be a list of strings (protocols) or a list of
             tuples (ports)

    Returns:
      rval: a string surrounded by '[' and '];' if len(group) > 1
            or with just ';' appended if len(group) == 1
    """

    def _FormattedGroup(el):
      """Return the actual formatting of an individual element.

      Args:
        el: either a string (protocol) or a tuple (ports)

      Returns:
        string: either the lower()'ed string or the ports, hyphenated
                if they're a range, or by itself if it's not.
      """
      if isinstance(el, str):
        return el.lower()
      elif isinstance(el, int):
        return str(el)
      # type is a tuple below here
      elif el[0] == el[1]:
        return '%d' % el[0]
      else:
        return '%d-%d' % (el[0], el[1])

    if len(group) > 1:
      rval = '[ ' + ' '.join([_FormattedGroup(x) for x in group]) + ' ];'
    else:
      rval = _FormattedGroup(group[0]) + ';'
    return rval


class JuniperSRX(aclgenerator.ACLGenerator):
  """SRX rendering class.

     This class takes a policy object and renders the output into a syntax
     which is understood by SRX firewalls.

     Args:
       pol: policy.Policy object
  """

  _PLATFORM = 'srx'
  SUFFIX = '.srx'
  _SUPPORTED_AF = set(('inet', 'inet6', 'mixed'))
  _ZONE_ADDR_BOOK = 'address-book-zone'
  _GLOBAL_ADDR_BOOK = 'address-book-global'
  _ADDRESSBOOK_TYPES = set((_ZONE_ADDR_BOOK, _GLOBAL_ADDR_BOOK))
  _EXPRESSPATH = 'expresspath'
  _SUPPORTED_TARGET_OPTIONS = set((_ZONE_ADDR_BOOK, _GLOBAL_ADDR_BOOK,
                                   _EXPRESSPATH))

  _AF_MAP = {'inet': (4,),
             'inet6': (6,),
             'mixed': (4, 6)}
  _AF_ICMP_MAP = {'icmp': 'inet',
                  'icmpv6': 'inet6'}
  INDENT = '    '
  _MAX_HEADER_COMMENT_LENGTH = 71
  # The SRX platform is limited in how many IP addresses can be used in
  # a single policy.
  _ADDRESS_LENGTH_LIMIT = 1023
  # IPv6 are 32 bytes compared to IPv4, this is used as a multiplier.
  _IPV6_SIZE = 4

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    supported_tokens, supported_sub_tokens = super(
        JuniperSRX, self)._BuildTokens()

    supported_tokens |= {'dscp_except',
                         'dscp_match',
                         'dscp_set',
                         'logging',
                         'option',
                         'owner',
                         'timeout',
                         'verbatim',
                         'vpn'}

    supported_sub_tokens.update(
        {'action': {'accept', 'deny', 'reject', 'count', 'log', 'dscp'},
        })
    del supported_sub_tokens['option']
    return supported_tokens, supported_sub_tokens

  def _TranslatePolicy(self, pol, exp_info):
    # pylint: disable=attribute-defined-outside-init
    """Transform a policy object into a JuniperSRX object.

    Args:
      pol: policy.Policy object
      exp_info: print a info message when a term is set to expire
                in that many weeks

    Raises:
      UnsupportedFilterError: An unsupported filter was specified
      UnsupportedHeader: A header option exists that is not understood/usable
      SRXDuplicateTermError: Two terms were found with same name in same filter
      ConflictingTargetOptions: Two target options are conflicting in the header
      MixedAddrBookTypes: Global and Zone address books in the same policy
      ConflictingApplicationSets: When two duplicate named terms have
                                  conflicting application entries
    """
    self.srx_policies = []
    self.addressbook = collections.OrderedDict()
    self.applications = []
    self.ports = []
    self.from_zone = ''
    self.to_zone = ''
    self.addr_book_type = set()

    current_date = datetime.datetime.utcnow().date()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)

    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue

      filter_options = header.FilterOptions(self._PLATFORM)

      # TODO(robankeny): Clean up option section.
      if (len(filter_options) < 4 or filter_options[0] != 'from-zone' or
          filter_options[2] != 'to-zone'):
        raise UnsupportedFilterError('SRX filter arguments must specify '
                                     'from-zone and to-zone.')

      # check if to-zone is not a supported target option
      if filter_options[1] in self._SUPPORTED_TARGET_OPTIONS:
        raise UnsupportedFilterError('to-zone %s cannot be the same as any '
                                     'valid SRX target-options' %
                                     (filter_options[1]))
      else:
        self.from_zone = filter_options[1]

      # check if from-zone is not a supported target option
      if filter_options[3] in self._SUPPORTED_TARGET_OPTIONS:
        raise UnsupportedFilterError('from-zone %s cannot be the same as any '
                                     'valid SRX target-options' %
                                     (filter_options[3]))
      else:
        self.to_zone = filter_options[3]

      # variables used to collect target-options and set defaults
      filter_type = ''

      # parse srx target options
      extra_options = filter_options[4:]
      if self._ADDRESSBOOK_TYPES.issubset(extra_options):
        raise ConflictingTargetOptions('only one address-book-type can '
                                       'be specified per header "%s"' %
                                       ' '.join(filter_options))
      else:
        address_book_type = set([
            self._ZONE_ADDR_BOOK,
            self._GLOBAL_ADDR_BOOK]).intersection(extra_options)
        if len(address_book_type) is 0:
          address_book_type = {self._GLOBAL_ADDR_BOOK}
        self.addr_book_type.update(address_book_type)
        if len(self.addr_book_type) > 1:
          raise MixedAddrBookTypes('Global and Zone address-book-types cannot '
                                   'be used in the same policy')
        if self.from_zone == 'all' and self.to_zone == 'all':
          if self._ZONE_ADDR_BOOK in self.addr_book_type:
            raise UnsupportedFilterError('Zone address books cannot be used '
                                         'with a global policy.')
        elif self.from_zone == 'all' or self.to_zone == 'all':
          raise UnsupportedFilterError('The zone name all is reserved for '
                                       'global policies.')

      if self._EXPRESSPATH in filter_options[4:]:
        self.expresspath = True
      else:
        self.expresspath = False

      for filter_opt in filter_options[4:]:
          # validate address families
        if filter_opt in self._SUPPORTED_AF:
          if not filter_type:
            filter_type = filter_opt
          else:
            raise ConflictingTargetOptions('only one address family can be '
                                           'specified per header "%s"' %
                                           ' '.join(filter_options))
        elif filter_opt in self._SUPPORTED_TARGET_OPTIONS:
          continue
        else:
          raise UnsupportedHeader('SRX Generator currently does not support '
                                  '%s as a header option "%s"' %
                                  (filter_opt, ' '.join(filter_options)))

      # if address-family and address-book-type have not been set then default
      if not filter_type:
        filter_type = 'mixed'

      term_dup_check = set()
      new_terms = []
      self._FixLargePolices(terms, filter_type)
      for term in terms:
        if set(['established', 'tcp-established']).intersection(term.option):
          logging.debug('Skipping established term %s ' +
                        'because SRX is stateful.', term.name)
          continue
        term.name = self.FixTermLength(term.name)
        if term.name in term_dup_check:
          raise SRXDuplicateTermError('You have a duplicate term: %s'
                                      % term.name)
        term_dup_check.add(term.name)

        if term.expiration:
          if term.expiration <= exp_info_date:
            logging.info('INFO: Term %s in policy %s>%s expires '
                         'in less than two weeks.', term.name, self.from_zone,
                         self.to_zone)
          if term.expiration <= current_date:
            logging.warn('WARNING: Term %s in policy %s>%s is expired.',
                         term.name, self.from_zone, self.to_zone)
            continue

        # SRX address books leverage network token names for IPs.
        # When excluding addresses, we lose those distinct names so we need
        # to create a new unique name based off the term name before excluding.
        if term.source_address_exclude:
          # If we have a naked source_exclude, we need something to exclude from
          if not term.source_address:
            term.source_address = [nacaddr.IP('0.0.0.0/0',
                                              term.name.upper(),
                                              term.name.upper())]
          # Use the term name as the token & parent_token
          new_src_parent_token = term.name.upper() + '_SRC_EXCLUDE'
          new_src_token = new_src_parent_token
          for i in term.source_address_exclude:
            term.source_address = nacaddr.RemoveAddressFromList(
                term.source_address, i)
            for i in term.source_address:
              i.token = new_src_token
              i.parent_token = new_src_parent_token

        if term.destination_address_exclude:
          if not term.destination_address:
            term.destination_address = [nacaddr.IP('0.0.0.0/0',
                                                   term.name.upper(),
                                                   term.name.upper())]
          new_dst_parent_token = term.name.upper() + '_DST_EXCLUDE'
          new_dst_token = new_dst_parent_token
          for i in term.destination_address_exclude:
            term.destination_address = nacaddr.RemoveAddressFromList(
                term.destination_address, i)
            for i in term.destination_address:
              i.token = new_dst_token
              i.parent_token = new_dst_parent_token

        # SRX policies are controlled by addresses that are used within, so
        # policy can be at the same time inet and inet6.
        if self._GLOBAL_ADDR_BOOK in self.addr_book_type:
          for zone in self.addressbook:
            for unused_name, ips in sorted(six.iteritems(self.addressbook[zone])):
              ips = [i for i in ips]
              if term.source_address == ips:
                term.source_address = ips
              if term.destination_address == ips:
                term.destination_address = ips
        for addr in term.source_address:
          if addr.version in self._AF_MAP[filter_type]:
            self._BuildAddressBook(self.from_zone, addr)
        for addr in term.destination_address:
          if addr.version in self._AF_MAP[filter_type]:
            self._BuildAddressBook(self.to_zone, addr)

        new_term = Term(term, self.from_zone, self.to_zone, self.expresspath)
        new_terms.append(new_term)

        # Because SRX terms can contain inet and inet6 addresses. We have to
        # have ability to recover proper AF for ICMP type we need.
        # If protocol is empty or we cannot map to inet or inet6 we insert bogus
        # af_type name which will cause new_term.NormalizeIcmpTypes to fail.
        if not term.protocol:
          icmp_af_type = 'unknown_af_icmp'
        else:
          icmp_af_type = self._AF_ICMP_MAP.get(
              term.protocol[0], 'unknown_af_icmp')
        tmp_icmptype = new_term.NormalizeIcmpTypes(
            term.icmp_type, term.protocol, icmp_af_type)
        # NormalizeIcmpTypes returns [''] for empty, convert to [] for eval
        normalized_icmptype = tmp_icmptype if tmp_icmptype != [''] else []
        # rewrites the protocol icmpv6 to icmp6
        if 'icmpv6' in term.protocol:
          protocol = list(term.protocol)
          protocol[protocol.index('icmpv6')] = 'icmp6'
        else:
          protocol = term.protocol
        new_application_set = {'sport': self._BuildPort(term.source_port),
                               'dport': self._BuildPort(term.destination_port),
                               'protocol': protocol,
                               'icmp-type': normalized_icmptype,
                               'timeout': term.timeout}

        for application_set in self.applications:
          if all(item in list(application_set.items()) for item in
                 new_application_set.items()):
            new_application_set = ''
            term.replacement_application_name = application_set['name']
            break
          if (term.name == application_set['name'] and
              new_application_set != application_set):
            raise ConflictingApplicationSets(
                'Application set %s has a conflicting entry' % term.name)

        if new_application_set:
          new_application_set['name'] = term.name
          self.applications.append(new_application_set)

      self.srx_policies.append((header, new_terms, filter_options))

  def _FixLargePolices(self, terms, address_family):
    """Loops over all terms finding terms exceeding SRXs policy limit.

    Args:
      terms: List of terms from a policy.
      address_family: Tuple containing address family versions.

    See the following URL for more information
    http://www.juniper.net/techpubs/en_US/junos12.1x44/topics/reference/
    general/address-address-sets-limitations.html
    """

    def Chunks(l):
      """Splits a list of IP addresses into smaller lists based on byte size."""
      return_list = [[]]
      counter = 0
      index = 0
      for i in l:
        # Size is split in half due to the max size being a sum of src and dst.
        if counter > (self._ADDRESS_LENGTH_LIMIT/2):
          counter = 0
          index += 1
          return_list.append([])
        if i.version == 6:
          counter += self._IPV6_SIZE
        else:
          counter += 1
        return_list[index].append(i)
      return return_list

    expanded_terms = []
    for term in terms:
      if (term.AddressesByteLength(
          self._AF_MAP[address_family]) > self._ADDRESS_LENGTH_LIMIT):
        logging.warn('LARGE TERM ENCOUNTERED')
        src_chunks = Chunks(term.source_address)
        counter = 0
        for chunk in src_chunks:
          for ip in chunk:
            ip.parent_token = 'src_' + term.name + str(counter)
          counter += 1
        dst_chunks = Chunks(term.destination_address)
        counter = 0
        for chunk in dst_chunks:
          for ip in chunk:
            ip.parent_token = 'dst_' + term.name + str(counter)
          counter += 1

        src_dst_products = itertools.product(src_chunks, dst_chunks)
        counter = 0
        for src_dst_list in src_dst_products:
          new_term = copy.copy(term)
          new_term.source_address = src_dst_list[0]
          new_term.destination_address = src_dst_list[1]
          new_term.name = new_term.name + '_' + str(counter)
          expanded_terms.append(new_term)
          counter += 1
      else:
        expanded_terms.append(term)
    if expanded_terms:
      del terms[:]
      terms.extend(expanded_terms)

  def _BuildAddressBook(self, zone, address):
    """Create the address book configuration entries.

    Args:
      zone: the zone these objects will reside in
      address: a naming library address object
    """
    if zone not in self.addressbook:
      self.addressbook[zone] = collections.defaultdict(list)
    name = address.parent_token
    for ip in self.addressbook[zone][name]:
      if ip.Contains(address):
        return
      if address.Contains(ip):
        for index, ip_addr in enumerate(self.addressbook[zone][name]):
          if ip_addr == ip:
            self.addressbook[zone][name][index] = address
        return
    self.addressbook[zone][name].append(address)

  def _SortAddressBookNumCheck(self, item):
    """Used to give a natural order to the list of acl entries.

    Args:
      item: string of the address book entry name

    Returns:
      returns the characters and number
    """

    item_list = item.split('_')
    num = item_list.pop(-1)
    if isinstance(item_list[-1], int):
      set_number = item_list.pop(-1)
      num = int(set_number) * 1000 + int(num)
    alpha = '_'.join(item_list)
    if num:
      return (alpha, int(num))
    return (alpha, 0)

  def _BuildPort(self, ports):
    """Transform specified ports into list and ranges.

    Args:
      ports: a policy terms list of ports

    Returns:
      port_list: list of ports and port ranges
    """
    port_list = []
    for i in ports:
      if i[0] == i[1]:
        port_list.append(str(i[0]))
      else:
        port_list.append('%s-%s' % (str(i[0]), str(i[1])))
    return port_list

  def _GenerateAddressBook(self):
    """Creates address book."""
    target = IndentList(self.INDENT)

    # create address books if address-book-type set to global
    if self._GLOBAL_ADDR_BOOK in self.addr_book_type:
      global_address_book = collections.defaultdict(list)

      target.IndentAppend(1, 'replace: address-book {')
      target.IndentAppend(2, 'global {')
      for zone in self.addressbook:
        for group in self.addressbook[zone]:
          for address in self.addressbook[zone][group]:
            global_address_book[group].append(address)
      names = sorted(global_address_book.keys())
      for name in names:
        counter = 0
        ips = nacaddr.SortAddrList(global_address_book[name])
        ips = nacaddr.CollapseAddrList(ips)
        global_address_book[name] = ips
        for ip in ips:
          target.IndentAppend(4, 'address ' + name + '_' + str(counter) + ' ' +
                              str(ip) + ';')
          counter += 1

      for group in sorted(global_address_book.keys()):
        target.IndentAppend(4, 'address-set ' + group + ' {')
        counter = 0
        for unused_addr in global_address_book[group]:
          target.IndentAppend(5, 'address ' + group + '_' + str(counter) + ';')
          counter += 1
        target.IndentAppend(4, '}')

      target.IndentAppend(2, '}')
      target.IndentAppend(1, '}')

    else:
      target.IndentAppend(1, 'zones {')
      for zone in self.addressbook:
        target.IndentAppend(2, 'security-zone ' + zone + ' {')
        target.IndentAppend(3, 'replace: address-book {')

        # building individual addresses
        groups = sorted(self.addressbook[zone])
        for group in groups:
          ips = nacaddr.SortAddrList(self.addressbook[zone][group])
          ips = nacaddr.CollapseAddrList(ips)
          self.addressbook[zone][group] = ips
          count = 0
          for address in self.addressbook[zone][group]:
            target.IndentAppend(4, 'address ' + group + '_' + str(count) +
                                ' ' + str(address) + ';')
            count += 1

        # building address-sets
        for group in groups:
          target.IndentAppend(4, 'address-set ' + group + ' {')
          count = 0
          for address in self.addressbook[zone][group]:
            target.IndentAppend(5, 'address ' + group + '_' + str(count) + ';')
            count += 1

          target.IndentAppend(4, '}')
        target.IndentAppend(3, '}')
        target.IndentAppend(2, '}')
      target.IndentAppend(1, '}')

    return target

  def _GenerateApplications(self):
    target = IndentList(self.INDENT)
    apps_set_list = IndentList(self.INDENT)
    target.append('replace: applications {')
    done_apps = []
    for app in sorted(self.applications, key=lambda x: x['name']):
      app_list = IndentList(self.INDENT)
      if app in done_apps:
        continue

      if app['protocol'] or app['sport'] or app['dport'] or app['icmp-type']:
        # generate ICMP statements
        if app['icmp-type']:
          target.IndentAppend(1, 'application ' + app['name'] + '-app {')

          if app['timeout']:
            timeout = app['timeout']
          else:
            timeout = 60
          for i, code in enumerate(app['icmp-type']):
            for proto in app['protocol']:
              target.IndentAppend(
                  2,
                  'term t%d protocol %s %s-type %s inactivity-timeout %d;' %
                  (i + 1, proto, proto, str(code), int(timeout))
              )
          target.IndentAppend(1, '}')

        # generate non-ICMP statements
        else:
          i = 1
          apps_set_list.IndentAppend(1, 'application-set ' +
                                     app['name'] + '-app {')

          for proto in app['protocol'] or ['']:
            for sport in app['sport'] or ['']:
              for dport in app['dport'] or ['']:
                chunks = []
                if proto:
                  # SRX does not like proto vrrp
                  if proto == 'vrrp':
                    proto = '112'
                  chunks.append(' protocol %s' % proto)
                if sport:
                  chunks.append(' source-port %s' % sport)
                if dport:
                  chunks.append(' destination-port %s' % dport)
                if app['timeout']:
                  chunks.append(' inactivity-timeout %d' % int(app['timeout']))
                if chunks:
                  apps_set_list.IndentAppend(
                      2, 'application ' + app['name'] + '-app%d;' % i
                  )
                  app_list.IndentAppend(
                      1, 'application ' + app['name'] + '-app%d {' % i
                  )

                  app_list.IndentAppend(2, 'term t%d' % i +
                                        ''.join(chunks) + ';')
                  app_list.IndentAppend(1, '}')
                  i += 1
          apps_set_list.IndentAppend(1, '}')

        done_apps.append(app)
        if app_list:
          target.extend(app_list)

    target.extend(apps_set_list)
    target.append('}\n')
    return target

  def __str__(self):
    """Render the output of the JuniperSRX policy into config."""
    target = IndentList(self.INDENT)
    target.append('security {')

    # ADDRESSBOOK
    target.extend(self._GenerateAddressBook())

    # POLICIES
    target.IndentAppend(1, '/*')
    target.extend(aclgenerator.AddRepositoryTags(self.INDENT * 1))
    target.IndentAppend(1, '*/')

    target.IndentAppend(1, 'replace: policies {')

    for (header, terms, filter_options) in self.srx_policies:
      target.IndentAppend(2, '/*')
      target.extend([self.INDENT * 2 + line for line in
                     aclgenerator.WrapWords(header.comment,
                                            self._MAX_HEADER_COMMENT_LENGTH)])
      target.IndentAppend(2, '*/')

      # ZONE DIRECTION
      if filter_options[1] == 'all' and filter_options[3] == 'all':
        target.IndentAppend(2, 'global {')
      else:
        target.IndentAppend(2, 'from-zone ' + filter_options[1] +
                            ' to-zone ' + filter_options[3] + ' {')

      # GROUPS
      if header.apply_groups:
        target.IndentAppend(3, JunipersrxList('apply-groups',
                                              header.apply_groups))
      # GROUPS EXCEPT
      if header.apply_groups_except:
        target.IndentAppend(
            3,
            JunipersrxList('apply-groups-except', header.apply_groups_except)
        )
      for term in terms:
        str_result = str(term)
        if str_result:
          target.append(str_result)
      target.IndentAppend(2, '}')
    target.IndentAppend(1, '}')
    target.append('}')

    # APPLICATIONS
    target.extend(self._GenerateApplications())

    return '\n'.join(target)
