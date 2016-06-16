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

__author__ = 'robankeny@google.com (Robert Ankeny)'

import collections
import copy
import datetime
import itertools

from lib import aclgenerator
from lib import nacaddr
import logging


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
             'dscp': 'dscp'}

  def __init__(self, term, zones):
    super(Term, self).__init__(term)
    self.term = term
    self.from_zone = zones[1]
    self.to_zone = zones[3]
    self.extra_actions = []

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
    ret_str = []

    # COMMENTS
    comment_max_width = 68
    if self.term.owner:
      self.term.comment.append('Owner: %s' % self.term.owner)
    comments = aclgenerator.WrapWords(self.term.comment, comment_max_width)
    if comments and comments[0]:
      ret_str.append(JuniperSRX.INDENT * 3 + '/*')
      for line in comments:
        ret_str.append(JuniperSRX.INDENT * 3 + line)
      ret_str.append(JuniperSRX.INDENT * 3 + '*/')

    ret_str.append(JuniperSRX.INDENT * 3 + 'policy ' + self.term.name + ' {')
    ret_str.append(JuniperSRX.INDENT * 4 + 'match {')

    # SOURCE-ADDRESS
    if self.term.source_address:
      saddr_check = set()
      for saddr in self.term.source_address:
        saddr_check.add(saddr.parent_token)
      saddr_check = sorted(saddr_check)
      source_address_string = ''
      for addr in saddr_check:
        source_address_string += addr + ' '
      ret_str.append(JuniperSRX.INDENT * 5 + 'source-address [ ' +
                     source_address_string + '];')
    else:
      ret_str.append(JuniperSRX.INDENT * 5 + 'source-address any;')

    # DESTINATION-ADDRESS
    if self.term.destination_address:
      daddr_check = []
      for daddr in self.term.destination_address:
        daddr_check.append(daddr.parent_token)
      daddr_check = set(daddr_check)
      daddr_check = list(daddr_check)
      daddr_check.sort()
      destination_address_string = ''
      for addr in daddr_check:
        destination_address_string += addr + ' '
      ret_str.append(JuniperSRX.INDENT * 5 + 'destination-address [ ' +
                     destination_address_string + '];')
    else:
      ret_str.append(JuniperSRX.INDENT * 5 + 'destination-address any;')

    # APPLICATION
    if (not self.term.source_port and not self.term.destination_port and not
        self.term.icmp_type and not self.term.protocol):
      ret_str.append(JuniperSRX.INDENT * 5 + 'application any;')
    else:
      ret_str.append(JuniperSRX.INDENT * 5 + 'application ' + self.term.name +
                     '-app;')

    # DSCP MATCH
    if self.term.dscp_match:
      ret_str.append(JuniperSRX.INDENT * 5 + 'dscp'
                     ' [ ' + ' '.join(self.term.dscp_match) + ' ];')

    # DSCP EXCEPT
    if self.term.dscp_except:
      ret_str.append(JuniperSRX.INDENT * 5 + 'dscp-except'
                     ' [ ' + ' '.join(self.term.dscp_except) + ' ];')

    ret_str.append(JuniperSRX.INDENT * 4 + '}')

    # ACTIONS
    for action in self.term.action:
      ret_str.append(JuniperSRX.INDENT * 4 + 'then {')

      # VPN target can be only specified when ACTION is accept
      if str(action) == 'accept' and self.term.vpn:
        ret_str.append(JuniperSRX.INDENT * 5 + self.ACTIONS.get(
            str(action)) + ' {')
        ret_str.append(JuniperSRX.INDENT * 6 + 'tunnel {')
        ret_str.append(JuniperSRX.INDENT * 7 + 'ipsec-vpn %s;' %
                       self.term.vpn[0])
        if self.term.vpn[1]:
          ret_str.append(JuniperSRX.INDENT * 7 + 'pair-policy %s;' %
                         self.term.vpn[1])

        ret_str.append(JuniperSRX.INDENT * 6 + '}')
        ret_str.append(JuniperSRX.INDENT * 5 + '}')

      else:
        ret_str.append(JuniperSRX.INDENT * 5 + self.ACTIONS.get(
            str(action)) + ';')

      # DSCP SET
      if self.term.dscp_set:
        ret_str.append(
            JuniperSRX.INDENT * 5 + 'dscp ' + self.term.dscp_set + ';')

      # LOGGING
      if self.term.logging:
        ret_str.append(JuniperSRX.INDENT * 5 + 'log {')
        ret_str.append(JuniperSRX.INDENT * 6 + 'session-init;')
        for log_target in self.term.logging:
          if str(log_target) == 'log-both':
            ret_str.append(JuniperSRX.INDENT * 6 + 'session-close;')
        ret_str.append(JuniperSRX.INDENT * 5 + '}')

      ret_str.append(JuniperSRX.INDENT * 4 + '}')

      ret_str.append(JuniperSRX.INDENT * 3 + '}')

    # OPTIONS
    if self.term.option:
      raise SRXOptionError('Options are not implemented yet, please remove ' +
                           'from term %s' % self.term.name)

    # VERBATIM
    if self.term.verbatim:
      raise SRXVerbatimError('Verbatim is not implemented, please remove ' +
                             'the offending term %s.' % self.term.name)
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
  _SUPPORTED_TARGET_OPTIONS = set(('address-book-zone', 'address-book-global'))
  _AF_MAP = {'inet': (4,),
             'inet6': (6,),
             'mixed': (4, 6)}
  _AF_ICMP_MAP = {'icmp': 'inet',
                  'icmpv6': 'inet6'}
  _OPTIONAL_SUPPORTED_KEYWORDS = set(['dscp_except',
                                      'dscp_match',
                                      'dscp_set',
                                      'expiration',
                                      'logging',
                                      'owner',
                                      'routing_instance',    # safe to skip
                                      'timeout',
                                      'qos',                 # safely ignored
                                      'counter',             # safely ignored
                                      'vpn'])
  INDENT = '    '
  _MAX_HEADER_COMMENT_LENGTH = 71
  # The SRX platform is limited in how many IP addresses can be used in
  # a single policy.
  _ADDRESS_LENGTH_LIMIT = 1023
  # IPv6 are 32 bytes compared to IPv4, this is used as a multiplier.
  _IPV6_SIZE = 4

  def _TranslatePolicy(self, pol, exp_info):
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
                                  conflicting applicaiton entries
    """
    self.srx_policies = []
    self.addressbook = collections.OrderedDict()
    self.applications = []
    self.ports = []
    self.from_zone = ''
    self.to_zone = ''
    self.addr_book_type_global = True
    self.file_comment = []

    current_date = datetime.datetime.utcnow().date()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)

    # list is used for check if policy only utilizes one type of address book.
    # (global or zone)
    addr_book_types = []
    self._FixLargePolices()
    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue

      if header.filecomment:
        self.file_comment = header.filecomment

      filter_options = header.FilterOptions(self._PLATFORM)

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
      target_options = []
      filter_type = ''
      address_book_type = ''

      # parse srx target options
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
          target_options.append(filter_opt)

          # check to see if option is an address-book-type and only one
          # address-book-type is specified per header
          if filter_opt == 'address-book-zone':
            if not address_book_type:
              address_book_type = 'zone'
            else:
              raise ConflictingTargetOptions('only one address-book-type can '
                                             'be specified per header "%s"' %
                                             ' '.join(filter_options))
          elif filter_opt == 'address-book-global':
            if not address_book_type:
              address_book_type = 'global'
            else:
              raise ConflictingTargetOptions('only one address-book-type can '
                                             'be specified per header "%s"' %
                                             ' '.join(filter_options))
          else:
            raise UnsupportedHeader('SRX Generator currently does not '
                                    'support %s as a header option "%s"' %
                                    (filter_opt, ' '.join(filter_options)))
        else:
          raise UnsupportedHeader('SRX Generator currently does not support '
                                  '%s as a header option "%s"' %
                                  (filter_opt, ' '.join(filter_options)))

      # if address-family and address-book-type have not been set then default
      if not filter_type:
        filter_type = 'mixed'
      if not address_book_type:
        address_book_type = 'global'

      addr_book_types.append(address_book_type)

      # check if policy is global
      if self.from_zone == 'all' and self.to_zone == 'all':
        if address_book_type == 'zone':
          raise UnsupportedFilterError('Zone address books cannot be used with '
                                       'a global policy.')
      elif self.from_zone == 'all' or self.to_zone == 'all':
        raise UnsupportedFilterError('The zone name all is reserved for global '
                                     'policies.')

      term_dup_check = set()
      new_terms = []
      for term in terms:
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

        for i in term.source_address_exclude:
          term.source_address = nacaddr.RemoveAddressFromList(
              term.source_address, i)
        for i in term.destination_address_exclude:
          term.destination_address = nacaddr.RemoveAddressFromList(
              term.destination_address, i)

        # SRX policies are controlled by addresses that are used within, so
        # policy can be at the same time inet and inet6.

        for addr in term.source_address:
          if addr.version in self._AF_MAP[filter_type]:
            self._BuildAddressBook(self.from_zone, addr)
        for addr in term.destination_address:
          if addr.version in self._AF_MAP[filter_type]:
            self._BuildAddressBook(self.to_zone, addr)

        new_term = Term(term, filter_options)
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
                               'name': term.name,
                               'protocol': protocol,
                               'icmp-type': normalized_icmptype,
                               'timeout': term.timeout}

        for application_set in self.applications:
          if (term.name == application_set['name'] and
              new_application_set != application_set):
            raise ConflictingApplicationSets(
                'Application set %s has a conflicting entry' % term.name)

        self.applications.append(new_application_set)

      self.srx_policies.append((header, new_terms, filter_options))

    # Check if policy only utilizes one type of address book. (global or zone)
    if all(p == 'global' for p in addr_book_types):
      self.addr_book_type_global = True
    elif all(p == 'zone' for p in addr_book_types):
      self.addr_book_type_global = False
    else:
      raise MixedAddrBookTypes('Global and Zone address-book-types cannot '
                               'be used in the same policy')

  def _FixLargePolices(self):
    """Loops over all terms finding terms exceeding SRXs policy limit.

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

    for (unused_header, terms) in self.policy.filters:
      expanded_terms = []
      for term in terms:
        if term.AddressesByteLength() > self._ADDRESS_LENGTH_LIMIT:
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
      if ip[0].Contains(address):
        return
      if address.Contains(ip[0]):
        for index, ip_addr in enumerate(self.addressbook[zone][name]):
          if ip_addr == ip:
            self.addressbook[zone][name][index] = (
                address, self.addressbook[zone][name][index][1])
        return
    counter = len(self.addressbook[zone][name])
    address_name = '%s_%s' % (name, str(counter))
    self.addressbook[zone][name].append((address, address_name))

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
    target = []

    # create address books if address-book-type set to global
    if self.addr_book_type_global:
      address_book_names_dict = {}
      address_book_groups_dict = {}

      target.append(self.INDENT + 'replace: address-book {')
      target.append(self.INDENT * 2 + 'global {')
      for zone in self.addressbook:

        # building individual addresses dictionary
        groups = sorted(self.addressbook[zone])
        for group in groups:
          for address, name in self.addressbook[zone][group]:
            if name in address_book_names_dict:
              if address_book_names_dict[name].Contains(address):
                continue
            address_book_names_dict[name] = address

        # building individual address-set dictionary
        for group in groups:
          group_names = []
          for address, name in self.addressbook[zone][group]:
            group_names.append(name)
          address_book_groups_dict[group] = group_names

      # sort address books and address sets
      address_book_groups_dict = collections.OrderedDict(
          sorted(address_book_groups_dict.items()))
      address_book_keys = sorted(
          address_book_names_dict.keys(), key=self._SortAddressBookNumCheck)

      # add global address-book to target
      for name in address_book_keys:
        target.append(self.INDENT * 4 + 'address ' + name + ' ' +
                      str(address_book_names_dict[name]) + ';')

      for group, address_list in address_book_groups_dict.items():
        target.append(self.INDENT * 4 + 'address-set ' + group + ' {')
        for name in address_list:
          target.append(self.INDENT * 5 + 'address ' + name + ';')
        target.append(self.INDENT * 4 + '}')

      target.append(self.INDENT * 2 + '}')
      target.append(self.INDENT + '}')

    else:
      target.append(self.INDENT + 'zones {')
      for zone in self.addressbook:
        target.append(self.INDENT * 2 + 'security-zone ' + zone + ' {')
        target.append(self.INDENT * 3 + 'replace: address-book {')

        # building individual addresses
        groups = sorted(self.addressbook[zone])
        for group in groups:
          for address, name in self.addressbook[zone][group]:
            target.append(self.INDENT * 4 + 'address ' + name + ' ' +
                          str(address) + ';')

        # building address-sets
        for group in groups:
          target.append(self.INDENT * 4 + 'address-set ' + group + ' {')
          for address, name in self.addressbook[zone][group]:
            target.append(self.INDENT * 5 + 'address ' + name + ';')

          target.append(self.INDENT * 4 + '}')
        target.append(self.INDENT * 3 + '}')
        target.append(self.INDENT * 2 + '}')
      target.append(self.INDENT + '}')

    return target

  def _GenerateApplications(self):
    target = []
    apps_set_list = []
    target.append('replace: applications {')
    done_apps = []
    for app in sorted(self.applications, key=lambda x: x['name']):
      app_list = []
      if app in done_apps:
        continue

      if app['protocol'] or app['sport'] or app['dport'] or app['icmp-type']:
        # generate ICMP statements
        if app['icmp-type']:
          target.append(self.INDENT + 'application ' + app['name'] + '-app {')

          if app['timeout']:
            timeout = app['timeout']
          else:
            timeout = 60
          for i, code in enumerate(app['icmp-type']):
            target.append(
                self.INDENT * 2 +
                'term t%d protocol icmp icmp-type %s inactivity-timeout %d;' %
                (i + 1, str(code), int(timeout)))
          target.append(self.INDENT + '}')

        # generate non-ICMP statements
        else:
          i = 1
          apps_set_list.append(
              self.INDENT + 'application-set ' + app['name'] + '-app {')

          for proto in app['protocol'] or ['']:
            for sport in app['sport'] or ['']:
              for dport in app['dport'] or ['']:
                chunks = []
                if proto:
                  # SRX does not like proto vrrp
                  if proto == 'vrrp': proto = '112'
                  chunks.append(' protocol %s' % proto)
                if sport: chunks.append(' source-port %s' % sport)
                if dport: chunks.append(' destination-port %s' % dport)
                if app['timeout']:
                  chunks.append(' inactivity-timeout %d' % int(app['timeout']))
                if chunks:
                  apps_set_list.append(
                      self.INDENT * 2 + 'application ' + app['name'] +
                      '-app%d;' % i)
                  app_list.append(self.INDENT + 'application ' + app['name'] +
                                  '-app%d {' % i)

                  app_list.append(self.INDENT * 2 + 'term t%d' % i +
                                  ''.join(chunks) + ';')
                  app_list.append(self.INDENT + '}')
                  i += 1
          apps_set_list.append(self.INDENT + '}')

        done_apps.append(app)
        if app_list:
          target.extend(app_list)

    target.extend(apps_set_list)
    target.append('}\n')
    return target

  def __str__(self):
    """Render the output of the JuniperSRX policy into config."""
    target = []

    # add file comments
    for fc in self.file_comment:
      fc = fc.replace('"', "")
      target.append('/* %s */' % fc)

    target.append('security {')

    # ADDRESSBOOK
    target.extend(self._GenerateAddressBook())

    # POLICIES
    target.append(self.INDENT * 1 + '/*')
    target.extend(aclgenerator.AddRepositoryTags(self.INDENT * 1))
    target.append(self.INDENT * 1 + '*/')

    target.append(self.INDENT + 'replace: policies {')

    for (header, terms, filter_options) in self.srx_policies:
      target.append(self.INDENT * 2 + '/*')
      target.extend([self.INDENT * 2 + line for line in
                     aclgenerator.WrapWords(header.comment,
                                            self._MAX_HEADER_COMMENT_LENGTH)])
      target.append(self.INDENT * 2 + '*/')

      # ZONE DIRECTION
      if filter_options[1] == 'all' and filter_options[3] == 'all':
        target.append(self.INDENT * 2 + 'global {')
      else:
        target.append(self.INDENT * 2 + 'from-zone ' + filter_options[1] +
                      ' to-zone ' + filter_options[3] + ' {')

      # GROUPS
      if header.apply_groups:
        target.append(self.INDENT * 3 + 'apply-groups [ ' +
                      ' '.join(header.apply_groups) + ' ];')
      # GROUPS EXCEPT
      if header.apply_groups_except:
        target.append(self.INDENT * 3 + 'apply-groups-except [ ' +
                      ' '.join(header.apply_groups_except) + ' ];')
      for term in terms:
        target.append(str(term))
      target.append(self.INDENT * 2 + '}')
    target.append(self.INDENT + '}')
    target.append('}')

    # APPLICATIONS
    target.extend(self._GenerateApplications())

    return '\n'.join(target)
