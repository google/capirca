# Copyright 2023 Google Inc. All Rights Reserved.
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

"""Versa generator."""
# pylint: disable=super-init-not-called


import collections
import copy
import datetime
import itertools

from absl import logging
from capirca.lib import aclgenerator
from capirca.lib import nacaddr



class Error(Exception):
  """generic error class."""


class UnsupportedFilterError(Error):
  """generic error class."""
  pass


class UnsupportedHeaderError(Error):
  """generic error class."""
  pass


class VersaDuplicateTermError(Error):
  """generic error class."""
  pass

class VersaUnsupportedTerm(Error):
  """generic error class."""
  pass

class VersaVerbatimError(Error):
  """generic error class."""
  pass


class VersaOptionError(Error):
  """generic error class."""
  pass


class MixedAddrBookTypesError(Error):
  """generic error class."""
  pass


class ConflictingTargetOptionsError(Error):
  """generic error class."""
  pass


class ConflictingApplicationSetsError(Error):
  """generic error class."""
  pass

class Tree:
  """Creates a Tree Object."""
  target=[]
  INDENT = '    '

  def __init__(self, name='root',typ=None):
    """The init function"""
    self.children = []
    self.name = name
    self.typ = typ


  def AddParent(self, parent=None):
    """Add a Node to Parent"""
    if isinstance(parent, Tree):
      parent.AddNode(self)

  def __repr__(self):
    """repr for a Node """
    return self.name

  def AddNode(self, node):
    """add a Node """
    assert isinstance(node, Tree)
    self.children.append(node)

  def FindNode(self, nodename):
    """find a Node """
    if self.name == nodename:
      return self
    if self.children:
      for child in self.children:
        ret = child.FindNode(nodename)
        if isinstance(ret, Tree):
          return ret
    return None

  # Print the tree
  def PrintTree(self,num=0):
    """Prints the tree. It returns the target """
    self.ResetTarget()
    self.PrintTreeInt(num)
    return self.target

  def PrintTreeInt(self,num=0):
    """Internal function to print the tree. Does recursion"""
    if self.name:
      self.target.append(f'{self.INDENT*num}{self.name}' + '  {')
    if self.typ is not None:
      if isinstance(self.typ, str):
        if self.name:
          self.target.append(f'{self.INDENT*(num+1)}{self.typ}')
        else:
          self.target.append(f'{self.INDENT*num}{self.typ}')
      elif isinstance(self.typ, list):
        for item in self.typ:
          self.target.append(f'{self.INDENT*(num+1)}{item}')
    if self.children:
      for child in self.children:
        child.PrintTreeInt(num+1)
    if self.name:
      self.target.append(f'{self.INDENT*num}' + '}')

  def ResetTarget(self):
    """Reset the target """
    self.target.clear()

class Term(aclgenerator.Term):
  """Representation of an individual Versa term.

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

  def __init__(self, term, from_zone, to_zone, addrbook, verbose=True):
    super().__init__(term)
    self.term = term
    self.from_zone = []
    self.to_zone = []
    self.verbose = verbose
    self.addrbook = addrbook
    self.app = []

    if term.source_zone:
      self.from_zone = term.source_zone
    elif from_zone != 'all':
      self.from_zone.append(from_zone)

    if term.destination_zone:
      self.to_zone = term.destination_zone
    elif to_zone != 'all':
      self.to_zone.append(to_zone)

  def AddApplication(self,new_app):
    """Add new app"""
    self.app.append(new_app)


  def BuildTermZone(self, p_node, zonetype):

    if zonetype == 'src':
      mtype = self.from_zone
      match_str = 'source'
      maddr = self.term.source_address
      maddr_ex = self.term.source_address_exclude
      addr_str = 'src-'
    else:
      mtype = self.to_zone
      match_str = 'destination'
      maddr = self.term.destination_address
      maddr_ex = self.term.destination_address_exclude
      addr_str = 'dest-'


    zone_str = '['
    for zone in mtype:
      zone_str = zone_str + ' ' + zone
    zone_str = zone_str + ' ];'
    match_node= Tree(match_str)
    match_node.AddParent(p_node)
    matchnode_zone = Tree('zone', 'zone-list ' + zone_str)
    matchnode_zone.AddParent(match_node)

    if maddr:
      if addr_str + self.term.name in self.addrbook:
        addr_list = ['address-group-list [ ' + addr_str + self.term.name+ ' ];']
        if maddr_ex:
          not_found = 0
          maddr_st = map(str, maddr)
          for ip in maddr_ex:
            if str(ip) not in maddr_st:
              not_found += 1
          if not_found > 0:
            # pylint: disable=logging-not-lazy
            logging.warning( f'WARNING: Term {self.term.name} in policy '+
                'has source or destination addresses that does not match ' +
                 'address list')
          addr_list.append('negate;')
        addr_t = Tree('address',addr_list)
        addr_t.AddParent(matchnode_zone )
      else:
        pass


  def BuildTermApp(self, p_node):
    """Build Term app"""
    mstr = []
    if self.app:
      apps = list(filter(lambda x: x['name'] == self.term.name, self.app))
      if len(apps) > 0:
        slist = ''
        for i in range(0,len(apps)):
          for j in range(0,len(apps[i]['protocol'])):
            slist = slist + ' ' + self.term.name + '-app' + str(j+1)
        if len(slist) > 0:
          slist = 'services-list [' + slist + ' ];'
          mstr.append(slist)

    if self.term.versa_application:
      predef_str = 'predefined-services-list ['
      for predef in self.term.versa_application:
        predef_str = predef_str + ' ' + predef
      predef_str = predef_str + ' ];'
      mstr.append(predef_str)
    if len(mstr) > 0 :
      services= Tree('services', mstr)
      services.AddParent(p_node)

  def BuildTermDscp(self, p_node):
    """Build Term dscp"""
    valid_dscp = []

    for dscp in self.term.dscp_match:
      if int(dscp) >= 0 and int(dscp) <= 63:
        valid_dscp.append(dscp)
      else:
        pass
    if valid_dscp:
      valid_dscp_str = 'dscp [ ' + ' '.join(valid_dscp) + ' ];'
      dscp = Tree('', valid_dscp_str)
      dscp.AddParent(p_node)

  def BuildTermLogging(self, p_node):
    """Build the Term Logging """
    set_term = Tree('set')
    set_term.AddParent(p_node)
    action_val = self.term.action[0]
    if action_val == 'accept':
      action_val = 'allow'
    action=Tree('', 'action ' + action_val + ';')
    action.AddParent(set_term)
    log_event = ''
    if not self.term.logging:
      log_event = 'never'
    elif str(self.term.logging[0]).lower() == 'true':
      log_event = 'start'
    elif str(self.term.logging[0]) == 'log-both':
      log_event = 'both'
    elif str(self.term.logging[0]) == 'disable':
      log_event = 'never'
    else:
      log_event = 'never'
    lef = Tree('lef', 'event '+ log_event + ';')
    lef.AddParent(set_term)

  def BuildTerm(self, p_node):
    """Build the Term Tree"""

    max_comment_length = 60
    access_pn=Tree('access-policy ' + self.term.name )
    access_pn.AddParent(p_node)
    if self.verbose and self.term.comment:
      if len(self.term.comment[0]) < max_comment_length:
        comm=Tree('', '/* ' + self.term.comment[0] + ' */')
      else:
        comments = aclgenerator.WrapWords(self.term.comment, 60)
        comments.append( '*/')
        comments.insert(0, '/*')
        comm=Tree('', comments)
      comm.AddParent(access_pn)

    rule_match =Tree('match')
    rule_match.AddParent(access_pn)

    if self.from_zone:
      self.BuildTermZone(rule_match, 'src')

    if self.to_zone:
      self.BuildTermZone(rule_match, 'dest')

    if self.term.versa_application or self.app:
      self.BuildTermApp(rule_match)

    if self.term.dscp_match:
      self.BuildTermDscp(rule_match)

    if self.term.action:
      self.BuildTermLogging(access_pn)

    #print("\n".join(set_term.PrintTree()))



class Versa(aclgenerator.ACLGenerator):
  """Versa rendering class.

     This class takes a policy object and renders the output into a syntax
     which is understood by Versa firewalls.

     Args:
       pol: policy.Policy object
  """

  _PLATFORM = 'versa'
  SUFFIX = '.vsp'
  _SUPPORTED_AF = set(('inet', 'inet6', 'mixed'))
  _ZONE_ADDR_BOOK = 'address-book-zone'
  _GLOBAL_ADDR_BOOK = 'address-book-global'
  _ADDRESSBOOK_TYPES = set((_ZONE_ADDR_BOOK, _GLOBAL_ADDR_BOOK))
  _NOVERBOSE = 'noverbose'
  _SUPPORTED_TARGET_OPTIONS = set((_ZONE_ADDR_BOOK,
                                   _GLOBAL_ADDR_BOOK,
                                   _NOVERBOSE))
  _VERSA_SUPPORTED_TARGET_OPTIONS = set(('template',
                                         'tenant',
                                         'policy'))

  _AF_MAP = {'inet': (4,),
             'inet6': (6,),
             'mixed': (4, 6)}
  _AF_ICMP_MAP = {'icmp': 'inet',
                  'icmpv6': 'inet6'}
  INDENT = '    '
  _MAX_HEADER_COMMENT_LENGTH = 71
  # The Versa platform is limited in how many IP addresses can be used in
  # a single policy.
  _ADDRESS_LENGTH_LIMIT = 1023
  # IPv6 are 32 bytes compared to IPv4, this is used as a multiplier.
  _IPV6_SIZE = 4

  def __init__(self, pol, exp_info):
    self.versa_policies = []
    self.comment = ''
    self.addressbook = collections.OrderedDict()
    self.applications = []
    self.ports = []
    self.from_zone = ''
    self.to_zone = ''
    self.addr_book_type = set()
    self.templatename = '_templatename'
    self.tenantname = '_tenantname'
    self.policyname = '_policyname'
    super().__init__(pol, exp_info)

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    supported_tokens, supported_sub_tokens = super()._BuildTokens()

    supported_tokens |= {
                         'dscp_match',
                         'destination_zone',
                         'logging',
                         'option',
                         'source_zone',
                         'versa_application'
                         }

    supported_sub_tokens.update(
        {'action': {'accept', 'deny', 'reject', 'count', 'log', 'dscp'},
        })

    del supported_sub_tokens['option']
    return supported_tokens, supported_sub_tokens


  def HeaderParams(self, mstr, val):
    """HeaderParams populates the template name and tenant name
    and policy name The basic config without the rules looks like this.

    devices {  template template_name {
    config { orgs { org-services tenantname { security { access-policies {
        access-policy-group Default-Policy { rules
        ...
       }
    } } } } }
    } }
    """

    if len(val) > 0:
      if 'template' in mstr:
        self.templatename = val
      elif 'tenant' in mstr:
        self.tenantname =  val
      elif 'policy' in mstr:
        self.policyname =  val

  def _TranslatePolicy(self, pol, exp_info):
    """
    # pylint: disable=attribute-defined-outside-init
    Transform a policy object into a Versa object.

    Args:
      pol: policy.Policy object
      exp_info: print a info message when a term is set to expire
                in that many weeks

    Raises:
      UnsupportedFilterError: An unsupported filter was specified
      UnsupportedHeaderError: A header option exists that is not
                              understood/usable
      VersaDuplicateTermError: Two terms were found with same name
                               in same filter
      ConflictingTargetOptionsError: Two target options are
                                    conflicting in the header
      MixedAddrBookTypesError: Global and Zone address books in the
                               same policy
      ConflictingApplicationSetsError: When two duplicate named terms
                               have conflicting application entries
    """
    current_date = datetime.datetime.utcnow().date()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)

    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue


      filter_options = header.FilterOptions(self._PLATFORM)

      # TODO(robankeny): Clean up option section.
      if (len(filter_options) < 4 or filter_options[0] != 'from-zone' or
          filter_options[2] != 'to-zone'):
        raise UnsupportedFilterError('Versa filter arguments must specify '
                                     'from-zone and to-zone.')

      # check if to-zone is not a supported target option
      self.from_zone = filter_options[1]
      if filter_options[1] in self._SUPPORTED_TARGET_OPTIONS:
        raise UnsupportedFilterError(f'to-zone {filter_options[1]} cannot be '+
                          'the same as any valid Versa target-options')

      # check if from-zone is not a supported target option
      self.to_zone = filter_options[3]
      if filter_options[3] in self._SUPPORTED_TARGET_OPTIONS:
        raise UnsupportedFilterError(f'from-zone {filter_options[1]} cannot'+
                ' be the same as any valid Versa target-options')

      # variables used to collect target-options and set defaults
      filter_type = ''

      # parse versa target options
      extra_options = filter_options[4:]
      if 'address-book' in ''.join(extra_options):
        raise UnsupportedFilterError('Unsupported address-book in target')

      address_book_type = {self._ZONE_ADDR_BOOK}
      self.addr_book_type.update(address_book_type)

      verbose = True
      cnt = -1
      for i in range(0, len(extra_options)):
        if cnt == i:
          continue   # we want to skip this element
        if (i+1 <= len(extra_options) and (extra_options[i] in
                              self._VERSA_SUPPORTED_TARGET_OPTIONS)):
          self.HeaderParams(extra_options[i], extra_options[i+1])
          cnt = i+1
        elif extra_options[i] in self._SUPPORTED_AF:
          if not filter_type:
            filter_type = extra_options[i]
          else:
            raise ConflictingTargetOptionsError(
              'only one address family can be specified per header')
        elif self._NOVERBOSE in extra_options[i]:
          verbose = False
        else:
          raise UnsupportedHeaderError(
            'Versa Generator currently does not support '
            f'{extra_options[i]} as a header option')

      if verbose and header.comment:
        self.comment = header.comment[0]

      # if address-family and address-book-type have not been set then default
      if not filter_type:
        filter_type = 'mixed'


      term_dup_check = set()

      new_terms = []
      self._FixLargePolices(terms, filter_type)
      addr_counter = 0
      for term in terms:
        # Only generate the term if it's for the appropriate platform.
        if term.platform:
          if self._PLATFORM not in term.platform:
            continue
        if term.platform_exclude:
          if self._PLATFORM in term.platform_exclude:
            continue

        if term.counter:
          raise VersaUnsupportedTerm(
            'Versa Generator currently does not support counter'
            '{' '.join(term.counter)}in the protocol field of term')

        if term.icmp_type:
          raise VersaUnsupportedTerm(
            'Versa Generator currently does not support icmp-type'
            '{' '.join(term.protocol)}in the protocol field of term')

        if term.protocol and 'icmpv6' in ' '.join(term.protocol):
          raise VersaUnsupportedTerm(
            'Versa Generator currently does not support icmpv6'
            '{' '.join(term.protocol)}in the protocol field of term')

        if term.stateless_reply:
          # pylint: disable=logging-not-lazy
          logging.warning( f'WARNING: Term {term.name} in policy '+
                f'{self.from_zone}>{self.to_zone} is a stateless reply '+
                 'term and will not be rendered.')
          continue
        if set(['established', 'tcp-established']).intersection(term.option):
          logging.debug('Skipping established term %s because Versa is' +
                          ' stateful.',term.name)
          continue
        term.name = self.FixTermLength(term.name)
        if term.name in term_dup_check:
          raise VersaDuplicateTermError('You have a duplicate term: ' +
                                        f'{term.name}')
        term_dup_check.add(term.name)

        if term.expiration:
          if term.expiration <= exp_info_date:
            logging.info('INFO: Term %s in policy %s>%s expires '
                         'in less than two weeks.', term.name, self.from_zone,
                         self.to_zone)
          if term.expiration <= current_date:
            logging.warning('WARNING: Term %s in policy %s>%s is expired.',
                            term.name, self.from_zone, self.to_zone)
            continue


        # Versa address books leverage network token names for IPs.
        # When excluding addresses, we lose those distinct names so we need
        # to create a new unique name based off the term name before excluding.
        if term.source_address_exclude:
          # If we have a naked source_exclude, we need something to exclude from
          if not term.source_address:
            raise VersaUnsupportedTerm('Versa Generator received source '+
                              'address exclude but no source address')

        if term.destination_address_exclude:
          if not term.destination_address:
            raise VersaUnsupportedTerm('Versa Generator received destination '+
                        'address but no destination address')

        # Filter source_address based on filter_type & add to address book
        if term.source_address:
          valid_addrs = []
          for addr in term.source_address:
            if addr.version in self._AF_MAP[filter_type]:
              valid_addrs.append(addr)
          if not valid_addrs:
            logging.warning(
                'WARNING: Term %s has 0 valid source IPs, skipping.', term.name)
            continue
          term.source_address = valid_addrs
          for addr in term.source_address:
            addr_counter=self._BuildAddressBook('src-'+term.name,
                                               addr_counter, addr)

        # Filter destination_address based on filter_type & add to address book
        if term.destination_address:
          valid_addrs = []
          for addr in term.destination_address:
            if addr.version in self._AF_MAP[filter_type]:
              valid_addrs.append(addr)
          if not valid_addrs:
            logging.warning(
                'WARNING: Term %s has 0 valid destination IPs, skipping.',
                term.name)
            continue
          term.destination_address = valid_addrs
          for addr in term.destination_address:
            addr_counter=self._BuildAddressBook('dest-'+term.name,
                                                addr_counter, addr)

        new_term = Term(term, self.from_zone, self.to_zone,
                                         self.addressbook, verbose)
        new_terms.append(new_term)

        if term.protocol and 'icmp' in ' '.join(term.protocol):
          term.protocol.remove('icmp')
          term.versa_application.append('ICMP')
        # Because Versa terms can contain inet and inet6 addresses. We have to
        # have ability to recover proper AF for ICMP type we need.
        # If protocol is empty or we cannot map to inet or inet6 we insert bogus
        # af_type name which will cause new_term.NormalizeIcmpTypes to fail.

        # NormalizeIcmpTypes returns [''] for empty, convert to [] for eval
        #normalized_icmptype = tmp_icmptype if tmp_icmptype != [''] else []
        # rewrites the protocol icmpv6 to icmp6
        if 'icmpv6' in term.protocol:
          protocol = list(term.protocol)
          protocol[protocol.index('icmpv6')] = 'icmp6'
        else:
          protocol = term.protocol
        new_application_set = {'sport': self.BuildPort(term.source_port),
                               'dport': self.BuildPort(term.destination_port),
                               'protocol': protocol }

        # add this only of one of the parameters is not None
        if ( new_application_set['sport'] or new_application_set['dport'] or
            new_application_set['protocol'] ):
          for application_set in self.applications:
            if all(item in list(application_set.items()) for item in
                   new_application_set.items()):
              new_application_set = ''
              term.replacement_application_name = application_set['name']
              break
            if (term.name == application_set['name'] and
                new_application_set != application_set):
              raise ConflictingApplicationSetsError(
                  f'Application set {term.name} has a conflicting entry')

          if new_application_set:
            new_application_set['name'] = term.name
            self.applications.append(new_application_set)
            new_term.AddApplication(new_application_set)

      self.versa_policies.append((header, new_terms, filter_options))

  def _FixLargePolices(self, terms, address_family):
    """Loops over all terms finding terms exceeding Versas policy limit.

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
        logging.warning('LARGE TERM ENCOUNTERED')
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

  def _BuildAddressBook(self, zone, counter, address):
    """Create the address book configuration entries.

    Args:
      zone: the zone these objects will reside in
      address: a naming library address object
    """
    if zone not in self.addressbook:
      self.addressbook[zone] = collections.defaultdict(list)
    if str(counter) in self.addressbook[zone]:
      return counter
    self.addressbook[zone][str(counter)].append(address)
    return counter + 1


  def BuildPort(self, ports):
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
        port_list.append(f'{str(i[0])}-{str(i[1])}')
    return port_list

  def GenerateAddressBook(self, node):
    """Generate Address Book into the Tree Structure

    Args:
      node: the Parent node to attach too

    Returns:
      None
    """
    if not self.addressbook:
      return
    addrs = Tree('addresses')
    addrs.AddParent(node)
    index=0
    for zone in self.addressbook:
      # building individual addresses
      groups = sorted(self.addressbook[zone])
      for group in groups:
        ips = nacaddr.SortAddrList(self.addressbook[zone][group])
        ips = nacaddr.CollapseAddrList(ips)
        self.addressbook[zone][group] = ips
        count = index + 0
        for address in self.addressbook[zone][group]:
          prefix_type = 'ipv4-prefix '
          if isinstance( address, nacaddr.IPv6):
            prefix_type = 'ipv6-prefix '
          addr_list = Tree('address'+' _' + group,  prefix_type +
                  ' ' + str(address) + ';')
          addr_list.AddParent(addrs)
          count += 1
      index += count

    addr_groups=Tree('address-groups')
    addr_groups.AddParent(node)
    for zone in self.addressbook:
      # building address-sets
      addrlist = ''
      for group in self.addressbook[zone]:
        addrlist = addrlist + '_' + group + ' '
      group_t=Tree('group ' + zone, 'address-list [ ' + addrlist + '];')
      group_t.AddParent(addr_groups)



  def GenerateApplications(self, node):
    """Generate Application into the Tree Structure

    Args:
      node: the Parent node to attach too

    Returns:
      None
    """
    if len(self.applications) == 0:
      return
    srvcs= Tree('services')
    srvcs.AddParent(node)
    i=1
    for app in sorted(self.applications, key=lambda x: x['name']):
      for proto in app['protocol'] or ['']:
        mstr = []
        # Protocol
        mstr.append('protocol '+ proto.upper() + ';')

        # Source Port
        if app['sport'] :
          sport_str = 'source-port \"'
          j=0
          for sport in app['sport']:
            sport_str = sport_str + sport
            if j < len(app['sport']) - 1:
              sport_str = sport_str + ', '
            j += 1
          sport_str = sport_str + '";'
          mstr.append(sport_str)

        # Destination Port
        if app['dport'] :
          dport_str = 'destination-port \"'
          j=0
          for dport in app['dport']:
            dport_str = dport_str + dport
            if j < len(app['dport']) - 1:
              dport_str = dport_str + ', '
            j += 1
          dport_str = dport_str + '";'
          mstr.append(dport_str)

        srv= Tree('service '+app['name'] + '-app' + str(i),mstr)
        srv.AddParent(srvcs)
        i += 1

  def __str__(self):
    """Render the output of the Versa policy into config."""
    root=Tree(name='devices')

    tmplt=Tree(name='template ' + self.templatename)
    tmplt.AddParent(root)

    config=Tree('config')
    config.AddParent(tmplt)

    if self.comment:
      comm=Tree('', '/* ' + self.comment + ' */')
      comm.AddParent(config)

    orgs=Tree('orgs')
    orgs.AddParent(config)

    org_services=Tree('org-services ' + self.tenantname )
    org_services.AddParent(orgs)

    sec=Tree('security')
    sec.AddParent(org_services)

    access_p=Tree('access-policies')
    access_p.AddParent(sec)

    access_pg=Tree('access-policy-group ' + self.policyname)
    access_pg.AddParent(access_p)

    rules=Tree('rules')
    rules.AddParent(access_pg)


    # pylint: disable=unused-variable
    for (header, terms, filter_options) in self.versa_policies:
      for term in terms:
        term.BuildTerm(rules)

    if self.addressbook:
      objects = Tree('objects')
      objects.AddParent(org_services)
      # AddressBook
      self.GenerateAddressBook(objects)
      # APPLICATIONS
      self.GenerateApplications(objects)

    target = root.PrintTree()

    return '\n'.join(target)
