# Copyright 2012 Google Inc. All Rights Reserved.
# $Id: //depot/google3/ops/security/lib/juniper.py#60 $
# $Date: 2011/07/22 $

"""SRX generator."""
# pylint: disable-msg=W0231

__author__ = 'robankeny@google.com (Robert Ankeny)'

import datetime
import logging

import aclgenerator
import nacaddr


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


class Term(aclgenerator.Term):
  """Representation of an individual SRX term.

     This is mostly useful for the __str__() method.

     Args:
       obj: a policy.Term object
       term_type: type of filter to generate, e.g. inet or inet6
       filter_options: list of remaining target options (zones)
  """

  _ACTIONS = {'accept': 'permit',
              'deny': 'deny',
              'reject': 'reject',
              'count': 'count',
              'log': 'log'}

  def __init__(self, term, term_type, zones):
    self.term = term
    self.term_type = term_type
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

    #COMMENTS
    comment_max_width = 68
    comments = aclgenerator.WrapWords(self.term.comment, comment_max_width)
    if comments and comments[0]:
      ret_str.append(JuniperSRX.INDENT * 3 + '/*')
      for line in comments:
        ret_str.append(JuniperSRX.INDENT * 3 + line)
      ret_str.append(JuniperSRX.INDENT * 3 + '*/')

    ret_str.append(JuniperSRX.INDENT * 3 + 'policy ' + self.term.name + ' {')
    ret_str.append(JuniperSRX.INDENT * 4 + 'match {')

    #SOURCE-ADDRESS
    if self.term.source_address:
      saddr_check = []
      for saddr in self.term.source_address:
        saddr_check.append(saddr.parent_token)
      saddr_check = set(saddr_check)
      source_address_string = ''
      for addr in saddr_check:
        source_address_string += addr + ' '
      ret_str.append(JuniperSRX.INDENT * 5 + 'source-address [ ' +
                     source_address_string + '];')
    else:
      ret_str.append(JuniperSRX.INDENT * 5 + 'source-address any;')

    #DESTINATION-ADDRESS
    if self.term.destination_address:
      daddr_check = []
      for daddr in self.term.destination_address:
        daddr_check.append(daddr.parent_token)
      daddr_check = set(daddr_check)
      destination_address_string = ''
      for addr in daddr_check:
        destination_address_string += addr + ' '
      ret_str.append(JuniperSRX.INDENT * 5 + 'destination-address [ ' +
                     destination_address_string + '];')
    else:
      ret_str.append(JuniperSRX.INDENT * 5 + 'destination-address any;')

    #APPLICATION
    if (not self.term.source_port and not self.term.destination_port and not
        self.term.icmp_type and not self.term.protocol):
      ret_str.append(JuniperSRX.INDENT * 5 + 'application any;')
    else:
      ret_str.append(JuniperSRX.INDENT * 5 + 'application ' + self.term.name +
                     '-app;')

    ret_str.append(JuniperSRX.INDENT * 4 + '}')

    #ACTIONS
    for action in self.term.action:
      ret_str.append(JuniperSRX.INDENT * 4 + 'then {')
      ret_str.append(JuniperSRX.INDENT * 5 + self._ACTIONS.get(
          str(action)) + ';')

      #LOGGING
      if self.term.logging:
        ret_str.append(JuniperSRX.INDENT * 5 + 'log {')
        ret_str.append(JuniperSRX.INDENT * 6 + 'session-init;')
        ret_str.append(JuniperSRX.INDENT * 5 + '}')
      ret_str.append(JuniperSRX.INDENT * 4 + '}')

      ret_str.append(JuniperSRX.INDENT * 3 + '}')

    #OPTIONS
    if self.term.option:
      raise SRXOptionError('Options are not implemented yet, please remove ' +
                           'from term %s' % self.term.name)

    #VERBATIM
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
  _SUFFIX = '.srx'
  _SUPPORTED_AF = set(('inet',))

  _OPTIONAL_SUPPORTED_KEYWORDS = set(['expiration', 'logging', 'timeout'])
  INDENT = '    '

  def _TranslatePolicy(self, pol):
    """Transform a policy object into a JuniperSRX object.

    Args:
      pol: policy.Policy object

    Raises:
      UnsupportedFilterError: An unsupported filter was specified
      UnsupportedHeader: A header option exists that is not understood/usable
      SRXDuplicateTermError: Two terms were found with same name in same filter
    """
    self.srx_policies = []
    self.addressbook = {}
    self.applications = []
    self.ports = []
    self.from_zone = ''
    self.to_zone = ''

    current_date = datetime.date.today()

    for header, terms in pol.filters:
      if not self._PLATFORM in header.platforms:
        continue

      filter_options = header.FilterOptions('srx')

      if (len(filter_options) < 4 or filter_options[0] != 'from-zone' or
          filter_options[2] != 'to-zone'):
        raise UnsupportedFilterError(
            'SRX filter arguments must specify from-zone and to-zone.')
      self.from_zone = filter_options[1]
      self.to_zone = filter_options[3]

      if len(filter_options) > 4:
        filter_type = filter_options[4]
      else:
        filter_type = 'inet'
      if filter_type not in self._SUPPORTED_AF:
        raise UnsupportedHeader(
            'SRX Generator currently does not support %s as a header option' %
            (filter_type))

      term_dup_check = set()
      new_terms = []
      for term in terms:
        if term.name in term_dup_check:
          raise SRXDuplicateTermError('You have a duplicate term: %s'
                                      % term.name)
        term_dup_check.add(term.name)

        if term.expiration and term.expiration <= current_date:
          logging.warn('WARNING: Term %s in policy %s>%s is expired and will '
                       'not be rendered.', term.name, self.from_zone,
                       self.to_zone)

        new_terms.append(Term(term, filter_type, filter_options))
        for i in term.source_address_exclude:
          term.source_address = nacaddr.RemoveAddressFromList(
              term.source_address, i)
        for i in term.destination_address_exclude:
          term.destination_address = nacaddr.RemoveAddressFromList(
              term.destination_address, i)

        for addr in term.source_address:
          self._BuildAddressBook(self.from_zone, addr)
        for addr in term.destination_address:
          self._BuildAddressBook(self.to_zone, addr)

        # create Term object so we can access the NormalizeIcmpTypes method
        # This is ugly, and the fix is probably to make method a function
        tmp = aclgenerator.Term()
        tmp_icmptype = tmp.NormalizeIcmpTypes(term.icmp_type, term.protocol,
                                              filter_type, term.name)
        # NormalizeIcmpTypes returns [''] for empty, convert to [] for eval
        normalized_icmptype = tmp_icmptype if tmp_icmptype != [''] else []
        # rewrites the protocol icmpv6 to icmp6
        if 'icmpv6' in term.protocol:
          protocol = list(term.protocol)
          protocol[protocol.index('icmpv6')] = 'icmp6'
        else:
          protocol = term.protocol
        self.applications.append({'sport': self._BuildPort(term.source_port),
                                  'dport': self._BuildPort(
                                      term.destination_port),
                                  'name': term.name,
                                  'protocol': protocol,
                                  'icmp-type': normalized_icmptype,
                                  'timeout': term.timeout})
      self.srx_policies.append((header, new_terms, filter_options))

  def _BuildAddressBook(self, zone, address):
    """Create the address book configuration entries.

    Args:
      zone: the zone these objects will reside in
      address: a naming library address object
    """
    if zone not in self.addressbook:
      self.addressbook[zone] = {}
    if address.parent_token not in self.addressbook[zone]:
      self.addressbook[zone][address.parent_token] = []
    name = address.parent_token
    for ip in self.addressbook[zone][name]:
      if str(address) == str(ip[0]):
        return
    counter = len(self.addressbook[zone][address.parent_token])
    name = '%s_%s' % (name, str(counter))
    self.addressbook[zone][address.parent_token].append((address, name))

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

  def __str__(self):
    """Render the output of the JuniperSRX policy into config."""
    target = []
    target.append('security {')
    target.append(self.INDENT + 'zones {')
    for zone in self.addressbook:
      target.append(self.INDENT * 2 + 'security-zone ' + zone + ' {')
      target.append(self.INDENT * 3 + 'address-book {')
      for group in self.addressbook[zone]:
        for address, name in self.addressbook[zone][group]:
          target.append(self.INDENT * 4 + 'address ' + name + ' ' +
                        str(address) + ';')
      for group in self.addressbook[zone]:
        target.append(self.INDENT * 4 + 'address-set ' + group + ' {')
        for address, name in self.addressbook[zone][group]:
          target.append(self.INDENT * 5 + 'address ' + name + ';')

        target.append(self.INDENT * 4 + '}')
      target.append(self.INDENT * 3 + '}')
      target.append(self.INDENT * 2 + '}')
    target.append(self.INDENT + '}')

    target.append(self.INDENT + 'policies {')
    for (_, terms, filter_options) in self.srx_policies:
      target.append(self.INDENT * 2 + 'from-zone ' + filter_options[1] +
                    ' to-zone ' + filter_options[3] + ' {')
      for term in terms:
        target.append(str(term))
      target.append(self.INDENT * 2 +'}')
    target.append(self.INDENT + '}')
    target.append('}')

    #APPLICATIONS
    target.append('applications {')
    done_apps = []
    for app in self.applications:
      app_list = []
      if app in done_apps:
        continue
      if app['protocol'] or app['sport'] or app['dport'] or app['icmp-type']:
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
                (i+1, str(code), int(timeout)))
        else:
          i = 1
          target.append(self.INDENT +
                        'application-set ' + app['name'] + '-app {')
          for proto in (app['protocol'] or ['']):
            for sport in (app['sport'] or ['']):
              for dport in (app['dport'] or ['']):
                chunks = []
                if proto: chunks.append(' protocol %s' % proto)
                if sport: chunks.append(' source-port %s' % sport)
                if dport: chunks.append(' destination-port %s' % dport)
                if app['timeout']:
                  chunks.append(' inactivity-timeout %d' % int(app['timeout']))
                if chunks:
                  target.append(self.INDENT * 2 +
                                'application ' + app['name'] + '-app%d;' % i)
                  app_list.append(self.INDENT + 'application ' + app['name'] +
                                  '-app%d {' % i)
                  app_list.append(self.INDENT * 2 + 'term t%d' % i +
                                  ''.join(chunks) + ';')
                  app_list.append(self.INDENT + '}')
                  i += 1
        target.append(self.INDENT + '}')
        done_apps.append(app)
        if app_list:
          target.extend(app_list)

    target.append('}')
    return '\n'.join(target)
