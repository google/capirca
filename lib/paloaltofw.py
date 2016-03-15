#!/usr/bin/python

"""Palo Alto Firewall generator."""

__author__ = 'apoorva.dornadula@berkeley.edu (Apoorva Dornadula)'

import collections
import datetime
import logging

import aclgenerator
import nacaddr

import re


class Error(Exception):
  """generic error class."""


class UnsupportedFilterError(Error):
  pass


class UnsupportedHeader(Error):
  pass


class PaloAltoFWDuplicateTermError(Error):
  pass


class PaloAltoFWVerbatimError(Error):
  pass


class PaloAltoFWOptionError(Error):
  pass

class PaloAltoFWDuplicateServiceError(Error):
  pass


class Term(aclgenerator.Term):
  """Representation of an individual term.

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
      if 'paloalto' not in self.term.platform:
        return ''
    if self.term.platform_exclude:
      if 'paloalto' in self.term.platform_exclude:
        return ''
    ret_str = []

    # COMMENTS
    comment_max_width = 68
    if self.term.owner:
      self.term.comment.append('Owner: %s' % self.term.owner)
    comments = aclgenerator.WrapWords(self.term.comment, comment_max_width)
    if comments and comments[0]:
      ret_str.append(PaloAltoFW.INDENT * 3 + '/*')
      for line in comments:
        ret_str.append(PaloAltoFW.INDENT * 3 + line)
      ret_str.append(PaloAltoFW.INDENT * 3 + '*/')

    ret_str.append(PaloAltoFW.INDENT * 3 + 'policy ' + self.term.name + ' {')
    ret_str.append(PaloAltoFW.INDENT * 4 + 'match {')

    # SOURCE-ADDRESS
    if self.term.source_address:
      saddr_check = set()
      for saddr in self.term.source_address:
        saddr_check.add(saddr.parent_token)
      saddr_check = sorted(saddr_check)
      source_address_string = ''
      for addr in saddr_check:
        source_address_string += addr + ' '
      ret_str.append(PaloAltoFW.INDENT * 5 + 'source-address [ ' +
                     source_address_string + '];')
    else:
      ret_str.append(PaloAltoFW.INDENT * 5 + 'source-address any;')

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
      ret_str.append(PaloAltoFW.INDENT * 5 + 'destination-address [ ' +
                     destination_address_string + '];')
    else:
      ret_str.append(PaloAltoFW.INDENT * 5 + 'destination-address any;')

    # APPLICATION
    if (not self.term.source_port and not self.term.destination_port and not
        self.term.icmp_type and not self.term.protocol):
      ret_str.append(PaloAltoFW.INDENT * 5 + 'application any;')
    else:
      ret_str.append(PaloAltoFW.INDENT * 5 + 'application ' + self.term.name +
                     '-app;')

    ret_str.append(PaloAltoFW.INDENT * 4 + '}')

    # ACTIONS
    for action in self.term.action:
      ret_str.append(PaloAltoFW.INDENT * 4 + 'then {')
      ret_str.append(PaloAltoFW.INDENT * 5 + self._ACTIONS.get(
          str(action)) + ';')

      # LOGGING
      if self.term.logging:
        ret_str.append(PaloAltoFW.INDENT * 5 + 'log {')
        ret_str.append(PaloAltoFW.INDENT * 6 + 'session-init;')
        ret_str.append(PaloAltoFW.INDENT * 5 + '}')
      ret_str.append(PaloAltoFW.INDENT * 4 + '}')

      ret_str.append(PaloAltoFW.INDENT * 3 + '}')

    # OPTIONS
    if self.term.option:
      raise PaloAltoFWOptionError('Options are not implemented yet, please remove ' +
                           'from term %s' % self.term.name)

    # VERBATIM
    if self.term.verbatim:
      raise PaloAltoFWVerbatimError('Verbatim is not implemented, please remove ' +
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


class Service():

  service_map = {}
  def __init__(self, ports, service_name, protocol): # ports is a tuple of ports
    global counter
    if ports in self.service_map:
      raise PaloAltoFWDuplicateServiceError('You have a duplicate service. A service already exists on port(s): %s'
                                      % str(ports))
    tup = str(ports)[1:-1]
    if tup[-1] == ",":
      tup = tup[:-1]
    self.service_map[(ports, protocol)] = {"name": "service-" + protocol + "-" + tup}


class Rule():

  rules = {}
  def __init__(self, from_zone, to_zone, terms):
    # Palo Alto Firewall rule keys
    self.options = {}
    self.options["from_zone"] = [from_zone]
    self.options["to_zone"] = [to_zone]

    self.modifyOptions(terms)

  def extract_ip(self, cidr):
    r = re.search("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", cidr)
    return r.group() if r else "any"

  def modifyOptions(self, PAFWterm):
    # for PAFWterm in terms:
    term = PAFWterm.term
    self.options["source"] = []
    self.options["destination"] = []
    self.options["application"] = []
    self.options["service"] = []
    self.options["action"] = "allow"

    if term.source_address:
      for addr in term.source_address:
        self.options["source"].append(self.extract_ip(str(addr)))

    if term.destination_address:
      for addr in term.destination_address:
        self.options["destination"].append(self.extract_ip(str(addr)))

    if term.action:
      self.options["action"] = term.action[0]

    if term.destination_port:
      ports = []
      for tup in term.destination_port:
        ports.append(tup[0])
      ports = tuple(ports)

      # check to see if this service already exists
      for p in term.protocol:
        if (ports, p) in Service.service_map:
          self.options["service"].append(Service.service_map[(ports, p)]["name"])
        else:
          # create service
          new_service = Service(ports, term.name, p)
          self.options["service"].append(Service.service_map[(ports, p)]["name"])
    if term.protocol:
      if term.protocol[0] == "icmp":
        self.options["application"].append("ping")

    self.rules["-".join(self.options["from_zone"]) + "_2_" + "-".join(self.options["to_zone"]) + "-" + term.name] = self.options



class PaloAltoFW(aclgenerator.ACLGenerator):
  """PaloAltoFW rendering class.

     This class takes a policy object and renders the output into a syntax
     which is understood by Palo Alto firewalls.

     Args:
       pol: policy.Policy object
  """

  _PLATFORM = 'paloalto'
  _SUFFIX = '.xml'
  _SUPPORTED_AF = set(('inet',))
  _OPTIONAL_SUPPORTED_KEYWORDS = set(['expiration',
                                      'logging',
                                      'owner',
                                      'routing_instance',    # safe to skip
                                      'timeout',
                                     ])
  INDENT = '  '

  def _TranslatePolicy(self, pol, exp_info):
    """Transform a policy object into a PaloAltoFW object.

    Args:
      pol: policy.Policy object
      exp_info: print a info message when a term is set to expire
                in that many weeks

    Raises:
      UnsupportedFilterError: An unsupported filter was specified
      UnsupportedHeader: A header option exists that is not understood/usable
      PaloAltoFWDuplicateTermError: Two terms were found with same name in same filter
    """
    self.pafw_policies = []
    self.addressbook = collections.OrderedDict()
    self.applications = []
    self.ports = []
    self.from_zone = ''
    self.to_zone = ''
    self.policy_name = ''

    current_date = datetime.date.today()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)
    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue

      filter_options = header.FilterOptions(self._PLATFORM)

      if (len(filter_options) < 4 or filter_options[0] != 'from-zone' or
          filter_options[2] != 'to-zone'):
        raise UnsupportedFilterError(
            'Palo Alto Firewall filter arguments must specify from-zone and to-zone.')

      self.from_zone = filter_options[1]
      self.to_zone = filter_options[3]

      if len(filter_options) > 4:
        filter_type = filter_options[4]
      else:
        filter_type = 'inet'

      if filter_type not in self._SUPPORTED_AF:
        raise UnsupportedHeader(
            'Palo Alto Firewall Generator currently does not support %s as a header option' %
            (filter_type))

      term_dup_check = set()
      new_terms = []
      for term in terms:
        term.name = self.FixTermLength(term.name)
        if term.name in term_dup_check:
          raise PaloAltoFWDuplicateTermError('You have a duplicate term: %s'
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

        new_term = Term(term, filter_type, filter_options)
        new_terms.append(new_term)
        tmp_icmptype = new_term.NormalizeIcmpTypes(
            term.icmp_type, term.protocol, filter_type)
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
      self.pafw_policies.append((header, new_terms, filter_options))
      # create Palo Alto Firewall Rule object
      for term in new_terms:
        rule = Rule(self.from_zone, self.to_zone, term)

  def _BuildAddressBook(self, zone, address):
    """Create the address book configuration entries.

    Args:
      zone: the zone these objects will reside in
      address: a naming library address object
    """
    if zone not in self.addressbook:
      self.addressbook[zone] = collections.OrderedDict()
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
    """Render the output of the PaloAltoFirewall policy into config."""
    initial = []
    # INITAL CONFIG
    initial.append('<?xml version="1.0"?>"')
    initial.append('<config version="7.0.0" urldb="paloaltonetworks">')
    initial.append(self.INDENT * 1 + '<devices>')
    initial.append(self.INDENT * 2 + '<entry name="localhost.localdomain">')
    initial.append(self.INDENT * 3 + '<vsys>')
    initial.append(self.INDENT * 4 + '<entry name="vsys1">')
    initial.append(self.INDENT * 5 + '<application/>')
    initial.append(self.INDENT * 5 + '<application-group/>')

    # SERVICES
    service = []
    service.append(self.INDENT * 5 + "<!-- Services -->")

    service.append(self.INDENT * 5 + "<service>")
    for k,v in Service.service_map.items():
      service.append(self.INDENT * 6 + '<entry name="' + v["name"] + '">')
      service.append(self.INDENT * 7 + "<protocol>")
      service.append(self.INDENT * 8 + "<" + k[1] + ">")
      tup = str(k[0])[1:-1]
      if tup[-1] == ",":
        tup = tup[:-1]
      service.append(self.INDENT * 9 + "<port>" + tup + "</port>")
      service.append(self.INDENT * 8 + "</" + k[1] + ">")
      service.append(self.INDENT * 7 + "</protocol>")
      service.append(self.INDENT * 6 + "</entry>")
    service.append(self.INDENT * 5 + "</service>")

    # RULES
    rules = []
    rules.append(self.INDENT * 5 + "<!-- Rules -->")

    rules.append(self.INDENT * 5 + "<rulebase>")
    rules.append(self.INDENT * 6 + "<security>")
    rules.append(self.INDENT * 7 + "<rules>")

    for name, options in Rule.rules.items():
      rules.append(self.INDENT * 8 + '<entry name="' + name + '">')

      rules.append(self.INDENT * 9 + "<to>")
      for tz in options["to_zone"]:
        rules.append(self.INDENT * 10 + "<member>" + tz + "</member>")
      rules.append(self.INDENT * 9 + "</to>")

      rules.append(self.INDENT * 9 + "<from>")
      for fz in options["from_zone"]:
        rules.append(self.INDENT * 10 + "<member>" + fz + "</member>")
      rules.append(self.INDENT * 9 + "</from>")

      rules.append(self.INDENT * 9 + "<source>")
      if options["source"] == []:
        rules.append(self.INDENT * 10 + "<member>any</member>")
      else:
        for s in options["source"]:
          rules.append(self.INDENT * 10 + "<member>" + s + "</member>")
      rules.append(self.INDENT * 9 + "</source>")

      rules.append(self.INDENT * 9 + "<destination>")
      if options["destination"] == []:
        rules.append(self.INDENT * 10 + "<member>any</member>")
      else:
        for d in options["destination"]:
          rules.append(self.INDENT * 10 + "<member>" + d + "</member>")
      rules.append(self.INDENT * 9 + "</destination>")

      rules.append(self.INDENT * 9 + "<service>")
      if options["service"] == []:
        rules.append(self.INDENT * 10 + "<member>any</member>")
      else:
        for s in options["service"]:
          rules.append(self.INDENT * 10 + "<member>" + s + "</member>")
      rules.append(self.INDENT * 9 + "</service>")

      rules.append(self.INDENT * 9 + "<action>")
      rules.append(self.INDENT * 10 + "<member>" + options["action"] + "</member>")
      rules.append(self.INDENT * 9 + "</action>")

      rules.append(self.INDENT * 9 + "<application>")
      if options["application"] == []:
        rules.append(self.INDENT * 10 + "<member>any</member>")
      else:
        for a in options["application"]:
          rules.append(self.INDENT * 10 + "<member>" + a + "</member>")
      rules.append(self.INDENT * 9 + "</application>")

      rules.append(self.INDENT * 8 + "</entry>")

    rules.append(self.INDENT * 7 + "</rules>")
    rules.append(self.INDENT * 6 + "</security>")

    rules.append(self.INDENT * 5 + "</rulebase>")

    end = []
    end.append(self.INDENT * 4 + "</entry>")
    end.append(self.INDENT * 3 + "</vsys>")
    end.append(self.INDENT * 2 + "</entry>")
    end.append(self.INDENT * 1 + "</devices>")
    end.append("</config>")

    return '\n'.join(initial) + '\n\n' +'\n'.join(service) + "\n\n" + '\n'.join(rules) + '\n' + '\n'.join(end)
