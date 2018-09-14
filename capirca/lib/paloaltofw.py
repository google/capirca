# Copyright 2017 Google Inc. All Rights Reserved.
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
"""Palo Alto Firewall generator."""

import collections
import datetime
import logging

from capirca.lib import aclgenerator
from capirca.lib import nacaddr


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


class PaloAltoFWTooLongName(Error):
  pass


class Term(aclgenerator.Term):
  """Representation of an individual term.

  This is mostly useful for the __str__() method.

  Args:
    obj: a policy.Term object
    term_type: type of filter to generate, e.g. inet or inet6
    filter_options: list of remaining target options (zones)
  """

  ACTIONS = {
      "accept": "allow",
      "deny": "deny",
      "reject": "reject",
      "count": "count",
      "log": "log"
  }

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
    # Nothing here for now

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
        return "%d" % el[0]
      else:
        return "%d-%d" % (el[0], el[1])

    if len(group) > 1:
      rval = "[ " + " ".join([_FormattedGroup(x) for x in group]) + " ];"
    else:
      rval = _FormattedGroup(group[0]) + ";"
    return rval


class Service(object):

  service_map = {}

  def __init__(self, ports, service_name,
               protocol):  # ports is a tuple of ports
    if (ports, protocol) in self.service_map:
      raise PaloAltoFWDuplicateServiceError(
          ("You have a duplicate service. "
           "A service already exists on port(s): %s")
          % str(ports))

    final_service_name = "service-" + service_name + "-" + protocol

    for unused_k, v in Service.service_map.items():
      if v["name"] == final_service_name:
        raise PaloAltoFWDuplicateServiceError(
            "You have a duplicate service. A service named %s already exists." %
            str(final_service_name))

    if len(final_service_name.decode("utf-8")) > 63:
      raise PaloAltoFWTooLongName("Service name must be 63 characters max: %s" %
                                  str(final_service_name))
    self.service_map[(ports, protocol)] = {"name": final_service_name}


class Rule(object):
  """Extend the Term() class for PaloAlto Firewall Rules."""

  rules = {}

  def __init__(self, from_zone, to_zone, terms):
    # Palo Alto Firewall rule keys
    self.options = {}
    self.options["from_zone"] = [from_zone]
    self.options["to_zone"] = [to_zone]
    if not from_zone or not to_zone:
      raise PaloAltoFWOptionError("Source or destination zone is empty.")

    self.ModifyOptions(terms)

  def ModifyOptions(self, terms):
    """Massage firewall rules into Palo Alto rules format."""
    term = terms.term
    self.options["source"] = []
    self.options["destination"] = []
    self.options["application"] = []
    self.options["service"] = []
    self.options["action"] = "allow"

    # SOURCE-ADDRESS
    if term.source_address:
      saddr_check = set()
      for saddr in term.source_address:
        saddr_check.add(saddr.parent_token)
      saddr_check = sorted(saddr_check)
      for addr in saddr_check:
        self.options["source"].append(str(addr))
    else:
      self.options["source"].append("any")

    # DESTINATION-ADDRESS
    if term.destination_address:
      daddr_check = set()
      for daddr in term.destination_address:
        daddr_check.add(daddr.parent_token)
      daddr_check = sorted(daddr_check)
      for addr in daddr_check:
        self.options["destination"].append(str(addr))
    else:
      self.options["destination"].append("any")

    if term.action:
      self.options["action"] = term.action[0]

    if term.pan_application:
      for pan_app in term.pan_application:
        self.options["application"].append(pan_app)

    if term.destination_port:
      ports = []
      for tup in term.destination_port:
        if len(tup) > 1 and tup[0] != tup[1]:
          ports.append(str(tup[0]) + "-" + str(tup[1]))
        else:
          ports.append(str(tup[0]))
      ports = tuple(ports)

      # check to see if this service already exists
      for p in term.protocol:
        if (ports, p) in Service.service_map:
          self.options["service"].append(Service.service_map[(ports, p)][
              "name"])
        else:
          # create service
          unused_new_service = Service(ports, term.name, p)
          self.options["service"].append(Service.service_map[(ports, p)][
              "name"])
    if term.protocol:
      if term.protocol[0] == "icmp":
        self.options["application"].append("ping")

    rule_name = term.name
    if rule_name in self.rules:
      raise PaloAltoFWDuplicateTermError(
          "You have a duplicate term. A term named %s already exists."
          % str(rule_name))

    self.rules[rule_name] = self.options


class PaloAltoFW(aclgenerator.ACLGenerator):
  """PaloAltoFW rendering class."""

  _PLATFORM = "paloalto"
  SUFFIX = ".xml"
  _SUPPORTED_AF = set(("inet", "inet6", "mixed"))
  _AF_MAP = {"inet": (4,), "inet6": (6,), "mixed": (4, 6)}
  _TERM_MAX_LENGTH = 31

  INDENT = "  "

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    supported_tokens, supported_sub_tokens = super(PaloAltoFW,
                                                   self)._BuildTokens()

    supported_tokens = {
        "action",
        "comment",
        "destination_address",
        "destination_port",
        "expiration",
        "icmp_type",
        "logging",
        "name",
        "owner",
        "platform",
        "protocol",
        "source_address",
        "source_port",
        "timeout",
        "pan_application",
        "translated"
    }

    supported_sub_tokens.update({
        "action": {"accept", "deny", "reject", "count", "log"},
    })
    del supported_sub_tokens["option"]
    return supported_tokens, supported_sub_tokens

  def _TranslatePolicy(self, pol, exp_info):
    """Transform a policy object into a PaloAltoFW object.

    Args:
      pol: policy.Policy object
      exp_info: print a info message when a term is set to expire
                in that many weeks

    Raises:
      UnsupportedFilterError: An unsupported filter was specified
      UnsupportedHeader: A header option exists that is not
      understood/usable
      PaloAltoFWDuplicateTermError: Two terms were found with same name in
      same filter
    """
    self.pafw_policies = []
    self.addressbook = collections.OrderedDict()
    self.applications = []
    self.pan_applications = []
    self.ports = []
    self.from_zone = ""
    self.to_zone = ""
    self.policy_name = ""

    current_date = datetime.date.today()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)
    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue

      filter_options = header.FilterOptions(self._PLATFORM)

      if (len(filter_options) < 4 or filter_options[0] != "from-zone" or
          filter_options[2] != "to-zone"):
        raise UnsupportedFilterError(
            "Palo Alto Firewall filter arguments must specify from-zone and "
            "to-zone."
        )

      self.from_zone = filter_options[1]
      self.to_zone = filter_options[3]

      if len(filter_options) > 4:
        filter_type = filter_options[4]
      else:
        filter_type = "inet"

      if filter_type not in self._SUPPORTED_AF:
        raise UnsupportedHeader(
            "Palo Alto Firewall Generator currently does not support"
            " %s as a header option" % (filter_type))

      term_dup_check = set()
      new_terms = []
      for term in terms:
        term.name = self.FixTermLength(term.name)
        if term.name in term_dup_check:
          raise PaloAltoFWDuplicateTermError("You have a duplicate term: %s" %
                                             term.name)
        term_dup_check.add(term.name)

        if term.expiration:
          if term.expiration <= exp_info_date:
            logging.info("INFO: Term %s in policy %s>%s expires "
                         "in less than two weeks.", term.name, self.from_zone,
                         self.to_zone)
          if term.expiration <= current_date:
            logging.warn("WARNING: Term %s in policy %s>%s is expired and "
                         "will not be rendered.",
                         term.name, self.from_zone, self.to_zone)
            continue

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
        tmp_icmptype = new_term.NormalizeIcmpTypes(term.icmp_type,
                                                   term.protocol, filter_type)
        # NormalizeIcmpTypes returns [''] for empty, convert to [] for
        # eval
        normalized_icmptype = tmp_icmptype if tmp_icmptype != [""] else []
        # rewrites the protocol icmpv6 to icmp6
        if "icmpv6" in term.protocol:
          protocol = list(term.protocol)
          protocol[protocol.index("icmpv6")] = "icmp6"
        else:
          protocol = term.protocol
        self.applications.append({
            "sport": self._BuildPort(term.source_port),
            "dport": self._BuildPort(term.destination_port),
            "name": term.name,
            "protocol": protocol,
            "icmp-type": normalized_icmptype,
            "timeout": term.timeout
        })
      self.pafw_policies.append((header, new_terms, filter_options))
      # create Palo Alto Firewall Rule object
      for term in new_terms:
        unused_rule = Rule(self.from_zone, self.to_zone, term)

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
    name = "%s_%s" % (name, str(counter))
    self.addressbook[zone][address.parent_token].append((address, name))

  def _SortAddressBookNumCheck(self, item):
    """Used to give a natural order to the list of acl entries.

    Args:
      item: string of the address book entry name

    Returns:
      returns the characters and number
    """

    item_list = item.split("_")
    num = item_list.pop(-1)
    if isinstance(item_list[-1], int):
      set_number = item_list.pop(-1)
      num = int(set_number) * 1000 + int(num)
    alpha = "_".join(item_list)
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
        port_list.append("%s-%s" % (str(i[0]), str(i[1])))
    return port_list

  def __str__(self):
    """Render the output of the PaloAltoFirewall policy into config."""
    initial = []
    # INITAL CONFIG
    initial.append('<?xml version="1.0"?>')
    initial.append('<config version="7.0.0" urldb="paloaltonetworks">')
    initial.append(self.INDENT * 1 + "<devices>")
    initial.append(self.INDENT * 2 + '<entry name="localhost.localdomain">')
    initial.append(self.INDENT * 3 + "<vsys>")
    initial.append(self.INDENT * 4 + '<entry name="vsys1">')
    initial.append(self.INDENT * 5 + "<application/>")
    initial.append(self.INDENT * 5 + "<application-group/>")

    # ADDRESS
    address_entries = []
    address_entries.append(self.INDENT * 5 + "<!-- Addresses -->")
    address_entries.append(self.INDENT * 5 + "<address>")

    address_book_names_dict = {}
    address_book_groups_dict = {}
    for zone in self.addressbook:
      # building individual addresses dictionary
      groups = sorted(self.addressbook[zone])
      for group in groups:
        for address, name in self.addressbook[zone][group]:
          if name in address_book_names_dict:
            if address_book_names_dict[name].Contains(address):
              continue
          address_book_names_dict[name] = address

        # building individual address-group dictionary
        for group in groups:
          group_names = []
          for address, name in self.addressbook[zone][group]:
            group_names.append(name)
          address_book_groups_dict[group] = group_names

      # sort address books and address sets
      address_book_groups_dict = collections.OrderedDict(
          sorted(address_book_groups_dict.items()))
    address_book_keys = sorted(
        list(address_book_names_dict.keys()), key=self._SortAddressBookNumCheck)

    for name in address_book_keys:
      address_entries.append(self.INDENT * 6 + '<entry name="' + name + '">')
      address_entries.append(self.INDENT * 7 + "<description>" + name +
                             "</description>")
      address_entries.append(self.INDENT * 7 + "<ip-netmask>" + str(
          address_book_names_dict[name]) + "</ip-netmask>")
      address_entries.append(self.INDENT * 6 + "</entry>")

    address_entries.append(self.INDENT * 5 + "</address>")

    address_group_entries = []
    address_group_entries.append(self.INDENT * 5 + "<!-- Address groups-->")
    address_group_entries.append(self.INDENT * 5 + "<address-group>")

    for group, address_list in address_book_groups_dict.items():
      address_group_entries.append(self.INDENT * 6 + '<entry name="' + group +
                                   '">')
      address_group_entries.append(self.INDENT * 7 + "<static>")
      for name in address_list:
        address_group_entries.append(self.INDENT * 8 + "<member>" + name +
                                     "</member>")
      address_group_entries.append(self.INDENT * 7 + "</static>")
      address_group_entries.append(self.INDENT * 7 + "</entry>")
    address_group_entries.append(self.INDENT * 5 + "</address-group>")

    # SERVICES
    service = []
    service.append(self.INDENT * 5 + "<!-- Services -->")

    service.append(self.INDENT * 5 + "<service>")
    for k, v in Service.service_map.items():
      service.append(self.INDENT * 6 + '<entry name="' + v["name"] + '">')
      service.append(self.INDENT * 7 + "<protocol>")
      service.append(self.INDENT * 8 + "<" + k[1] + ">")
      tup = str(k[0])[1:-1]
      if tup[-1] == ",":
        tup = tup[:-1]
      service.append(self.INDENT * 9 + "<port>" + tup.replace("'", "") +
                     "</port>")
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
      if not options["source"]:
        rules.append(self.INDENT * 10 + "<member>any</member>")
      else:
        for s in options["source"]:
          rules.append(self.INDENT * 10 + "<member>" + s + "</member>")
      rules.append(self.INDENT * 9 + "</source>")

      rules.append(self.INDENT * 9 + "<destination>")
      if not options["destination"]:
        rules.append(self.INDENT * 10 + "<member>any</member>")
      else:
        for d in options["destination"]:
          rules.append(self.INDENT * 10 + "<member>" + d + "</member>")
      rules.append(self.INDENT * 9 + "</destination>")

      rules.append(self.INDENT * 9 + "<service>")
      if not options["service"] and not options["application"]:
        rules.append(self.INDENT * 10 + "<member>any</member>")
      elif not options["service"] and options["application"]:
        rules.append(self.INDENT * 10 + "<member>application-default</member>")
      else:
        for s in options["service"]:
          rules.append(self.INDENT * 10 + "<member>" + s + "</member>")
      rules.append(self.INDENT * 9 + "</service>")

      rules.append(self.INDENT * 9 + "<action>" + Term.ACTIONS.get(
          str(options["action"])) + "</action>")

      if fz == tz == "any":
        rules.append(self.INDENT * 9 + "<rule-type>interzone</rule-type>")

      rules.append(self.INDENT * 9 + "<application>")
      if not options["application"]:
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
    end.append("</config>\n")

    return ("\n".join(initial) + "\n\n" + "\n".join(service) + "\n\n" +
            "\n".join(rules) + "\n".join(address_group_entries) +
            "\n".join(address_entries) + "\n" + "\n".join(end))
