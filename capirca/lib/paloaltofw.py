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
import copy
import datetime
import logging
import re
from xml.dom import minidom
import xml.etree.ElementTree as etree
from capirca.lib import aclgenerator
from capirca.lib import nacaddr
from capirca.lib import policy


class Error(Exception):
  """generic error class."""


class UnsupportedFilterError(Error):
  pass


class UnsupportedHeaderError(Error):
  pass


class PaloAltoFWDuplicateTermError(Error):
  pass


class PaloAltoFWUnsupportedProtocolError(Error):
  pass


class PaloAltoFWVerbatimError(Error):
  pass


class PaloAltoFWOptionError(Error):
  pass


class PaloAltoFWDuplicateServiceError(Error):
  pass


class PaloAltoFWNameTooLongError(Error):
  pass


class PaloAltoFWBadIcmpTypeError(Error):
  pass


class ServiceMap:
  """Manages service names across a single policy instance."""

  def __init__(self):
    self.entries = {}

  def get_service_name(self, term_name, src_ports, ports, protocol, prefix=None):
    """Returns service name based on the provided ports and protocol."""
    if (src_ports, ports, protocol) in self.entries:
      return self.entries[(src_ports, ports, protocol)]["name"]

    if prefix is None:
      prefix = "service-"
    service_name = "%s%s-%s" % (prefix, term_name, protocol)

    if len(service_name) > 63:
      raise PaloAltoFWNameTooLongError(
          "Service name must be 63 characters max: %s" % service_name)

    for _, service in self.entries.items():
      if service["name"] == service_name:
        raise PaloAltoFWDuplicateServiceError(
            "You have a duplicate service. A service named %s already exists." %
            service_name)

    self.entries[(src_ports, ports, protocol)] = {"name": service_name}
    return service_name


class Rule:
  """Extend the Term() class for PaloAlto Firewall Rules."""

  def __init__(self, from_zone, to_zone, term, service_map):
    # Palo Alto Firewall rule keys
    MAX_ZONE_LENGTH = 31

    if not from_zone or not to_zone:
      raise PaloAltoFWOptionError("Source or destination zone is empty.")
    if len(from_zone) > MAX_ZONE_LENGTH:
      x = "Source zone must be %d characters max: %s" % (MAX_ZONE_LENGTH,
                                                         from_zone)
      raise PaloAltoFWNameTooLongError(x)
    if len(to_zone) > MAX_ZONE_LENGTH:
      x = "Destination zone must be %d characters max: %s" % (MAX_ZONE_LENGTH,
                                                              to_zone)
      raise PaloAltoFWNameTooLongError(x)

    self.options = []

    while term is not None:
      x, term = self.TermToOptions(from_zone, to_zone,
                                   term, service_map)
      self.options.append(x)

  @staticmethod
  def TermToOptions(from_zone, to_zone, term, service_map):
    """Convert term to Palo Alto security rule options."""
    options = {}
    options["from_zone"] = [from_zone]
    options["to_zone"] = [to_zone]
    options["description"] = []
    options["source"] = []
    options["destination"] = []
    options["application"] = []
    options["service"] = []
    options["logging"] = []

    ACTIONS = {
      "accept": "allow",
      "deny": "deny",
      "reject": "reset-client",
      "reject-with-tcp-rst": "reset-client",
    }

    new_term = None

    def pan_ports(ports):
      x = []
      for tup in ports:
        if len(tup) > 1 and tup[0] != tup[1]:
          x.append(str(tup[0]) + "-" + str(tup[1]))
        else:
          x.append(str(tup[0]))

      return tuple(x)

    # COMMENT
    if term.comment:
      options["description"] = term.comment

    # LOGGING
    if term.logging:
      for item in term.logging:
        if item.value in ["disable"]:
          options["logging"] = ["disable"]
          break
        elif item.value in ["log-both"]:
          options["logging"].append("log-start")
          options["logging"].append("log-end")
        elif item.value in ["True", "true", "syslog", "local"]:
          options["logging"].append("log-end")

    # SOURCE-ADDRESS
    if term.source_address:
      saddr_check = set()
      for saddr in term.source_address:
        saddr_check.add(saddr.parent_token)
      saddr_check = sorted(saddr_check)
      for addr in saddr_check:
        options["source"].append(str(addr))
    # missing source handled during XML document generation

    # DESTINATION-ADDRESS
    if term.destination_address:
      daddr_check = set()
      for daddr in term.destination_address:
        daddr_check.add(daddr.parent_token)
      daddr_check = sorted(daddr_check)
      for addr in daddr_check:
        options["destination"].append(str(addr))
    # missing destination handled during XML document generation

    # ACTION
    if term.action:
      options["action"] = ACTIONS[term.action[0]]

    if term.option:
      options["option"] = term.option

    if term.pan_application:
      for pan_app in term.pan_application:
        options["application"].append(pan_app)

    if term.source_port or term.destination_port:
      src_ports = pan_ports(term.source_port)
      if term.destination_port:
        ports = pan_ports(term.destination_port)
      else:
        ports = pan_ports([("0", "65535")])

      # check to see if this service already exists
      for p in term.protocol:
        service_name = service_map.get_service_name(term.name,
                                                    src_ports, ports, p)
        if service_name not in options["service"]:
          options["service"].append(service_name)

    elif "tcp" in term.protocol or "udp" in term.protocol:
      services = {"tcp", "udp"} & set(term.protocol)
      others = set(term.protocol) - services
      if others:
        logging.info(
          "INFO: Term %s in policy %s>%s contains port-less %s "
          "with non-port protocol(s). Moving %s to a new term.",
          term.name, from_zone, to_zone,
          ', '.join(list(services)), ', '.join(list(others)))
        new_term = copy.deepcopy(term)
        new_term.protocol = list(others)
        term.protocol = list(services)
        options["application"] = []
      for p in term.protocol:
        ports = pan_ports([("0", "65535")])
        # use prefix "" to avoid service name clash with term named "any"
        service_name = service_map.get_service_name("any", (), ports, p, "")
        if service_name not in options["service"]:
          options["service"].append(service_name)

    if term.protocol:
      # Add certain protocol names as application in the application list
      # if missing.
      for proto_name in term.protocol:
        if (proto_name in ["igmp", "sctp", "gre"] and
            proto_name not in options["application"]):
          options["application"].append(proto_name)
        elif proto_name in ("ah", "esp"):
          ipsec_app_proto = "ipsec-%s" % proto_name
          if ipsec_app_proto not in options["application"]:
            options["application"].append(ipsec_app_proto)

    return options, new_term


class PaloAltoFW(aclgenerator.ACLGenerator):
  """PaloAltoFW rendering class."""

  _PLATFORM = "paloalto"
  SUFFIX = ".xml"
  _SUPPORTED_AF = set(("inet", "inet6", "mixed"))
  _AF_MAP = {"inet": (4,), "inet6": (6,), "mixed": (4, 6)}
  _TERM_MAX_LENGTH = 63
  _APPLICATION_NAME_MAX_LENGTH = 31
  _TERM_PREFIX_LENGTH = 24
  _SUPPORTED_PROTO_NAMES = [
      "tcp",
      "udp",
      "icmp",
      "icmpv6",
      "sctp",
      "igmp",
      "gre",
      "ah",
      "esp",
  ]
  _MAX_RULE_DESCRIPTION_LENGTH = 1024
  _MAX_TAG_COMMENTS_LENGTH = 1023
  _TAG_NAME_FORMAT = "{from_zone}_{to_zone}_policy-comment-{num}"
  _MAX_RULE_SRC_DST_MEMBERS = 65535

  _ABBREVIATION_TABLE = [
      # Service abbreviations first.
      ("experiment", "EXP"),
      ("wifi-radius", "W-R"),
      ("customer", "CUST"),
      ("server", "SRV"),
      # Next, common routing terms
      ("global", "GBL"),
      ("google", "GOOG"),
      ("service", "SVC"),
      ("router", "RTR"),
      ("internal", "INT"),
      ("external", "EXT"),
      ("transit", "TRNS"),
      ("management", "MGMT"),
      # State info
      ("established", "EST"),
      ("unreachable", "UNR"),
      ("fragment", "FRAG"),
      ("accept", "ACC"),
      ("discard", "DISC"),
      ("reject", "REJ"),
      ("replies", "RPLS"),
      ("reply", "RPL"),
      ("request", "REQ"),
      # ICMP types specific
      ("inverse", "INV"),
      ("neighbor", "NBR"),
      ("discovery", "DSCVR"),
      ("advertisement", "ADV"),
      ("solicitation", "SOL"),
      ("multicast", "MCAST"),
      ("certification", "CERT"),
      ("listener", "LSNR"),
      ("address", "ADDR"),
  ]

  INDENT = "  "

  def __init__(self, pol, exp_info):
    self.pafw_policies = []
    self.addressbook = collections.OrderedDict()
    self.applications = []
    self.application_refs = {}
    self.application_groups = []
    self.pan_applications = []
    self.ports = []
    self.from_zone = ""
    self.to_zone = ""
    self.policy_name = ""
    self.config = None
    self.service_map = ServiceMap()
    super().__init__(pol, exp_info)

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    supported_tokens, supported_sub_tokens = super()._BuildTokens()

    supported_tokens = {
        "action",
        "comment",
        "destination_address",
        "destination_address_exclude",
        "destination_port",
        "expiration",
        "icmp_type",
        "logging",
        "name",
        "option",
        "owner",
        "platform",
        "platform_exclude",
        "protocol",
        "source_address",
        "source_address_exclude",
        "source_port",
        "stateless_reply",
        "timeout",
        "pan_application",
        "translated",
    }

    supported_sub_tokens.update({
        "action": {"accept", "deny", "reject", "reject-with-tcp-rst"},
        "option": {"established", "tcp-established"},
    })
    return supported_tokens, supported_sub_tokens

  def _TranslatePolicy(self, pol, exp_info):
    """Transform a policy object into a PaloAltoFW object.

    Args:
      pol: policy.Policy object
      exp_info: print a info message when a term is set to expire in that many
        weeks

    Raises:
      UnsupportedFilterError: An unsupported filter was specified
      UnsupportedHeaderError: A header option exists that is not
      understood/usable
      PaloAltoFWDuplicateTermError: Two terms were found with same name in
      same filter
      PaloAltoFWBadIcmpTypeError: The referenced ICMP type is not supported
      by the policy term.
      PaloAltoFWUnsupportedProtocolError: The term contains unsupporter protocol
      name.
    """
    current_date = datetime.date.today()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)
    first_addr_obj = None

    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue

      # The filter_options is a list of options from header, e.g.
      # ['from-zone', 'internal', 'to-zone', 'external']
      filter_options = header.FilterOptions(self._PLATFORM)

      if (len(filter_options) < 4 or filter_options[0] != "from-zone" or
          filter_options[2] != "to-zone"):
        raise UnsupportedFilterError(
            "Palo Alto Firewall filter arguments must specify from-zone and "
            "to-zone.")

      self.from_zone = filter_options[1]
      self.to_zone = filter_options[3]

      # The filter_type values are either inet, inet6, or mixed. Later, the
      # code analyzes source and destination IP addresses and determines whether
      # it is an appropriate type for the filter_type value.
      if len(filter_options) > 4:
        filter_type = filter_options[4]
      else:
        filter_type = "inet"

      if filter_type not in self._SUPPORTED_AF:
        raise UnsupportedHeaderError(
            'Palo Alto Firewall Generator invalid address family option: "%s"'
            '; expect {%s}' % (filter_type, '|'.join(self._SUPPORTED_AF)))

      valid_addr_obj = ["addr-obj", "no-addr-obj"]
      if len(filter_options) > 5 and filter_options[5] not in valid_addr_obj:
        raise UnsupportedHeaderError(
            'Palo Alto Firewall Generator invalid address objects option: "%s"'
            '; expect {%s}' % (filter_options[5], '|'.join(valid_addr_obj)))
      no_addr_obj = True if (len(filter_options) > 5 and
                             filter_options[5] == "no-addr-obj") else False

      unique_term_prefixes = True if (
          len(filter_options) > 6 and
          filter_options[6] == "unique-term-prefixes") else False

      if first_addr_obj is None:
        first_addr_obj = no_addr_obj
      if first_addr_obj != no_addr_obj:
        raise UnsupportedHeaderError(
            "Cannot mix addr-obj and no-addr-obj header option in "
            "a single policy file")

      term_dup_check = set()
      new_terms = []

      for term in terms:
        if term.stateless_reply:
          logging.warning(
              "WARNING: Term %s in policy %s>%s is a stateless reply "
              "term and will not be rendered.", term.name, self.from_zone,
              self.to_zone)
          continue
        if "established" in term.option:
          logging.warning(
              "WARNING: Term %s in policy %s>%s is a established "
              "term and will not be rendered.", term.name, self.from_zone,
              self.to_zone)
          continue
        if "tcp-established" in term.option:
          logging.warning(
              "WARNING: Term %s in policy %s>%s is a tcp-established "
              "term and will not be rendered.", term.name, self.from_zone,
              self.to_zone)
          continue

        # Verify platform specific terms. Skip whole term if platform does not
        # match.
        if term.platform:
          if self._PLATFORM not in term.platform:
            continue
        if term.platform_exclude:
          if self._PLATFORM in term.platform_exclude:
            continue

        if unique_term_prefixes:
          # Prefix hash of from_zone and to_zone to the term name to get mostly
          # unique names across different policies.
          # This is not crytopgraphically guaranteed.
          # This modified term name should not exceed _TERM_MAX_LENGTH.
          term.name = self.HexDigest(self.from_zone + self.to_zone,
                                     self._TERM_PREFIX_LENGTH) + "-" + term.name
        term.name = self.FixTermLength(term.name)
        if term.name in term_dup_check:
          raise PaloAltoFWDuplicateTermError("You have a duplicate term: %s" %
                                             term.name)
        term_dup_check.add(term.name)

        services = {"tcp", "udp"} & set(term.protocol)
        others = set(term.protocol) - services
        if others and term.pan_application:
          raise UnsupportedFilterError(
            "Term %s contains non tcp, udp protocols with pan-application: %s: %s"
            "\npan-application can only be used with protocols tcp, udp" %
            (term.name, ', '.join(term.pan_application), ', '.join(term.protocol)))

        if term.expiration:
          if term.expiration <= exp_info_date:
            logging.info(
                "INFO: Term %s in policy %s>%s expires "
                "in less than two weeks.", term.name, self.from_zone,
                self.to_zone)
          if term.expiration <= current_date:
            logging.warning(
                "WARNING: Term %s in policy %s>%s is expired and "
                "will not be rendered.", term.name, self.from_zone,
                self.to_zone)
            continue

        for i in term.source_address_exclude:
          term.source_address = nacaddr.RemoveAddressFromList(
              term.source_address, i)
        for i in term.destination_address_exclude:
          term.destination_address = nacaddr.RemoveAddressFromList(
              term.destination_address, i)

        # Count the number of occurencies of a particular version of the
        # address family, i.e. v4/v6 in source and destination IP addresses.
        afc = {
            4: {
                "src": 0,
                "dst": 0
            },
            6: {
                "src": 0,
                "dst": 0
            },
        }
        # Determine the address families in the source and destination
        # addresses references in the term. Next, determine IPv4 and IPv6
        # traffic flow patterns.
        exclude_address_family = []
        flows = []
        src_any = False
        dst_any = False
        if not term.source_address:
          src_any = True
        if not term.destination_address:
          dst_any = True
        for addr in term.source_address:
          afc[addr.version]["src"] += 1
        for addr in term.destination_address:
          afc[addr.version]["dst"] += 1
        for v in [4, 6]:
          if src_any and dst_any:
            flows.append("ip%d-ip%d" % (v, v))
            continue
          if (afc[v]["src"] == 0 and not src_any) and (afc[v]["dst"] == 0 and
                                                       not dst_any):
            continue
          if (afc[v]["src"] > 0 or src_any) and (afc[v]["dst"] > 0 or dst_any):
            flows.append("ip%d-ip%d" % (v, v))
            continue
          if (afc[v]["src"] > 0 or src_any) and afc[v]["dst"] == 0:
            flows.append("ip%d-src-only" % v)
            flows.append("ip%d-only" % v)
            continue
          if afc[v]["src"] == 0 and (afc[v]["dst"] > 0 or dst_any):
            flows.append("ip%d-dst-only" % v)
            flows.append("ip%d-only" % v)

        if filter_type == "inet":
          if "icmpv6" in term.protocol:
            logging.warning(
                "WARNING: Term %s in policy %s>%s references ICMPv6 protocol, "
                "term will not be rendered.", term.name, self.from_zone,
                self.to_zone)
            continue
          if "ip4-ip4" not in flows:
            logging.warning(
                "WARNING: Term %s in policy %s>%s has one or more invalid "
                "src-dest combinations %s, term will not be rendered.",
                term.name, self.from_zone, self.to_zone, flows)
            continue
          # exclude IPv6 addresses
          exclude_address_family.append(6)
        elif filter_type == "inet6":
          if "icmp" in term.protocol:
            logging.warning(
                "WARNING: Term %s in policy %s>%s references ICMP protocol, "
                "term and will not be rendered.", term.name, self.from_zone,
                self.to_zone)
            continue
          if "ip6-ip6" not in flows:
            logging.warning(
                "WARNING: Term %s in policy %s>%s has one or more invalid "
                "src-dest combinations %s, term will not be rendered.",
                term.name, self.from_zone, self.to_zone, flows)
            continue
          exclude_address_family.append(4)
        elif filter_type == "mixed":
          if "ip4-ip4" in flows and "ip6-ip6" not in flows:
            exclude_address_family.append(6)
            pass
          elif "ip6-ip6" in flows and "ip4-ip4" not in flows:
            exclude_address_family.append(4)
            pass
          elif "ip4-ip4" in flows and "ip6-ip6" in flows:
            pass
          elif "ip4-only" in flows and "ip6-only" in flows:
            logging.warning(
                "WARNING: Term %s in policy %s>%s has source and destinations "
                "of different address families %s, term will not be "
                "rendered.", term.name, self.from_zone, self.to_zone,
                filter(lambda p: re.search(p, "(src|dst)-only"), flows))
            continue
          else:
            logging.warning(
                "WARNING: Term %s in policy %s>%s has invalid src-dest "
                "combinations %s, the term will be rendered without them.",
                term.name, self.from_zone, self.to_zone,
                filter(lambda p: re.search(p, "(src|dst)-only"), flows))
            if "ip4-ip4" in flows:
              exclude_address_family.append(6)
            else:
              exclude_address_family.append(4)

        # Substitute large IPv6 ranges (/1, /2) with equivalent subnets.
        # Do this separately from address book building, or during policy
        # translation to account for both address-objects and no-address-objects
        if term.source_address:
          saddr_split = []
          for saddr in term.source_address:
            if saddr.version == 6 and 0 < saddr.prefixlen < 3:
              for saddr2 in saddr.subnets(new_prefix=3):
                saddr2.parent_token = saddr.parent_token
                saddr_split.append(saddr2)
            else:
              saddr_split.append(saddr)
          term.source_address = saddr_split
        if term.destination_address:
          daddr_split = []
          for daddr in term.destination_address:
            if daddr.version == 6 and 0 < daddr.prefixlen < 3:
              for daddr2 in daddr.subnets(new_prefix=3):
                daddr2.parent_token = daddr.parent_token
                daddr_split.append(daddr2)
            else:
              daddr_split.append(daddr)
          term.destination_address = daddr_split

        # Build address book for the addresses referenced in the term.
        for addr in term.source_address:
          if addr.version in exclude_address_family:
            continue
          self._BuildAddressBook(self.from_zone, addr)
        for addr in term.destination_address:
          if addr.version in exclude_address_family:
            continue
          self._BuildAddressBook(self.to_zone, addr)

        # Handle ICMP/ICMPv6 terms.
        if term.icmp_type and ("icmp" not in term.protocol and
                               "icmpv6" not in term.protocol):
          raise UnsupportedFilterError(
              "Palo Alto Firewall filter must have ICMP or ICMPv6 protocol " +
              "specified when using icmp_type keyword")

        for icmp_version in ["icmp", "icmpv6"]:
          if ("icmp" not in term.protocol and "icmpv6" not in term.protocol):
            # the protocol is not ICMP or ICMPv6
            break
          if icmp_version not in term.protocol:
            # skip if this icmp_version isn't in the term protocol.
            continue
          if icmp_version == "icmp" and "ip4-ip4" not in flows:
            # skip if there is no ip4 to ipv4 communication
            continue
          if icmp_version == "icmpv6" and "ip6-ip6" not in flows:
            # skip if there is no ip4 to ipv4 communication
            continue
          if icmp_version == "icmp":
            if filter_type == "inet6":
              continue
            if not term.icmp_type:
              term.pan_application.append("icmp")
              continue
            icmp_type_keyword = "ident-by-icmp-type"
            # The risk level 4 is the default PANOS' risk level for ICMP.
            risk_level = 4
          else:
            if filter_type == "inet":
              continue
            if not term.icmp_type:
              term.pan_application.append("ipv6-icmp")
              continue
            icmp_type_keyword = "ident-by-icmp6-type"
            # The risk level 2 is the default PANOS' risk level for ICMPv6.
            risk_level = 2
          # The term contains ICMP types
          for term_icmp_type_name in term.icmp_type:
            if icmp_version == "icmp":
              icmp_app_name = "icmp-%s" % term_icmp_type_name
              # This is to abbreviate the Application name where possible.
              # The limit is defined by _APPLICATION_NAME_MAX_LENGTH = 31.
              if len(icmp_app_name) > self._APPLICATION_NAME_MAX_LENGTH:
                icmp_app_name = self.FixTermLength(
                    icmp_app_name, True, True,
                    self._APPLICATION_NAME_MAX_LENGTH)
              if term_icmp_type_name not in policy.Term.ICMP_TYPE[4]:
                raise PaloAltoFWBadIcmpTypeError(
                    "term with bad icmp type: %s, icmp_type: %s" %
                    (term.name, term_icmp_type_name))
              term_icmp_type = policy.Term.ICMP_TYPE[4][term_icmp_type_name]
            else:
              icmp_app_name = "icmp6-%s" % term_icmp_type_name
              # This is to abbreviate the Application name where possible.
              # The limit is defined by _APPLICATION_NAME_MAX_LENGTH = 31.
              if len(icmp_app_name) > self._APPLICATION_NAME_MAX_LENGTH:
                icmp_app_name = self.FixTermLength(
                    icmp_app_name, True, True,
                    self._APPLICATION_NAME_MAX_LENGTH)
              if term_icmp_type_name not in policy.Term.ICMP_TYPE[6]:
                raise PaloAltoFWBadIcmpTypeError(
                    "term with bad icmp type: %s, icmp_type: %s" %
                    (term.name, term_icmp_type_name))
              term_icmp_type = policy.Term.ICMP_TYPE[6][term_icmp_type_name]
            if icmp_app_name not in self.application_refs:
              # the custom icmp application doesn't already exist
              app_entry = {
                  "category": "networking",
                  "subcategory": "ip-protocol",
                  "technology": "network-protocol",
                  "description": icmp_app_name,
                  "default": {
                      icmp_type_keyword: "%d" % term_icmp_type,
                  },
                  "risk": "%d" % risk_level,
              }
              self.application_refs[icmp_app_name] = app_entry
              self.applications.append(icmp_app_name)

            # always add the ICMP application to the term, it either already
            # existed due to a previous policy, or it was created in the
            # previous loop.
            if icmp_app_name not in term.pan_application:
              term.pan_application.append(icmp_app_name)

        # Filter out unsupported protocols
        for proto_name in term.protocol:
          if proto_name in self._SUPPORTED_PROTO_NAMES:
            continue
          raise PaloAltoFWUnsupportedProtocolError(
              "protocol %s is not supported" % proto_name)

        if term.icmp_type:
          if set(term.protocol) == {'icmp', 'icmpv6'}:
            raise UnsupportedFilterError('%s %s' % (
                'icmp-type specified for both icmp and icmpv6 protocols'
                ' in a single term:', term.name))
          if term.protocol != ['icmp'] and term.protocol != ['icmpv6']:
            raise UnsupportedFilterError('%s %s' % (
                'icmp-type specified for non-icmp protocols in term:',
                term.name))

        new_terms.append(term)

      # Create a ruleset. It contains the rules for the terms defined under
      # a single header on a particular platform.
      ruleset = {}

      for term in new_terms:
        current_rule = Rule(self.from_zone, self.to_zone, term,
                            self.service_map)
        if len(current_rule.options) > 1:
          for i, v in enumerate(current_rule.options):
            name = "%s-%d" % (term.name, i+1)
            name = self.FixTermLength(name)
            ruleset[name] = v
        else:
          ruleset[term.name] = current_rule.options[0]

      self.pafw_policies.append((header, ruleset, filter_options))

  def _BuildAddressBook(self, zone, address):
    """Create the address book configuration entries.

    Args:
      zone: the zone these objects will reside in
      address: a naming library address object
    """
    if zone not in self.addressbook:
      self.addressbook[zone] = collections.OrderedDict()
    if address.parent_token not in self.addressbook[zone]:
      # Store addresses as keys to enable quick lookups.
      # key: address, value: name
      self.addressbook[zone][address.parent_token] = collections.OrderedDict()
    name = address.parent_token
    if address in self.addressbook[zone][name]:
      return
    counter = len(self.addressbook[zone][address.parent_token])
    name = "%s_%s" % (name, str(counter))

    self.addressbook[zone][address.parent_token][address] = name

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

    # IPv4 addresses are normalized into the policy as IPv6 addresses
    # using ::<ipv4-address>.  The 0.0.0.0-255.255.255.255 range is
    # equivalent to ::0/96 which will only match IPv4 addresses; when
    # negated it will match only IPv6 addresses.
    # Used for address families inet and inet6 when source and
    # destination address are not specified (any any).
    ANY_IPV4_RANGE = "0.0.0.0-255.255.255.255"
    add_any_ipv4 = False

    address_book_names_dict = {}
    address_book_groups_dict = {}
    for zone in self.addressbook:
      # building individual addresses dictionary
      groups = sorted(self.addressbook[zone])
      for group in groups:
        for address, name in self.addressbook[zone][group].items():
          if name in address_book_names_dict:
            if address_book_names_dict[name].supernet_of(address):
              continue
          address_book_names_dict[name] = address

        # building individual address-group dictionary
        for nested_group in groups:
          group_names = []
          for address, name in self.addressbook[zone][nested_group].items():
            group_names.append(name)
          address_book_groups_dict[nested_group] = group_names

      # sort address books and address sets
      address_book_groups_dict = collections.OrderedDict(
          sorted(address_book_groups_dict.items()))

    address_book_keys = sorted(
        list(address_book_names_dict.keys()), key=self._SortAddressBookNumCheck)

    # INITAL CONFIG
    config = etree.Element("config", {
        "version": "8.1.0",
        "urldb": "paloaltonetworks"
    })
    devices = etree.SubElement(config, "devices")
    device_entry = etree.SubElement(devices, "entry",
                                    {"name": "localhost.localdomain"})
    vsys = etree.SubElement(device_entry, "vsys")
    vsys_entry = etree.SubElement(vsys, "entry", {"name": "vsys1"})

    # APPLICATION
    app_entries = etree.Element("application")
    for app_name in self.applications:
      if app_name not in self.application_refs:
        # this is not a custom application.
        continue
      app = self.application_refs[app_name]
      app_entry = etree.SubElement(app_entries, "entry", {"name": app_name})
      for k in self.application_refs[app_name]:
        if isinstance(app[k], (str)):
          etree.SubElement(app_entry, k).text = app[k]
        elif isinstance(app[k], (dict)):
          if k == "default":
            default_props = etree.SubElement(app_entry, "default")
          else:
            continue
          for prop in app[k]:
            if k == "default" and prop in [
                "ident-by-icmp-type", "ident-by-icmp6-type"
            ]:
              icmp_type_props = etree.SubElement(default_props, prop)
              etree.SubElement(icmp_type_props, "type").text = app[k][prop]
            else:
              pass
    vsys_entry.append(app_entries)

    # APPLICATION GROUPS
    etree.SubElement(vsys_entry, "application-group")

    # SERVICES
    service = etree.SubElement(vsys_entry, "service")
    for k, v in self.service_map.entries.items():
      entry = etree.SubElement(service, "entry", {"name": v["name"]})
      proto0 = etree.SubElement(entry, "protocol")
      proto = etree.SubElement(proto0, k[2])
      # destination port
      port = etree.SubElement(proto, "port")
      tup = str(k[1])[1:-1]
      if tup[-1] == ",":
        tup = tup[:-1]
      port.text = tup.replace("'", "").replace(", ", ",")
      # source port
      if len(k[0]):
        sport = etree.SubElement(proto, "source-port")
        tup = str(k[0])[1:-1]
        if tup[-1] == ",":
          tup = tup[:-1]
        sport.text = tup.replace("'", "").replace(", ", ",")

    # RULES
    rulebase = etree.SubElement(vsys_entry, "rulebase")
    security = etree.SubElement(rulebase, "security")
    rules = etree.SubElement(security, "rules")
    tag = etree.Element("tag")

    tag_num = 0

    # pylint: disable=unused-variable
    for (header, pa_rules, filter_options) in self.pafw_policies:
      tag_name = None
      if header.comment:
        comment = " ".join(header.comment).strip()
        if comment:
          tag_num += 1
          # max tag len 127, max zone len 31
          tag_name = self._TAG_NAME_FORMAT.format(
              from_zone=filter_options[1],
              to_zone=filter_options[3],
              num=tag_num)
          tag_entry = etree.SubElement(tag, "entry", {"name": tag_name})
          comments = etree.SubElement(tag_entry, "comments")
          if len(comment) > self._MAX_TAG_COMMENTS_LENGTH:
            logging.warning(
                "WARNING: tag %s comments exceeds maximum "
                "length %d, truncated.", tag_name,
                self._MAX_TAG_COMMENTS_LENGTH)
          comments.text = comment[:self._MAX_TAG_COMMENTS_LENGTH]

      no_addr_obj = True if (len(filter_options) > 5 and
                             filter_options[5] == "no-addr-obj") else False

      for name, options in pa_rules.items():
        entry = etree.SubElement(rules, "entry", {"name": name})
        if options["description"]:
          descr = etree.SubElement(entry, "description")
          x = " ".join(options["description"])
          if len(x) > self._MAX_RULE_DESCRIPTION_LENGTH:
            logging.warning(
                "WARNING: rule %s description exceeds maximum "
                "length %d, truncated.", name,
                self._MAX_RULE_DESCRIPTION_LENGTH)
          descr.text = x[:self._MAX_RULE_DESCRIPTION_LENGTH]

        to = etree.SubElement(entry, "to")
        for x in options["to_zone"]:
          member = etree.SubElement(to, "member")
          member.text = x

        from_ = etree.SubElement(entry, "from")
        for x in options["from_zone"]:
          member = etree.SubElement(from_, "member")
          member.text = x

        af = filter_options[4] if len(filter_options) > 4 else "inet"

        max_src_dst = 0
        source = etree.SubElement(entry, "source")
        if not options["source"]:
          member = etree.SubElement(source, "member")
          if not options["destination"] and af != "mixed":
            # only inet and inet6 use the any-ipv4 object
            member.text = "any-ipv4"
            add_any_ipv4 = True
          else:
            member.text = "any"
        else:
          for x in options["source"]:
            if no_addr_obj:
              for group in address_book_groups_dict[x]:
                member = etree.SubElement(source, "member")
                member.text = str(address_book_names_dict[group])
                max_src_dst += 1
            else:
              member = etree.SubElement(source, "member")
              member.text = x
              max_src_dst += 1

        if max_src_dst > self._MAX_RULE_SRC_DST_MEMBERS:
          raise UnsupportedFilterError(
            "term %s source members exceeds maximum of %d: %d" %
            (name, self._MAX_RULE_SRC_DST_MEMBERS, max_src_dst))

        max_src_dst = 0
        dest = etree.SubElement(entry, "destination")
        if not options["destination"]:
          member = etree.SubElement(dest, "member")
          if options["source"]:
            member.text = "any"
          else:
            if af != "mixed":
              # only inet and inet6 use the any-ipv4 object
              member.text = "any-ipv4"
              if af == "inet6":
                for x in ["negate-source", "negate-destination"]:
                  negate = etree.SubElement(entry, x)
                  negate.text = "yes"
            else:
              member.text = "any"
        else:
          for x in options["destination"]:
            if no_addr_obj:
              for group in address_book_groups_dict[x]:
                member = etree.SubElement(dest, "member")
                member.text = str(address_book_names_dict[group])
                max_src_dst += 1
            else:
              member = etree.SubElement(dest, "member")
              member.text = x
              max_src_dst += 1

        if max_src_dst > self._MAX_RULE_SRC_DST_MEMBERS:
          raise UnsupportedFilterError(
            "term %s destination members exceeds maximum of %d: %d" %
            (name, self._MAX_RULE_SRC_DST_MEMBERS, max_src_dst))

        # service section of a policy rule.
        service = etree.SubElement(entry, "service")
        if not options["service"] and not options["application"]:
          member = etree.SubElement(service, "member")
          member.text = "any"
        elif not options["service"] and options["application"]:
          # Adds custom applications.
          member = etree.SubElement(service, "member")
          member.text = "application-default"
        else:
          # Adds services.
          for x in options["service"]:
            member = etree.SubElement(service, "member")
            member.text = x

        # ACTION
        action = etree.SubElement(entry, "action")
        action.text = options["action"]

        # check whether the rule is interzone
        if list(set(options["from_zone"]).difference(options["to_zone"])):
          type_ = etree.SubElement(entry, "rule-type")
          type_.text = "interzone"
        elif not options["from_zone"] and not options["to_zone"]:
          type_ = etree.SubElement(entry, "rule-type")
          type_.text = "interzone"

        # APPLICATION
        app = etree.SubElement(entry, "application")
        if not options["application"]:
          member = etree.SubElement(app, "member")
          member.text = "any"
        else:
          for x in options["application"]:
            member = etree.SubElement(app, "member")
            member.text = x

        if tag_name is not None:
          rules_tag = etree.SubElement(entry, "tag")
          member = etree.SubElement(rules_tag, "member")
          member.text = tag_name

        # LOGGING
        if options["logging"]:
          if "disable" in options["logging"]:
            log = etree.SubElement(entry, "log-start")
            log.text = "no"
            log = etree.SubElement(entry, "log-end")
            log.text = "no"
          if "log-start" in options["logging"]:
            log = etree.SubElement(entry, "log-start")
            log.text = "yes"
          if "log-end" in options["logging"]:
            log = etree.SubElement(entry, "log-end")
            log.text = "yes"

    if no_addr_obj:
      address_book_groups_dict = {}
      address_book_keys = {}

    # ADDRESS
    addr_group = etree.SubElement(vsys_entry, "address-group")

    for group, address_list in address_book_groups_dict.items():
      entry = etree.SubElement(addr_group, "entry", {"name": group})
      static = etree.SubElement(entry, "static")
      for name in address_list:
        member = etree.SubElement(static, "member")
        member.text = name

    addr = etree.SubElement(vsys_entry, "address")

    for name in address_book_keys:
      entry = etree.SubElement(addr, "entry", {"name": name})
      desc = etree.SubElement(entry, "description")
      desc.text = name
      ip = etree.SubElement(entry, "ip-netmask")
      ip.text = str(address_book_names_dict[name])

    if add_any_ipv4:
      entry = etree.SubElement(addr, "entry", {"name": "any-ipv4"})
      desc = etree.SubElement(entry, "description")
      desc.text = ("Object to match all IPv4 addresses; "
                   "negate to match all IPv6 addresses.")
      range = etree.SubElement(entry, "ip-range")
      range.text = ANY_IPV4_RANGE

    vsys_entry.append(tag)

    self.config = config
    document = etree.tostring(config, encoding="UTF-8")
    dom = minidom.parseString(document.decode("UTF-8"))

    return dom.toprettyxml(indent=self.INDENT)
