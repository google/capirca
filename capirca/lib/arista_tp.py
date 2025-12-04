# Copyright 2021 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""arista traffic-policy generator."""

import copy
import datetime
import re
import textwrap

from absl import logging
from capirca.lib import aclgenerator
import six

#          1         2         3
# 123456789012345678901234567890123456789
# traffic-policies
#    traffic-policy foo
#      match dos-attaqrs-source-ip ipv4    << TERM_INDENT
#                  1         2         3         4         5         6
#         123456789012345678901234567890123456789012345678901234567890123456789
#         !! i am a comment, hear me rawr  << MATCH_INDENT
#         !!
#         source prefix field-set          << MATCH_INDENT
#         !
#         actions
#            counter edge-dos-attaqrs-source-ip-count  << ACTION_INDENT
#            drop
#      !
#
#          1         2         3
# 123456789012345678901234567890123456789
# traffic-policies
#    field-set ipv4 prefix dst-hjjqurby6yftqk6fa3xx4fas << TERM_INDENT
#       0.0.0.0/0                                       << MATCH_INDENT
#       except 34.64.0.0/26
#    !
#    field-set ipv4 prefix dst-hjjqurby6yftqk6fa3xx4fas

# various indentation constants - see above
INDENT_STR = " " * 3  # 3 spaces
TERM_INDENT = 2 * INDENT_STR
MATCH_INDENT = 3 * INDENT_STR
ACTION_INDENT = 4 * INDENT_STR
MAX_COMMENT_LENGTH = 60

# generic error class


class Error(Exception):
  pass


class TcpEstablishedWithNonTcpError(Error):
  pass


class AristaTpFragmentInV6Error(Error):
  pass


class TooManyAddressAttributesError(Error):
  pass

class Config:
  """config allows a configuration to be assembled easily.

  when appending to the configuration object, the element should be indented
  according to the arista traffic-policy style.

  a text representation of the config can be extracted with str().

  attributes:
  indent: The number of leading spaces on the current line.
  lines: the text lines of the configuration.

  """

  def __init__(self):
    self.lines = []

  def __str__(self):
    return "\n".join(self.lines)

  def Append(self, line_indent, line, verbatim=False):
    """append one line to the configuration.

    Args:
      line_indent: config specific spaces prepended to the line
      line: the configuratoin string to append to the config.
      verbatim: append line without adjusting indentation. Default False.
    """
    if verbatim:
      self.lines.append(line)
      return

    self.lines.append(line_indent + line.strip())


class Term(aclgenerator.Term):
  """represents an individual AristaTrafficPolicy term.

  useful for the __str__() method. where literally, everything interesting
  happens.

  attributes:
   term: the term object from the policy.
   term_type: string indicating type of term, inet, inet6 etc.
   noverbose: boolean to disable verbosity.

  """

  _PLATFORM = "arista_tp"
  _ACTIONS = {
      "accept": "",
      "deny": "drop",
      "reject": "drop",  # unsupported action, convert to drop
      "reject-with-tcp-rst": "drop",  # ibid
      # "next": "continue",
  }
  AF_MAP = {
      "inet": 4,
      "inet6": 6,
  }
  # the following lookup table is used to map between the various types of
  # filters the generator can render.  as new differences are
  # encountered, they should be added to this table.  Accessing members
  # of this table looks like:
  #  self._TERM_TYPE('inet').get('saddr') -> 'source-address'
  #
  # it's critical that the members of each filter type be the same, that is
  # to say that if _TERM_TYPE.get('inet').get('foo') returns something,
  # _TERM_TYPE.get('inet6').get('foo') must return the inet6 equivalent.
  _TERM_TYPE = {
      "inet": {
          "addr_fam": "ipv4",
      },
      "inet6": {
          "addr_fam": "ipv6",
      },
  }

  def __init__(self, term, term_type, noverbose, field_set):
    super().__init__(term)
    self.term = term
    self.term_type = term_type  # drives the address-family
    self.noverbose = noverbose
    # Exclusively generate traffic-policies using field sets for setting the
    # source and destination addresses.
    self.field_set = field_set

    if term_type not in self._TERM_TYPE:
      raise ValueError("unknown filter type: %s" % term_type)

  def __str__(self):
    # verify platform specific terms. skip the whole term if the platform
    # does not match.
    if (self.term.platform and self._PLATFORM not in self.term.platform):
      return ""
    if (self.term.platform_exclude and
        self._PLATFORM in self.term.platform_exclude):
      return ""

    config = Config()

    # a LoL which will be appended to the config at the end of this method
    # elements will be of the form [indentation, string, verbatim] by
    # default verbatim = False
    term_block = []

    # don't render icmpv6 protocol terms under inet, or icmp under inet6
    if (self.term_type == "inet6" and
        "icmp" in self.term.protocol) or (self.term_type == "inet" and
                                          "icmpv6" in self.term.protocol):
      logging.debug(
          self.NO_AF_LOG_PROTO.substitute(
              term=self.term.name,
              proto=", ".join(self.term.protocol),
              af=self.term_type,
          ))
      return ""

    # term verbatim output - this will skip over normal term creation
    # code.  warning generated from policy.py if appropriate.
    if self.term.verbatim:
      for line in self.term.verbatim:
        if line[0] == self._PLATFORM:
          # pass MATCH_INDENT, but this should be ignored in the
          # rendering
          term_block.append([MATCH_INDENT, str(line[1]), True])
      # we return immediately, there's no action to be formed
      for i, s, v in term_block:
        config.Append(i, s, verbatim=v)

      return str(config)

    # option processing
    flags = []
    misc_options = []
    if self.term.option:
      flags, misc_options = self._processTermOptions(self.term,
                                                     self.term.option)

    # helper for per-address-family keywords.
    family_keywords = self._TERM_TYPE.get(self.term_type)

    term_block.append([
        TERM_INDENT,
        "match %s %s" % (self.term.name, family_keywords["addr_fam"]), False
    ])

    term_af = self.AF_MAP.get(self.term_type)
    if self.term.owner and not self.noverbose:
      self.term.comment.append("owner: %s" % self.term.owner)
    if self.term.comment and not self.noverbose:
      reflowed_comments = self._reflowComments(self.term.comment,
                                               MAX_COMMENT_LENGTH)
      for line in reflowed_comments:
        term_block.append([MATCH_INDENT, "!! " + line, False])

    has_match_criteria = (
        self.term.destination_address or
        self.term.destination_address_exclude or self.term.destination_port or
        self.term.destination_prefix or self.term.fragment_offset or
        self.term.hop_limit or self.term.port or self.term.protocol or
        self.term.protocol_except or self.term.source_address or
        self.term.source_address_exclude or self.term.source_port or
        self.term.source_prefix or self.term.ttl or self.term.destination_self)

    # if the term name is default-* we will render this into the
    # appropriate default term name to be used in this filter.
    is_default_term = re.match(r"^ipv(4|6)\-default\-.*", self.term.name,
                               re.IGNORECASE)

    # if the term doesn't match on anything and isn't a default-term and
    # isn't a counter term, then we don't render it.
    if (not has_match_criteria and not is_default_term
        and not self.term.counter):
      # this term doesn't match on anything and isn't a default-term
      logging.warning(
          "WARNING: term %s has no valid match criteria and "
          "will not be rendered.",
          self.term.name,
      )
      return ""

    else:
      # source address
      src_addr = self.term.GetAddressOfVersion("source_address", term_af)
      src_addr_ex = self.term.GetAddressOfVersion("source_address_exclude",
                                                  term_af)

      if src_addr:
        src_str = "source prefix"
        # Use field sets if the term contains source addresses to exclude or if
        # the field_set flag is set.
        if src_addr_ex or self.field_set:
          # this should correspond to the generated field set
          src_str += " field-set src-%s" % self.term.name
        else:
          for addr in src_addr:
            src_str += " %s" % addr

        term_block.append([MATCH_INDENT, src_str, False])
      elif self.term.source_address:
        logging.debug(
            self.NO_AF_LOG_ADDR.substitute(
                term=self.term.name, direction="source", af=self.term_type))
        return ""

      # destination self
      if self.term.destination_self:
        if (
            self.term.destination_address
            or self.term.destination_address_exclude
            or self.term.destination_prefix
        ):
          raise TooManyAddressAttributesError(
              "'destination_self', 'destination_address', "
              "'destination_address_exclude', and 'destination_prefix' "
              "are mutually exclusive."
          )
        term_block.append([MATCH_INDENT, "destination prefix self unicast", False])

      # destination address
      dst_addr = self.term.GetAddressOfVersion("destination_address", term_af)
      dst_addr_ex = self.term.GetAddressOfVersion("destination_address_exclude",
                                                  term_af)

      if dst_addr:
        dst_str = "destination prefix"
        # Use field sets if the term contains destination addresses to exclude
        # or if the field_set flag is set.
        if dst_addr_ex or self.field_set:
          # this should correspond to the generated field set
          dst_str += " field-set dst-%s" % self.term.name
        else:
          for addr in dst_addr:
            dst_str += " %s" % addr

        term_block.append([MATCH_INDENT, dst_str, False])

      elif self.term.destination_address:
        logging.debug(
            self.NO_AF_LOG_ADDR.substitute(
                term=self.term.name, direction="destination",
                af=self.term_type))
        return ""

      if self.term.source_prefix:
        src_pfx_str = "source prefix field-set"
        for pfx in self.term.source_prefix:
          src_pfx_str += " %s" % pfx

        term_block.append([MATCH_INDENT, " %s" % src_pfx_str, False])

      if self.term.destination_prefix:
        dst_pfx_str = "destination prefix field-set"
        for pfx in self.term.destination_prefix:
          dst_pfx_str += " %s" % pfx

        term_block.append([MATCH_INDENT, " %s" % dst_pfx_str, False])

      # PROTOCOL MATCHES
      protocol_str = ""
      if self.term.protocol:
        protocol_str = self._processProtocol(self.term_type, self.term, flags)

      # protocol-except handling
      if self.term.protocol_except:
        protocol_str = self._processProtocolExcept(self.term_type, self.term,
                                                   flags)

      # tcp/udp port generation
      port_str = self._processPorts(self.term)
      if port_str:
        protocol_str += port_str

      # icmp[v6] handling
      icmp_type_str = ""
      icmp_code_str = ""
      if self.term.protocol == ["icmp"] or \
         self.term.protocol == ["icmpv6"]:
        icmp_type_str, icmp_code_str = self._processICMP(self.term)

      if self.term.icmp_type:
        protocol_str += icmp_type_str
      if self.term.icmp_code:
        protocol_str += icmp_code_str

      # don't render empty protocol strings.
      if protocol_str:
        term_block.append([MATCH_INDENT, protocol_str, False])

      # ADDITIONAL SUPPORTED MATCH OPTIONS ------------------------------
      # packet length
      if self.term.packet_length:
        term_block.append(
            [MATCH_INDENT,
             "ip length %s" % self.term.packet_length, False])

      # fragment offset
      if self.term.fragment_offset:
        term_block.append([
            MATCH_INDENT,
            "fragment offset %s" % self.term.fragment_offset, False
        ])

      if self.term.hop_limit:
        term_block.append([MATCH_INDENT, "ttl %s" % self.term.hop_limit, False])

      if self.term.ttl:
        term_block.append([MATCH_INDENT, "ttl %s" % self.term.ttl, False])

      if misc_options:
        for mopt in misc_options:
          term_block.append([MATCH_INDENT, mopt, False])

    # ACTION HANDLING
    # if there's no action, then this is an implicit permit
    current_action = self._ACTIONS.get(self.term.action[0])
    # non-permit/drop actions should be added here
    has_extra_actions = (
        self.term.logging
        or self.term.counter
        or self.term.dscp_set
        or self.term.traffic_class
        or self.term.police_kbps
        or self.term.police_burst
        or self.term.police_pps
        or self.term.next_hop_group
        or self.term.next_interface
    )

    # if !accept - generate an action statement
    # if accept and there are extra actions generate an actions statement
    # if accept and no extra actions don't generate an actions statement
    if self.term.action != ["accept"]:
      term_block.append([MATCH_INDENT, "actions", False])
      term_block.append([ACTION_INDENT, "%s" % current_action, False])
    elif self.term.action == ["accept"] and has_extra_actions:
      term_block.append([MATCH_INDENT, "actions", False])

    if has_extra_actions:
      # logging - only supported on deny actions
      if self.term.logging and self.term.action != ["accept"]:
        term_block.append([ACTION_INDENT, "log", False])
      elif self.term.logging and self.term.action == ["accept"]:
        logging.warning(
            "WARNING: term %s uses logging option but is not a deny "
            "action. logging will not be added.",
            self.term.name,
        )
        # counters
      if self.term.counter:
        term_block.append(
            [ACTION_INDENT,
             "count %s" % self.term.counter, False])

      # set dscp bits if any.
      if self.term.dscp_set and self._is_valid_dscp_value(self.term.dscp_set):
        term_block.append(
            [ACTION_INDENT, f"set dscp {self.term.dscp_set}", False]
        )

      if self.term.traffic_class:
        term_block.append([
            ACTION_INDENT,
            f"set traffic class {self.term.traffic_class}",
            False,
        ])
      if self.term.police_kbps and self.term.police_pps:
        logging.warning(
            "WARNING: term %s uses police_pps and police_kbps."
            "Only one of these options can be used.",
            self.term.name,
        )
      elif self.term.police_burst and self.term.police_pps:
        logging.warning(
            "WARNING: term %s uses police_burst, "
            "which is not supported with police_pps.",
            self.term.name,
        )
      elif self.term.police_burst and not self.term.police_kbps:
        logging.warning(
            "WARNING: term %s uses police_burst option but not police_kbps. "
            "police_burst will not be added.",
            self.term.name,
        )
      elif self.term.police_kbps and self.term.police_burst:
        term_block.append([
            ACTION_INDENT,
            (
                f"police rate {self.term.police_kbps} kbps burst-size"
                f" {self.term.police_burst}"
            ),
            False,
        ])
      elif self.term.police_kbps:
        term_block.append([
            ACTION_INDENT,
            f"police rate {self.term.police_kbps} kbps",
            False,
        ])
      elif self.term.police_pps:
        term_block.append([
            ACTION_INDENT,
            f"police rate {self.term.police_pps} pps",
            False,
        ])


      if self.term.next_hop_group:
        term_block.append([
            ACTION_INDENT,
            f"redirect next-hop group {self.term.next_hop_group}",
            False,
        ])

      if self.term.next_interface and self._is_valid_next_interface(
          self.term.next_interface):
        term_block.append([
            ACTION_INDENT,
            f"redirect interface {self.term.next_interface}",
            False,
        ])

      term_block.append([MATCH_INDENT, "!", False])  # end of actions
    term_block.append([TERM_INDENT, "!", False])  # end of match entry

    for tindent, tstr, tverb in term_block:
      config.Append(tindent, tstr, verbatim=tverb)

    return str(config)

  def _is_valid_dscp_value(self, dscp):
    if dscp.isdigit() and 0 <= int(dscp) <= 63:
      return True
    raise ValueError(f"Invalid DSCP value: {dscp}. Valid range is 0-63.")

  def _is_valid_next_interface(self, interface):
    if (
        interface.startswith("Ethernet")
        or interface.startswith("InternalRecirc")
        or interface.startswith("Port-Channel")
    ):
      return True
    raise ValueError(
        f"Invalid next interface value: {self.term.next_interface}. "
        "Must begin with Ethernet, InternalRecirc, or Port-Channel."
    )

  def _reflowComments(self, comments, max_length):
    """reflows capirca comments to stay within max_length.

    Args:
      comments (list): list of comment strings
      max_length (int):

    Returns:
      type: list containing the reflowed text.

    if a comment list entry is > max_length it will be reflowed and appended
    to the returned comment list

    """
    flowed_comments = []

    for comment in comments:
      lines = comment.split("\n")
      for line in lines:
        if len(line) > max_length:
          line = textwrap.wrap(line, max_length)
          flowed_comments.extend(line)
        else:
          flowed_comments.append(line)

    return flowed_comments

  def _processPorts(self, term):
    port_str = ""

    # source port generation
    if term.source_port:
      port_str += " source port %s" % self._Group(
          term.source_port, separator=", "
      )

    # destination port
    if term.destination_port:
      port_str += " destination port %s" % self._Group(
          term.destination_port, separator=", "
      )

    return port_str

  def _processICMP(self, term):
    icmp_types = [""]
    icmp_code_str = ""
    icmp_type_str = " type "

    if term.icmp_type:
      icmp_types = self.NormalizeIcmpTypes(term.icmp_type, term.protocol,
                                           self.term_type)
    if icmp_types != [""]:
      for t in icmp_types:
        icmp_type_str += "%s," % t

      if icmp_type_str.endswith(","):
        icmp_type_str = icmp_type_str[:-1]  # chomp trailing ','
        if not term.icmp_code:
          icmp_type_str += " code all"

    if self.term.icmp_code and len(icmp_types) <= 1:
      icmp_codes = self._Group(self.term.icmp_code)
      icmp_codes = re.sub(r" ", ",", icmp_codes)
      icmp_code_str += " code %s" % icmp_codes

    return icmp_type_str, icmp_code_str

  def _processProtocol(self, term_type, term, flags):
    anet_proto_map = {
        "inet": {
            # <1-255> protocol  values(s) or range(s) of protocol  values
            "ahp": "",
            "bgp": "",
            "icmp": "",
            "igmp": "",
            "ospf": "",
            "pim": "",
            "rsvp": "",
            "tcp": "",
            "udp": "",
            "vrrp": "",
        },
        "inet6": {
            # <0-255> protocol  values(s) or range(s) of protocol  values
            "bgp": "",  # BGP
            "icmpv6": "",  # ICMPv6 (58)
            "ospf": "",  # OSPF routing protocol (89)
            "pim": "",  # Protocol Independent Multicast (PIM) (103)
            "rsvp": "",  # Resource Reservation Protocol (RSVP) (46)
            "tcp": "",  # TCP
            "udp": "",  # UDP
            "vrrp": "",  # VRRP (112)
        }
    }

    protocol_str = ""
    prots = []
    # if there are dirty prots we'll need to convert the protocol list to
    # all numbers and generate the list of protocols to match on. EOS
    # doesn't support commingling named protocols w/numeric protocol-ids
    dirty_prots = False
    for p in term.protocol:
      if p not in anet_proto_map[term_type].keys():
        dirty_prots = True

      prots.append(p)

    if dirty_prots:
      num_prots = []
      for p in prots:
        try:
          num_prots.append(str(self.PROTO_MAP[p]))
        except KeyError:
          num_prots.append(str(p))
      protocol_str += "protocol %s" % ",".join(num_prots)
    else:
      protocol_str += "protocol %s" % self._Group(prots)

    if prots == ["tcp"] and flags:
      protocol_str += " flags " + " ".join(flags)

    return protocol_str

  def _processProtocolExcept(self, term_type, term, flags):
    # EOS does not have a protocol-except keyword. it does, however, support
    # lists of protocol-ids. given a term this function will generate the
    # appropriate list of protocol-id's which *will* be permited. within the
    # supported range of addaress family protocols.
    protocol_range = {
        "inet": 1,
        "inet6": 0,
    }
    protocol_str = ""
    except_list = set()
    for p in term.protocol_except:
      if p in self.PROTO_MAP.keys():
        except_list.add(self.PROTO_MAP[p])
      else:
        except_list.add(int(p))
    except_list = sorted(except_list)

    ex_str = ""
    ptr = protocol_range[term_type]
    for p in except_list:
      if 255 > p > ptr:
        if (p - 1) == ptr:
          ex_str += str(ptr) + ","
        else:
          ex_str += str(ptr) + "-" + str(p - 1) + ","

        ptr = p + 1
      elif p == ptr:
        ptr = p + 1

    ex_str += str(ptr) + "-" + "255"
    protocol_str = "protocol " + ex_str

    return protocol_str

  def _processTermOptions(self, term, options):
    flags = []
    misc_options = []

    for opt in [str(x) for x in options]:
      # note: traffic policies support additional tcp flags. for now,
      # only handle the required elements
      #
      # only append tcp-established for option established when
      # tcp is the only protocol
      if opt.startswith("established"):
        if self.term.protocol == ["tcp"] and "established" not in flags:
          flags.append("established")
      # if tcp-established specified, but more than just tcp is
      # included in the protocols, raise an error
      elif opt.startswith("tcp-established"):
        if (self.term.protocol == ["tcp"] and "established" not in flags):
          flags.append("established")
        if (len(self.term.protocol) > 1 or self.term.protocol != ["tcp"]):
          raise TcpEstablishedWithNonTcpError(
              "tcp-established can only be used with tcp "
              "protocol in term %s" % self.term.name)
      elif (opt.startswith("initial") and self.term.protocol == ["tcp"]):
        flags.append("initial")
      elif opt.startswith("rst") and self.term.protocol == ["tcp"]:
        flags.append("rst")
      elif "fragment" in opt:
        # handles the is-fragment and first-fragment options
        misc_options.append("fragment")

    return flags, misc_options

  def _Group(self, group, lc=True, separator=" "):
    """If 1 item return it, else return [item1 item2].

    Args:
      group: a list.  could be a list of strings(protocols) or a list of
             tuples(ports)
      lc: return a lower cased result for text.  Default is True.
      separator: default space for protocols and icmp codes. comma for ports.

    Returns:
      string: surrounded by '[' and '];' if len(group) > 1, or with
              just ';' appended if len(group) == 1
    """

    def _FormattedGroup(el, lc=True):
      """Return the actual formatting of an individual element.

      Args:
        el: either a string(protocol) or a tuple(ports)
        lc: return lower cased result for text.  Default is True.

      Returns:
        string: either the lower()'ed string or the ports, hyphenated
                if they're a range, or by itself if it's not.
      """
      if isinstance(el, str):
        if lc:
          return el
        else:
          return el.lower()
      elif isinstance(el, int):
        return str(el)
      # type is a tuple below here
      elif el[0] == el[1]:
        return "%d" % el[0]
      else:
        return "%d-%d" % (el[0], el[1])

    if len(group) > 1:
      rval = separator.join([_FormattedGroup(x, lc) for x in group])
    else:
      rval = _FormattedGroup(group[0])
    return rval


class AristaTrafficPolicy(aclgenerator.ACLGenerator):
  """arista traffic-policy rendering class.

  takes a policy object and renders the output into a syntax
  which is understood by arista switches.

  Attributes:
    pol: policy.Policy object
  """
  _AF_MAP = {"inet": 4, "inet6": 6}
  _DEFAULT_PROTOCOL = "ip"
  _PLATFORM = "arista_tp"
  _SUPPORTED_AF = frozenset(("inet", "inet6", "mixed"))
  _TERM = Term
  _LOGGING = set()

  SUFFIX = ".atp"

  def _BuildTokens(self):
    """returns: tuple of supported tokens and sub tokens."""
    supported_tokens, supported_sub_tokens = super()._BuildTokens()

    supported_tokens |= {
        "action",
        "comment",
        "counter",
        "destination_address",
        "destination_address_exclude",
        "destination_port",
        "destination_prefix",
        "destination_self",
        "dscp_set",
        "expiration",
        "fragment_offset",
        "hop_limit",
        "icmp_code",
        "icmp_type",
        "logging",
        "name",
        "option",
        "owner",
        "packet_length",
        "platform",
        "platform_exclude",
        "port",
        "protocol",
        "protocol_except",
        "police_burst",
        "police_kbps",
        "police_pps",
        "source_address",
        "source_address_exclude",
        "source_port",
        "source_prefix",
        "traffic_class",
        "ttl",
        "verbatim",
        "next_hop_group",
        "next_interface"
    }
    supported_sub_tokens.update({
        "option": {
            "established",
            "is-fragment",
            ".*",  # accept arbitrary options
            "tcp-established",
            "tcp-initial",
        }
    })
    return supported_tokens, supported_sub_tokens

  def _MinimizePrefixes(self, include, exclude):
    """Calculate a minimal set of prefixes for match conditions.

    Args:
      include: Iterable of nacaddr objects, prefixes to match.
      exclude: Iterable of nacaddr objects, prefixes to exclude.

    Returns:
      A tuple (I,E) where I and E are lists containing the minimized
      versions of include and exclude, respectively.  The order
      of each input list is preserved.
    """
    # Remove any included prefixes that have EXACT matches in the
    # excluded list.  Excluded prefixes take precedence on the router
    # regardless of the order in which the include/exclude are applied.
    exclude_set = set(exclude)
    include_result = [ip for ip in include if ip not in exclude_set]

    # Every address match condition on a AristaTp firewall filter
    # contains an implicit "0/0 except" or "0::0/0 except".  If an
    # excluded prefix is not contained within any less-specific prefix
    # in the included set, we can elide it.  In other words, if the
    # next-less-specific prefix is the implicit "default except",
    # there is no need to configure the more specific "except".
    exclude_result = []
    for exclude_prefix in exclude:
      for include_prefix in include_result:
        if exclude_prefix.subnet_of(include_prefix):
          exclude_result.append(exclude_prefix)
          break

    return include_result, exclude_result

  def _GenPrefixFieldset(self, direction, name, pfxs, ex_pfxs, af):
    field_list = ""

    for p in pfxs:
      field_list += (" " * 6) + "%s\n" % p
    for p in ex_pfxs:
      field_list += (" " * 6) + "except %s\n" % p
    fieldset_name = "%s-%s" % (direction, name)
    fieldset_hdr = ("field-set " + af + " prefix " + fieldset_name + "\n")
    field_set = fieldset_hdr + field_list
    return fieldset_name, field_set

  def _TranslatePolicy(self, pol, exp_info):
    self.arista_traffic_policies = []
    af_map_txt = {"inet": "ipv4", "inet6": "ipv6"}

    current_date = datetime.datetime.utcnow().date()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)

    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue

      filter_options = header.FilterOptions(self._PLATFORM)
      filter_name = header.FilterName(self._PLATFORM)
      noverbose = "noverbose" in filter_options[1:]
      field_set = "field_set" in filter_options[1:]
      if field_set:
        filter_options.remove("field_set")

      term_names = set()
      new_terms = []  # list of generated terms
      # Dictionary of generated field-sets with field-set name used as the key.
      policy_field_sets = dict()
      policy_counters = set()  # set of the counters in the policy

      # default to mixed policies
      filter_type = "mixed"
      if len(filter_options) > 1:
        filter_type = filter_options[1]

      # if the filter_type is mixed, we need to iterate through the
      # supported address families. treat the incoming policy term
      # (pol_term) as a template for the term and override the necessary
      # elements of the term for the inet6 evaluation.
      #
      # only make a copy of the pol_term if filter_type = "mixed"
      ftypes = []

      if filter_type == "mixed":
        ftypes = ["inet", "inet6"]
      else:
        ftypes = [filter_type]

      for pol_term in terms:
        for ft in ftypes:
          if filter_type == "mixed":
            term = copy.deepcopy(pol_term)
          else:
            term = pol_term

          # if the term name is default-* we will render this into the
          # appropriate default term name to be used in this filter.
          default_term = re.match(r"^default\-.*", term.name, re.IGNORECASE)

          # make the term names unique to address family.
          if ft == "inet6":
            term.name = af_map_txt[ft] + "-" + term.name

          if default_term:
            term.name = af_map_txt[ft] + "-default-all"

          if term.name in term_names:
            raise aclgenerator.DuplicateTermError("multiple terms named: %s" %
                                                  term.name)
          term_names.add(term.name)

          term = self.FixHighPorts(term, af=ft)
          if not term:
            continue

          if term.expiration:
            if term.expiration <= exp_info_date:
              logging.info(
                  "INFO: term %s in policy %s expires "
                  "in less than two weeks.",
                  term.name,
                  filter_name,
              )
            if term.expiration <= current_date:
              logging.warning(
                  "WARNING: term %s in policy %s is expired and "
                  "will not be rendered.",
                  term.name,
                  filter_name,
              )
              continue

          # emit warnings for unsupported options / terms
          if term.option:
            unsupported_opts = []
            for opt in [str(x) for x in term.option]:
              if opt.startswith("sample") or \
                 opt.startswith("first-fragment"):
                unsupported_opts.append(opt)

            # unsupported options are in use and should be skipped
            if unsupported_opts:
              logging.warning(
                  "WARNING: term %s in policy %s uses an "
                  "unsupported option (%s) and will not be "
                  "rendered.",
                  term.name,
                  filter_name,
                  " ".join(unsupported_opts),
              )
              continue

          has_unsupported_match_criteria = (
              term.dscp_except or term.dscp_match or term.ether_type or
              term.flexible_match_range or term.forwarding_class or
              term.forwarding_class_except or term.next_ip or term.port or
              term.traffic_type)
          if has_unsupported_match_criteria:
            logging.warning(
                "WARNING: term %s in policy %s uses an "
                "unsupported match criteria and will not "
                "be rendered.",
                term.name,
                filter_name,
            )
            continue

          if (("is-fragment" in term.option or "fragment" in term.option) and
              filter_type == "inet6"):
            raise AristaTpFragmentInV6Error("the term %s uses is-fragment but "
                                            "is a v6 policy." % term.name)

          # this should error out more gracefully in mixed configs
          if (("is-fragment" in term.option or "fragment" in term.option) and
              ft == "inet6"):
            logging.warning(
                "WARNING: term %s in mixed policy %s uses "
                "fragment the ipv6 version of the term will not be "
                "rendered.",
                term.name,
                filter_name,
            )
            continue

          # check for traffic-policy specific feature interactions
          if (("is-fragment" in term.option or "fragment" in term.option) and
              (term.source_port or term.destination_port)):
            logging.warning(
                "WARNING: term %s uses fragment as well as src/dst "
                "port matches.  traffic-policies currently do not "
                "support this match combination. the term will not "
                "be rendered",
                term.name,
            )
            continue

          # check for common unsupported actions (e.g.: next)
          if term.action == ["next"]:
            logging.warning(
                "WARNING: term %s uses an unsupported action "
                "(%s) and will not be rendered",
                term.name,
                " ".join(term.action),
            )
            continue

          # generate the prefix sets when there are inline addres
          # exclusions in a term. these will be referenced within the
          # term
          src_addr, src_addr_ex = self._MinimizePrefixes(
              term.GetAddressOfVersion("source_address", self._AF_MAP[ft]),
              term.GetAddressOfVersion(
                  "source_address_exclude", self._AF_MAP[ft]
              ),
          )

          # if there are no addresses to match, don't generate a field-set
          if (src_addr or src_addr_ex) and (src_addr_ex or field_set):
            name, fs = self._GenPrefixFieldset(
                "src", term.name, src_addr, src_addr_ex, af_map_txt[ft]
            )
            policy_field_sets[name] = fs

          dst_addr, dst_addr_ex = self._MinimizePrefixes(
              term.GetAddressOfVersion("destination_address", self._AF_MAP[ft]),
              term.GetAddressOfVersion(
                  "destination_address_exclude", self._AF_MAP[ft]
              ),
          )

          if (dst_addr or dst_addr_ex) and (dst_addr_ex or field_set):
            name, fs = self._GenPrefixFieldset(
                "dst", term.name, dst_addr, dst_addr_ex, af_map_txt[ft]
            )
            policy_field_sets[name] = fs

          # generate the unique list of named counters
          if term.counter:
            # we can't have '.' in counter names
            term.counter = re.sub(r"\.", "-", str(term.counter))
            policy_counters.add(term.counter)

          new_terms.append(self._TERM(term, ft, noverbose, field_set))

      self.arista_traffic_policies.append(
          (header, filter_name, filter_type, new_terms, policy_counters,
           policy_field_sets))

  @staticmethod
  def _remove_duplicate_field_sets(field_sets):
    """Removes duplicate field-sets and maps duplicate names to the original names.

    Args:
      field_sets (dict): A dictionary where keys are field-set names and values
                         are the field-set content as strings.

    Returns:
        tuple: A tuple containing:
            - A list of unique field-set content.
            - A dictionary mapping duplicate field-set names to original names.
    Example:
      If a policy has field-sets with identical prefixes, the function will
      return only the unique field-sets.
      !
      field-set ipv6 prefix src-ipv6-term-1
        2001:4860:4860::8888/128
        2001:4860:4860::8844/128
      !
      field-set ipv6 prefix src-ipv6-term-2
        2001:4860:4860::8888/128
        2001:4860:4860::8844/128
      !
      Result:
      !
      field-set ipv6 prefix src-ipv6-term-1
        2001:4860:4860::8888/128
        2001:4860:4860::8844/128
      !
    """

    # Key: field-set name (str), Value: Set() of prefixes.
    unique_field_sets = dict()
    # Key: duplicate field-set name, Value: Existing field-set name.
    field_sets_to_rename = dict()

    for curr_name, field_set_pfxs in field_sets.items():
      # Extract the prefixes from the field-set (lines excluding the header).
      current_prefixes = tuple(
          line.strip() for line in field_set_pfxs.splitlines()[1:]
      )

      for existing_name, existing_prefixes in unique_field_sets.items():
        if current_prefixes == existing_prefixes:
          # Found a duplicate; Mark the field-set for reanming.
          field_sets_to_rename[curr_name] = existing_name
          break
      else:
        # No duplicate found; add to unique field-sets.
        unique_field_sets[curr_name] = current_prefixes

    return (
        [field_sets[name] for name in unique_field_sets.keys()],
        field_sets_to_rename,
    )

  def __str__(self):
    config = Config()
    filter_names_all_same = False
    first_policy = True
    filter_names = dict()
    for (
        _,
        filter_name,
        _,
        _,
        _,
        _,
    ) in self.arista_traffic_policies:
      filter_names[filter_name] = True
    if len(filter_names) == 1:
      filter_names_all_same = True
    for (
        _,
        filter_name,
        _,
        terms,
        counters,
        field_sets,
    ) in self.arista_traffic_policies:
      # add the header information
      config.Append("", "traffic-policies")

      # duplicate field-sets to be renamed in the traffic policy.
      field_sets_to_rename = dict()
      if field_sets:
        # Remove duplicate field-sets if any.
        unique_field_sets, field_sets_to_rename = (
            self._remove_duplicate_field_sets(field_sets)
        )
        for fs in unique_field_sets:
          config.Append(INDENT_STR, fs)
          config.Append(INDENT_STR, "!")

      if not filter_names_all_same:
        config.Append(INDENT_STR, "no traffic-policy %s" % filter_name)
      elif first_policy:
        config.Append(INDENT_STR, "no traffic-policy %s" % filter_name)
        first_policy = False
      config.Append(INDENT_STR, "traffic-policy %s" % filter_name)

      # if there are counters, export the list of counters
      if counters:
        str_counters = " ".join(counters)
        config.Append("      ", "counter %s" % str_counters)

      # regex pattern for matching duplicate field-sets names in the policy.
      rename_pattern = re.compile("|".join(field_sets_to_rename.keys()))
      for term in terms:
        term_str = str(term)
        if term_str:
          if field_sets_to_rename:
            # Rename all duplicate field-set references in the policy.
            term_str = rename_pattern.sub(
                lambda match, rename_field_sets=field_sets_to_rename:
                rename_field_sets[match.group()],
                term_str,
            )
          config.Append("", term_str, verbatim=True)

    return str(config) + "\n"
