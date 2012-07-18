#!/usr/bin/python



"""Cisco ASA renderer."""

__author__ = 'antony@slac.stanford.edu (Antonio Ceseracciu)'

import datetime
import socket
import logging
import re

from third_party import ipaddr
import aclgenerator
import nacaddr


_ACTION_TABLE = {
    'accept': 'permit',
    'deny': 'deny',
    'reject': 'deny',
    'next': '! next',
    'reject-with-tcp-rst': 'deny',  # tcp rst not supported
    }


# generic error class
class Error(Exception):
  """Generic error class."""
  pass


class UnsupportedCiscoAccessListError(Error):
  """Raised when we're give a non named access list."""
  pass


class StandardAclTermError(Error):
  """Raised when there is a problem in a standard access list."""
  pass


class NoCiscoPolicyError(Error):
  """Raised when a policy is errantly passed to this module for rendering."""
  pass


class Term(aclgenerator.Term):
  """A single ACL Term."""


  def __init__(self, term, filter_name, af=4):
    self.term = term
    self.filter_name = filter_name
    self.options = []
    assert af in (4, 6)
    self.af = af

  def __str__(self):
    # Verify platform specific terms. Skip whole term if platform does not
    # match.
    if self.term.platform:
      if 'ciscoasa' not in self.term.platform:
        return ''
    if self.term.platform_exclude:
      if 'ciscoasa' in self.term.platform_exclude:
        return ''

    ret_str = ['\n']

    # Don't render icmpv6 protocol terms under inet, or icmp under inet6
    if ((self.af == 6 and 'icmp' in self.term.protocol) or
        (self.af == 4 and 'icmpv6' in self.term.protocol)):
      ret_str.append('remark Term %s' % self.term.name)
      ret_str.append('remark not rendered due to protocol/AF mismatch.')
      return '\n'.join(ret_str)

    ret_str.append('access-list %s remark %s' % (self.filter_name,
                                                 self.term.name))
    for comment in self.term.comment:
      for line in comment.split('\n'):
        ret_str.append('access-list %s remark %s' % (self.filter_name,
                                                     str(line)[:100]))

    # Term verbatim output - this will skip over normal term creation
    # code by returning early.  Warnings provided in policy.py.
    if self.term.verbatim:
      for next in self.term.verbatim:
        if next.value[0] == 'ciscoasa':
          ret_str.append(str(next.value[1]))
        return '\n'.join(ret_str)

    # protocol
    if not self.term.protocol:
      protocol = ['ip']
    else:
      # fix the protocol
      protocol = self.term.protocol

    # source address
    if self.term.source_address:
      source_address = self.term.GetAddressOfVersion('source_address', self.af)
      source_address_exclude = self.term.GetAddressOfVersion(
          'source_address_exclude', self.af)
      if source_address_exclude:
        source_address = nacaddr.ExcludeAddrs(
            source_address,
            source_address_exclude)
    else:
      # source address not set
      source_address = ['any']

    # destination address
    if self.term.destination_address:
      destination_address = self.term.GetAddressOfVersion(
          'destination_address', self.af)
      destination_address_exclude = self.term.GetAddressOfVersion(
          'destination_address_exclude', self.af)
      if destination_address_exclude:
        destination_address = nacaddr.ExcludeAddrs(
            destination_address,
            destination_address_exclude)
    else:
      # destination address not set
      destination_address = ['any']

    # options
    extra_options = []
    for opt in [str(x) for x in self.term.option]:
      if opt.find('tcp-established') == 0 and 6 in protocol:
        extra_options.append('established')
      elif opt.find('established') == 0 and 6 in protocol:
        # only needed for TCP, for other protocols policy.py handles high-ports
        extra_options.append('established')
    self.options.extend(extra_options)

    # ports
    source_port = [()]
    destination_port = [()]
    if self.term.source_port:
      source_port = self.term.source_port
    if self.term.destination_port:
      destination_port = self.term.destination_port

    # logging
    if self.term.logging:
      self.options.append('log')
      if 'disable' in [x.value for x in self.term.logging]:
        self.options.append('disable')

    # icmp-types
    icmp_types = ['']
    if self.term.icmp_type:
      icmp_types = self.NormalizeIcmpTypes(self.term.icmp_type,
                                           self.term.protocol, self.af,
                                           self.term.name)

    for saddr in source_address:
      for daddr in destination_address:
        for sport in source_port:
          for dport in destination_port:
            for proto in protocol:
              for icmp_type in icmp_types:
                # only output address family appropriate IP addresses
                do_output = False
                if self.af == 4:
                  if (((type(saddr) is nacaddr.IPv4) or (saddr == 'any')) and
                      ((type(daddr) is nacaddr.IPv4) or (daddr == 'any'))):
                    do_output = True
                if self.af == 6:
                  if (((type(saddr) is nacaddr.IPv6) or (saddr == 'any')) and
                      ((type(daddr) is nacaddr.IPv6) or (daddr == 'any'))):
                    do_output = True
                if do_output:
                  ret_str.extend(self._TermletToStr(
                      self.filter_name,
                      _ACTION_TABLE.get(str(self.term.action[0])),
                      proto,
                      saddr,
                      sport,
                      daddr,
                      dport,
                      icmp_type,
                      self.options))

    return '\n'.join(ret_str)

  def _TermPortToProtocol (self,portNumber,proto):

    _ASA_PORTS_TCP = {
5190: "aol",
179: "bgp",
19: "chargen",
1494: "citrix-ica",
514: "cmd",
2748: "ctiqbe",
13: "daytime",
9: "discard",
53: "domain",
7: "echo",
512: "exec",
79: "finger",
21: "ftp",
20: "ftp-data",
70: "gopher",
443: "https",
1720: "h323",
101: "hostname",
113: "ident",
143: "imap4",
194: "irc",
750: "kerberos",
543: "klogin",
544: "kshell",
389: "ldap",
636: "ldaps",
515: "lpd",
513: "login",
1352: "lotusnotes",
139: "netbios-ssn",
119: "nntp",
5631: "pcanywhere-data",
496: "pim-auto-rp",
109: "pop2",
110: "pop3",
1723: "pptp",
25: "smtp",
1521: "sqlnet",
22: "ssh",
111: "sunrpc",
49: "tacacs",
517: "talk",
23: "telnet",
540: "uucp",
43: "whois",
80: "www",
2049: "nfs"
    }
    _ASA_PORTS_UDP = {
512: "biff",
68: "bootpc",
67: "bootps",
9: "discard",
53: "domain",
195: "dnsix",
7: "echo",
500: "isakmp",
750: "kerberos",
434: "mobile-ip",
42: "nameserver",
137: "netbios-ns",
138: "netbios-dgm",
123: "ntp",
5632: "pcanywhere-status",
496: "pim-auto-rp",
1645: "radius",
1646: "radius-acct",
520: "rip",
5510: "secureid-udp",
161: "snmp",
162: "snmptrap",
111: "sunrpc",
514: "syslog",
49: "tacacs",
517: "talk",
69: "tftp",
37: "time",
513: "who",
177: "xdmcp",
2049: "nfs"
    }

    if proto == "tcp":
      if portNumber in _ASA_PORTS_TCP:
        return _ASA_PORTS_TCP[portNumber]
    elif proto == "udp":
      if portNumber in _ASA_PORTS_UDP:
        return _ASA_PORTS_UDP[portNumber]
    return portNumber

  def _TermletToStr(self, filter_name, action, proto, saddr, sport, daddr, dport,
                    icmp_type, option):
    """Take the various compenents and turn them into a cisco acl line.

    Args:
      action: str, action
      proto: str, protocl
      saddr: str or ipaddr, source address
      sport: str list or none, the source port
      daddr: str or ipaddr, the destination address
      dport: str list or none, the destination port
      icmp_type: icmp-type numeric specification (if any)
      option: list or none, optional, eg. 'logging' tokens.

    Returns:
      string of the cisco acl line, suitable for printing.
    """


    # inet4
    if type(saddr) is nacaddr.IPv4 or type(saddr) is ipaddr.IPv4Network:
      if saddr.numhosts > 1:
        saddr = '%s %s' % (saddr.ip, saddr.netmask)
      else:
        saddr = 'host %s' % (saddr.ip)
    if type(daddr) is nacaddr.IPv4 or type(daddr) is ipaddr.IPv4Network:
      if daddr.numhosts > 1:
        daddr = '%s %s' % (daddr.ip, daddr.netmask)
      else:
        daddr = 'host %s' % (daddr.ip)
    # inet6
    if type(saddr) is nacaddr.IPv6 or type(saddr) is ipaddr.IPv6Network:
      if saddr.numhosts > 1:
        saddr = '%s/%s' % (saddr.ip, saddr.prefixlen)
      else:
        saddr = 'host %s' % (saddr.ip)
    if type(daddr) is nacaddr.IPv6 or type(daddr) is ipaddr.IPv6Network:
      if daddr.numhosts > 1:
        daddr = '%s/%s' % (daddr.ip, daddr.prefixlen)
      else:
        daddr = 'host %s' % (daddr.ip)

    # fix ports
    if not sport:
      sport = ''
    elif sport[0] != sport[1]:
      sport = ' range %s %s' % (self._TermPortToProtocol(sport[0],proto), self._TermPortToProtocol(sport[1],proto))
    else:
      sport = ' eq %s' % (self._TermPortToProtocol(sport[0],proto))

    if not dport:
      dport = ''
    elif dport[0] != dport[1]:
      dport = ' range %s %s' % (self._TermPortToProtocol(dport[0],proto), self._TermPortToProtocol(dport[1],proto))
    else:
      dport = ' eq %s' % (self._TermPortToProtocol(dport[0],proto))

    if not option:
      option = ['']

    # Prevent UDP from appending 'established' to ACL line
    sane_options = list(option)
    if proto == 'udp' and 'established' in sane_options:
      sane_options.remove('established')

    ret_lines = []

    # str(icmp_type) is needed to ensure 0 maps to '0' instead of FALSE
    icmp_type = str(icmp_type)

    ret_lines.append('access-list %s extended  %s %s %s %s %s %s %s %s' % 
                     (filter_name, action, proto, saddr,
                      sport, daddr, dport,
                      icmp_type,
                      ' '.join(sane_options)
                      ))

    # remove any trailing spaces and replace multiple spaces with singles
    stripped_ret_lines = [re.sub('\s+', ' ', x).rstrip() for x in ret_lines]
    return stripped_ret_lines

#    return 'access-list %s extended %s %s %s%s %s%s %s' % (
#        filter_name, action, proto, saddr, sport, daddr, dport, ' '.join(option))


class CiscoASA(aclgenerator.ACLGenerator):
  """A cisco ASA policy object."""

  _PLATFORM = 'ciscoasa'
  _DEFAULT_PROTOCOL = 'ip'
  _SUFFIX = '.asa'

  def __init__(self, pol):
    for header in pol.headers:
      if self._PLATFORM not in header.platforms:
        raise NoCiscoPolicyError('no ciscoasa policy found in %s' % (
            header.target))

    self.policy = pol

  def __str__(self):
    target_header = []
    target = []
    current_date = datetime.date.today()

    # add the p4 tags
    p4_id = '%s%s' % ('$I', 'd:$')
    p4_date = '%s%s' % ('$Da', 'te:$')
    target_header.append('! %s' % p4_id)
    target_header.append('! %s' % p4_date)

    for header, terms in self.policy.filters:
      filter_options = header.FilterOptions('ciscoasa')
      filter_name = header.FilterName('ciscoasa')

      target.append('clear configure access-list %s' % filter_name)
      # add a header comment if one exists
      for comment in header.comment:
        for line in comment.split('\n'):
          target.append('access-list %s remark %s' % (filter_name,line))

      # now add the terms
      for term in terms:
        if term.expiration and term.expiration <= current_date:
          continue
        target.append(str(Term(term,filter_name)))

      target.append('\n')


    # ensure that the header is always first
    target = target_header + target

    return '\n'.join(target)
