#!/usr/bin/python

"""Cisco ASA renderer.

Unsupported user contributed platform generator/render for Cisco ASA.
"""

__author__ = 'antony@slac.stanford.edu (Antonio Ceseracciu)'

import socket
import logging

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


  def _TermletToStr(self, action, proto, saddr, sport, daddr, dport):

    # fix addreses
    if saddr:
      saddr = 'addrgroup %s' % saddr
    if daddr:
      daddr = 'addrgroup %s' % daddr
    # fix ports
    if sport:
      sport = 'portgroup %d-%d' % (sport[0], sport[1])
    else:
      sport = ''
    if dport:
      dport = 'portgroup %d-%d' % (dport[0], dport[1])
    else:
      dport = ''

    return ' %s %s %s %s %s %s' % (
        action, proto, saddr, sport, daddr, dport)


class Term(aclgenerator.Term):
  """A single ACL Term."""

  def __init__(self, term, filter_name, af=4):
    self.term = term
    self.filter_name = filter_name
    self.options = []
    assert af in (4, 6)
    self.af = af


  def __str__(self):
    ret_str = ['\n']

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
      protocol = map(self.PROTO_MAP.get, self.term.protocol, self.term.protocol)

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

    for saddr in source_address:
      for daddr in destination_address:
        for sport in source_port:
          for dport in destination_port:
            for proto in protocol:
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
                ret_str.append(self._TermletToStr(
                    self.filter_name,
                    _ACTION_TABLE.get(str(self.term.action[0])),
                    proto,
                    saddr,
                    sport,
                    daddr,
                    dport,
                    self.options))

    return '\n'.join(ret_str)

  def _TermletToStr(self, filter_name, action, proto, saddr, sport, daddr, dport, option):
    """Take the various compenents and turn them into a cisco acl line.

    Args:
      action: str, action
      proto: str, protocl
      saddr: str or ipaddr, source address
      sport: str list or none, the source port
      daddr: str or ipaddr, the destination address
      dport: str list or none, the destination port
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
      sport = 'range %d %d' % (sport[0], sport[1])
    else:
      sport = 'eq %d' % (sport[0])

    if not dport:
      dport = ''
    elif dport[0] != dport[1]:
      dport = 'range %d %d' % (dport[0], dport[1])
    else:
      dport = 'eq %d' % (dport[0])

    if not option:
      option = ['']

    return 'access-list %s extended %s %s %s %s %s %s %s' % (
        filter_name, action, proto, saddr, sport, daddr, dport, ' '.join(option))


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
        target.append(str(Term(term,filter_name)))

      target.append('\n')


    # ensure that the header is always first
    target = target_header + target

    return '\n'.join(target)
