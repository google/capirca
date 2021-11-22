# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Juniper MS-MPC  generator for capirca."""

import datetime
import logging

from capirca.lib import aclgenerator
from capirca.lib import juniper
from capirca.lib import nacaddr
import six

MAX_IDENTIFIER_LEN = 55  # It is really 63, but leaving room for added chars


class Term(juniper.Term):
  """Representation of an individual Juniper MS-MPC term.

     The __str__ method must be implemented.

     Args: term policy.Term object

  """
  _PLATFORM = 'msmpc'
  _DEFAULT_INDENT = 20
  _ACTIONS = {'accept': 'accept', 'deny': 'discard', 'reject': 'reject'}
  # msmpc supports a limited number of protocol names
  # https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/ref/statement/applications-edit-protocol.html
  _SUPPORTED_PROTOCOL_NAMES = (
      'ah',
      'egp',
      'esp',
      'gre',
      'icmp',
      'icmpv6',
      'igmp',
      'ipip',
      #'node', A pseudo-protocol which may require additional handling
      'ospf',
      'pim',
      'rsvp',
      'sctp',
      'tcp',
      'udp')

  def __init__(self, term, term_type, noverbose, filter_name):
    enable_dsmo = False
    super().__init__(term, term_type, enable_dsmo, noverbose)
    self.term = term
    self.term_type = term_type
    self.noverbose = noverbose
    self.filter_name = filter_name

    for prot in self.term.protocol:
      if prot not in self._SUPPORTED_PROTOCOL_NAMES:
        loc = self.term.protocol.index(prot)
        self.term.protocol[loc] = str(self.PROTO_MAP.get(prot, prot))

  def __str__(self):
    # Verify platform specific terms. Skip whole term if platform does not
    # match.
    if self.term.platform:
      if self._PLATFORM not in self.term.platform:
        return ''
    if self.term.platform_exclude:
      if self._PLATFORM in self.term.platform_exclude:
        return ''

    if self.enable_dsmo:
      raise NotImplementedError('enable_dsmo not implemented for msmpc')

    ret_str = juniper.Config(indent=self._DEFAULT_INDENT)

    # COMMENTS
    # this deals just fine with multi line comments, but we could probably
    # output them a little cleaner; do things like make sure the
    # len(output) < 80, etc. Note, if 'noverbose' is set for the filter, skip
    # all comment processing.
    if not self.noverbose:
      if self.term.owner:
        self.term.comment.append('Owner: %s' % self.term.owner)
      if self.term.comment:
        ret_str.Append('/*')
        for comment in self.term.comment:
          for line in comment.split('\n'):
            ret_str.Append('** ' + line)
        ret_str.Append('*/')

    # Term verbatim output - this will skip over normal term creation
    # code.  Warning generated from policy.py if appropriate.
    if self.term.verbatim:
      for next_term in self.term.verbatim:
        if next_term[0] == self._PLATFORM:
          ret_str.Append(str(next_term[1]), verbatim=True)
      return str(ret_str)

    # Determine whether there are any match conditions for the term.
    has_match_criteria = (
        self.term.address or self.term.dscp_except or self.term.dscp_match or
        self.term.destination_address or self.term.destination_port or
        self.term.destination_prefix or self.term.destination_prefix_except or
        self.term.encapsulate or self.term.ether_type or
        self.term.flexible_match_range or self.term.forwarding_class or
        self.term.forwarding_class_except or self.term.fragment_offset or
        self.term.hop_limit or self.term.next_ip or self.term.port or
        self.term.precedence or self.term.protocol or
        self.term.protocol_except or self.term.source_address or
        self.term.source_port or self.term.source_prefix or
        self.term.source_prefix_except or self.term.traffic_type or
        self.term.ttl)

    suffixes = []
    duplicate_term = False
    has_icmp = 'icmp' in self.term.protocol
    has_icmpv6 = 'icmpv6' in self.term.protocol
    has_v4_ip = self.term.GetAddressOfVersion(
        'source_address',
        self.AF_MAP.get('inet')) or self.term.GetAddressOfVersion(
            'source_address_exclude',
            self.AF_MAP.get('inet')) or self.term.GetAddressOfVersion(
                'destination_address',
                self.AF_MAP.get('inet')) or self.term.GetAddressOfVersion(
                    'destination_address_exclude', self.AF_MAP.get('inet'))
    has_v6_ip = self.term.GetAddressOfVersion(
        'source_address',
        self.AF_MAP.get('inet6')) or self.term.GetAddressOfVersion(
            'source_address_exclude',
            self.AF_MAP.get('inet6')) or self.term.GetAddressOfVersion(
                'destination_address',
                self.AF_MAP.get('inet6')) or self.term.GetAddressOfVersion(
                    'destination_address_exclude', self.AF_MAP.get('inet6'))

    if self.term_type == 'mixed':
      if not (has_v4_ip or has_v6_ip):
        suffixes = ['inet']
      elif not has_v6_ip:
        suffixes = ['inet']
      elif not has_v4_ip:
        suffixes = ['inet6']
      else:
        suffixes = ['inet', 'inet6']
        duplicate_term = True
    if not suffixes and self.term_type in ['inet', 'inet6']:
      suffixes = [self.term_type]

    for suffix in suffixes:
      if self.term_type == 'mixed' and (not (has_icmp and has_icmpv6)) and (
          has_v4_ip and has_v6_ip):
        if (has_icmp and suffix != 'inet') or (has_icmpv6 and
                                               suffix != 'inet6'):
          continue
      source_address = self.term.GetAddressOfVersion('source_address',
                                                     self.AF_MAP.get(suffix))
      source_address_exclude = self.term.GetAddressOfVersion(
          'source_address_exclude', self.AF_MAP.get(suffix))
      source_address, source_address_exclude = self._MinimizePrefixes(
          source_address, source_address_exclude)
      destination_address = self.term.GetAddressOfVersion(
          'destination_address', self.AF_MAP.get(suffix))
      destination_address_exclude = self.term.GetAddressOfVersion(
          'destination_address_exclude', self.AF_MAP.get(suffix))
      destination_address, destination_address_exclude = self._MinimizePrefixes(
          destination_address, destination_address_exclude)
      if ((not source_address) and self.term.GetAddressOfVersion(
          'source_address', self.AF_MAP.get('mixed')) and
          not source_address_exclude) or (
              (not destination_address) and self.term.GetAddressOfVersion(
                  'destination_address', self.AF_MAP.get('mixed')) and
              not destination_address_exclude):
        continue
      if ((has_icmpv6 and not has_icmp and suffix == 'inet') or
          (has_icmp and not has_icmpv6 and
           suffix == 'inet6')) and self.term_type != 'mixed':
        logging.debug(
            self.NO_AF_LOG_PROTO.substitute(
                term=self.term.name,
                proto=', '.join(self.term.protocol),
                af=suffix))
        return ''

      # NAME
      # if the term is inactive we have to set the prefix
      if self.term.inactive:
        term_prefix = 'inactive:'
      else:
        term_prefix = ''

      ret_str.Append(
          '%s term %s%s {' %
          (term_prefix, self.term.name, '-' + suffix if duplicate_term else ''))

      # We only need a "from {" clause if there are any conditions to match.
      if has_match_criteria:
        ret_str.Append('from {')
        # SOURCE ADDRESS
        if source_address or source_address_exclude:
          ret_str.Append('source-address {')
          if source_address:
            for saddr in source_address:
              for comment in self._Comment(saddr):
                ret_str.Append('%s' % comment)
              if saddr.version == 6 and 0 < saddr.prefixlen < 16:
                for saddr2 in saddr.subnets(new_prefix=16):
                  ret_str.Append('%s;' % saddr2)
              else:
                if saddr == nacaddr.IPv6('0::0/0'):
                  saddr = 'any-ipv6'
                elif saddr == nacaddr.IPv4('0.0.0.0/0'):
                  saddr = 'any-ipv4'
                ret_str.Append('%s;' % saddr)

          # SOURCE ADDRESS EXCLUDE
          if source_address_exclude:
            for ex in source_address_exclude:
              for comment in self._Comment(ex):
                ret_str.Append('%s' % comment)
              if ex.version == 6 and 0 < ex.prefixlen < 16:
                for ex2 in ex.subnets(new_prefix=16):
                  ret_str.Append('%s except;' % ex2)
              else:
                if ex == nacaddr.IPv6('0::0/0'):
                  ex = 'any-ipv6'
                elif ex == nacaddr.IPv4('0.0.0.0/0'):
                  ex = 'any-ipv4'
                ret_str.Append('%s except;' % ex)
          ret_str.Append('}')  # source-address {...}

        # DESTINATION ADDRESS
        if destination_address or destination_address_exclude:
          ret_str.Append('destination-address {')
          if destination_address:
            for daddr in destination_address:
              for comment in self._Comment(daddr):
                ret_str.Append('%s' % comment)
              if daddr.version == 6 and 0 < daddr.prefixlen < 16:
                for daddr2 in daddr.subnets(new_prefix=16):
                  ret_str.Append('%s;' % daddr2)
              else:
                if daddr == nacaddr.IPv6('0::0/0'):
                  daddr = 'any-ipv6'
                elif daddr == nacaddr.IPv4('0.0.0.0/0'):
                  daddr = 'any-ipv4'
                ret_str.Append('%s;' % daddr)

          # DESTINATION ADDRESS EXCLUDE
          if destination_address_exclude:
            for ex in destination_address_exclude:
              for comment in self._Comment(ex):
                ret_str.Append('%s' % comment)
              if ex.version == 6 and 0 < ex.prefixlen < 16:
                for ex2 in ex.subnets(new_prefix=16):
                  ret_str.Append('%s except;' % ex2)
              else:
                if ex == nacaddr.IPv6('0::0/0'):
                  ex = 'any-ipv6'
                elif ex == nacaddr.IPv4('0.0.0.0/0'):
                  ex = 'any-ipv4'
                ret_str.Append('%s except;' % ex)
          ret_str.Append('}')  # destination-address {...}

        # source prefix <except> list
        if self.term.source_prefix or self.term.source_prefix_except:
          for pfx in self.term.source_prefix:
            ret_str.Append('source-prefix-list ' + pfx + ';')
          for epfx in self.term.source_prefix_except:
            ret_str.Append('source-prefix-list ' + epfx + ' except;')

        # destination prefix <except> list
        if self.term.destination_prefix or self.term.destination_prefix_except:
          for pfx in self.term.destination_prefix:
            ret_str.Append('destination-prefix-list ' + pfx + ';')
          for epfx in self.term.destination_prefix_except:
            ret_str.Append('destination-prefix-list ' + epfx + ' except;')

        # APPLICATION
        if (self.term.source_port or self.term.destination_port or
            self.term.icmp_type or self.term.protocol):
          if hasattr(self.term, 'replacement_application_name'):
            ret_str.Append('application-sets ' +
                           self.term.replacement_application_name + '-app;')
          else:
            ret_str.Append('application-sets ' +
                           self.filter_name[:((MAX_IDENTIFIER_LEN) // 2)] +
                           self.term.name[-((MAX_IDENTIFIER_LEN) // 2):] +
                           '-app;')
        ret_str.Append('}')  # from {...}

      ret_str.Append('then {')
      # ACTION
      for action in self.term.action:
        ret_str.Append(self._ACTIONS.get(str(action)) + ';')
      if self.term.logging and 'disable' not in [
          x.value for x in self.term.logging
      ]:
        ret_str.Append('syslog;')
      ret_str.Append('}')  # then {...}
      ret_str.Append('}')  # term {...}
    return str(ret_str)


class JuniperMSMPC(aclgenerator.ACLGenerator):
  """Juniper MSMPC rendering class.

     This class takes a policy object and renders output into
     a syntax which is understood ny Juniper routers with MS-MPC cards.

     Args:
       pol: policy.Policy object
  """
  _PLATFORM = 'msmpc'
  SUFFIX = '.msmpc'
  _SUPPORTED_AF = frozenset(('inet', 'inet6', 'mixed'))
  _AF_MAP = {'inet': 4, 'inet6': 6, 'mixed': None}
  _AF_ICMP_MAP = {'icmp': 'inet', 'icmpv6': 'inet6'}
  _SUPPORTED_DIRECTION = {
      '': 'input-output',
      'ingress': 'input',
      'egress': 'output',
  }

  _OPTIONAL_SUPPORTED_KEYWORDS = frozenset([
      'expiration',
  ])

  def __init__(self, pol, exp_info):
    self.applications = {}
    super().__init__(pol, exp_info)

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    supported_tokens, supported_sub_tokens = super()._BuildTokens()

    supported_tokens |= {
        'destination_prefix', 'destination_prefix_except', 'icmp_code',
        'logging', 'owner', 'source_prefix', 'source_prefix_except'
    }
    supported_sub_tokens.update({
        'option': {
            'established',
            # TODO(sneakywombat): add all options to lex.
            '.*',  # make ArbitraryOptions work, yolo.
            'tcp-established',
            'inactive'
        }
    })
    return supported_tokens, supported_sub_tokens

  def _BuildPort(self, ports):
    """Transform specified ports into list and ranges.

    Args:
      ports: a policy terms list of ports

    Returns:
      port_list: list of ports and port ranges
    """
    port_list = []
    for p in ports:
      if p[0] == p[1]:
        port_list.append(str(p[0]))
      else:
        port_list.append('%s-%s' % (str(p[0]), str(p[1])))
    return port_list

  def _GenerateApplications(self, filter_name):
    target = []
    apps_set_list = []
    target.append('applications {')
    done_apps = []
    for app in sorted(self.applications[filter_name], key=lambda x: x['name']):
      app_list = []
      if app in done_apps:
        continue

      if app['protocol'] or app['sport'] or app['dport'] or app['icmp-type']:
        # generate ICMP statements
        if app['icmp-type']:
          if app['timeout']:
            timeout = app['timeout']
          else:
            timeout = 60
          num_terms = len(app['protocol']) * len(app['icmp-type'])
          apps_set_list.append('application-set ' + app['name'] + '-app {')
          for i in range(num_terms):
            apps_set_list.append('application ' + app['name'] + '-app%d' %
                                 (i + 1) + ';')
          apps_set_list.append('}')  # application-set {...}

          term_counter = 0
          for i, code in enumerate(app['icmp-type']):
            for proto in app['protocol']:
              target.append('application ' + app['name'] + '-app%d' %
                            (term_counter + 1) + ' {')
              if proto == 'icmp':
                target.append('application-protocol %s;' % proto)
              target.append('protocol %s;' % proto)
              target.append('%s-type %s;' % (proto, str(code)))
              if app['icmp-code']:
                target.append('%s-code %s;' %
                              (proto, self._Group(app['icmp-code'])))
              if int(timeout):
                target.append('inactivity-timeout %s;' % int(timeout))
              target.append('}')  # application {...}
              term_counter += 1
        # generate non-ICMP statements
        else:
          i = 1
          apps_set_list.append('application-set ' + app['name'] + '-app {')

          for proto in app['protocol'] or ['']:
            for sport in app['sport'] or ['']:
              for dport in app['dport'] or ['']:
                chunks = []
                if proto:
                  chunks.append('protocol %s;' % proto)
                if sport and ('udp' in proto or 'tcp' in proto):
                  chunks.append('source-port %s;' % sport)
                if dport and ('udp' in proto or 'tcp' in proto):
                  chunks.append('destination-port %s;' % dport)
                if app['timeout']:
                  chunks.append(' inactivity-timeout %d;' % int(app['timeout']))
                if chunks:
                  apps_set_list.append('application ' + app['name'] +
                                       '-app%d;' % i)
                  app_list.append('application ' + app['name'] + '-app%d {' % i)
                  for chunk in chunks:
                    app_list.append(chunk)
                  app_list.append('}')
                  i += 1
          apps_set_list.append('}')

        done_apps.append(app)
        if app_list:
          for item in app_list:
            target.append(item)

    for item in apps_set_list:
      target.append(item)
    target.append('}')
    # Return the output only if there is content inside of
    # the "applications {\n}" lines, otherwise return nothing.
    if len(target) > 2:
      return target
    else:
      return []

  def _TranslatePolicy(self, pol, exp_info):
    current_date = datetime.date.today()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)
    self.junipermsmpc_policies = []
    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue
      filter_options = header.FilterOptions(self._PLATFORM)
      filter_name = header.FilterName(self._PLATFORM)
      filter_options.remove(filter_name)
      filter_direction = None
      filter_type = None
      noverbose = 'noverbose' in filter_options
      self.applications[filter_name] = []

      if noverbose:
        # noverbose is a strict boolean, remove it
        # prior to iterating through the other options
        # that require additional processing.
        filter_options.remove('noverbose')

      for filter_opt in filter_options:
        # validate address families
        if filter_opt in self._SUPPORTED_AF:
          if not filter_type:
            filter_type = filter_opt
            continue
          else:
            raise ConflictingTargetOptionsError(
                'only one address family can be '
                'specified per header "%s"' % ' '.join(filter_options))
        # validate direction
        if filter_opt in self._SUPPORTED_DIRECTION.keys():
          if not filter_direction:
            filter_direction = self._SUPPORTED_DIRECTION.get(filter_opt)
            continue
          else:
            raise ConflictingTargetOptionsError('only one direction can be '
                                                'specified per header "%s"' %
                                                ' '.join(filter_options))
        raise UnsupportedHeaderError(
            'MSMPC Generator currently does not support '
            '%s as a header option "%s"' %
            (filter_opt, ' '.join(filter_options)))

      if not filter_direction:
        filter_direction = self._SUPPORTED_DIRECTION.get('')
      if not filter_type:
        filter_type = 'mixed'

      term_names = set()
      new_terms = []
      for term in terms:
        # Application sets need to be unique system-wide, so we construct
        # a name from a combination of the filter and term names, shortening
        # to the roughly half of the max identifier length for each part.
        # When shortening, we take the start of the filter name and the end of
        # the term name in a hope that we omit the most common bits
        # like -inbound and accept-.
        modified_term_name = filter_name[:(
            (MAX_IDENTIFIER_LEN) // 2)] + term.name[-(
                (MAX_IDENTIFIER_LEN) // 2):]
        if term.stateless_reply:
          logging.warning(
              'WARNING: Term %s is a stateless reply term and will not be '
              'rendered.', term.name)
          continue
        if set(['established', 'tcp-established']).intersection(term.option):
          logging.debug(
              'Skipping established term %s because MSMPC is stateful.',
              term.name)
          continue
        # if inactive is set, deactivate the term and remove the option.
        if 'inactive' in term.option:
          term.inactive = True
          term.option.remove('inactive')
        if term.name in term_names:
          raise JuniperMSMPCFilterError('Duplicate term name')
        term_names.add(term.name)
        if term.expiration:
          if term.expiration <= exp_info_date:
            logging.info(
                'INFO: Term %s in policy %s expires '
                'in less than two weeks.', term.name, filter_name)
          if term.expiration <= current_date:
            logging.warning(
                'WARNING: Term %s in policy %s is expired and '
                'will not be rendered.', term.name, filter_name)
            continue
        new_term = Term(term, filter_type, noverbose, filter_name)
        new_terms.append(new_term)

        # Because MSMPC terms can contain inet and inet6 addresses. We have to
        # have ability to recover proper AF for ICMP type we need.
        # If protocol is empty or we cannot map to inet or inet6 we insert bogus
        # af_type name which will cause new_term.NormalizeIcmpTypes to fail.
        if not term.protocol:
          icmp_af_type = 'unknown_af_icmp'
        else:
          icmp_af_type = self._AF_ICMP_MAP.get(term.protocol[0],
                                               'unknown_af_icmp')
        tmp_icmptype = new_term.NormalizeIcmpTypes(term.icmp_type,
                                                   term.protocol, icmp_af_type)
        # NormalizeIcmpTypes returns [''] for empty, convert to [] for eval
        normalized_icmptype = tmp_icmptype if tmp_icmptype != [''] else []
        # rewrites the protocol icmpv6 to icmp6
        if 'icmpv6' in term.protocol:
          protocol = list(term.protocol)
          protocol[protocol.index('icmpv6')] = 'icmp6'
        else:
          protocol = term.protocol
        # MSMPC requires tcp and udp to specify ports, rather than imply all
        # ports
        if 'udp' in term.protocol or 'tcp' in term.protocol:
          if not term.source_port and not term.destination_port:
            term.destination_port = [[1, 65535]]
        new_application_set = {
            'sport': self._BuildPort(term.source_port),
            'dport': self._BuildPort(term.destination_port),
            'protocol': protocol,
            'icmp-type': normalized_icmptype,
            'icmp-code': term.icmp_code,
            'timeout': term.timeout
        }

        for application_set in self.applications[filter_name]:
          if all(
              item in list(application_set.items())
              for item in new_application_set.items()):
            new_application_set = ''
            term.replacement_application_name = application_set['name']
            break
          if (modified_term_name == application_set['name'] and
              new_application_set != application_set):
            raise ConflictingApplicationSetsError(
                'Application set %s has a conflicting entry' %
                modified_term_name)

        if new_application_set:
          new_application_set['name'] = modified_term_name
          self.applications[filter_name].append(new_application_set)

      self.junipermsmpc_policies.append(
          (header, filter_name, filter_direction, new_terms))

  def _Group(self, group, lc=True):
    """If 1 item return it, else return [ item1 item2 ].

    Args:
      group: a list.  could be a list of strings (protocols) or a list of tuples
        (ports)
      lc: return a lower cased result for text.  Default is True.

    Returns:
      rval: a string surrounded by '[' and '];' if len(group) > 1
            or with just ';' appended if len(group) == 1
    """

    def _FormattedGroup(el, lc=True):
      """Return the actual formatting of an individual element.

      Args:
        el: either a string (protocol) or a tuple (ports)
        lc: return lower cased result for text.  Default is True.

      Returns:
        string: either the lower()'ed string or the ports, hyphenated
                if they're a range, or by itself if it's not.
      """
      if isinstance(el, str):
        if not lc:
          return el
        else:
          return el.lower()
      elif isinstance(el, int):
        return str(el)
      # type is a tuple below here
      elif el[0] == el[1]:
        return '%d' % el[0]
      else:
        return '%d-%d' % (el[0], el[1])

    if len(group) > 1:
      rval = '[ ' + ' '.join([_FormattedGroup(x, lc=lc) for x in group]) + ' ];'
    else:
      rval = _FormattedGroup(group[0], lc=lc) + ';'
    return rval

  def __str__(self):
    target = juniper.Config()
    for (header, filter_name, filter_direction,
         terms) in self.junipermsmpc_policies:
      target.Append('groups {')
      target.Append('replace:')
      target.Append('/*')

      # we want the acl to contain id and date tags, but p4 will expand
      # the tags here when we submit the generator, so we have to trick
      # p4 into not knowing these words.  like taking c-a-n-d-y from a
      # baby.
      for line in aclgenerator.AddRepositoryTags('** '):
        target.Append(line)
      target.Append('**')

      for comment in header.comment:
        for line in comment.split('\n'):
          target.Append('** ' + line)
      target.Append('*/')

      target.Append('%s {' % filter_name)
      target.Append('services {')
      target.Append('stateful-firewall {')
      target.Append('rule %s {' % filter_name)
      target.Append('match-direction %s;' % filter_direction)
      for term in terms:
        term_str = str(term)
        if term_str:
          target.Append(term_str, verbatim=True)
      target.Append('}')  # rule { ... }
      target.Append('}')  # stateful-firewall { ... }
      target.Append('}')  # services { ... }
      for line in self._GenerateApplications(filter_name):
        target.Append(line)
      target.Append('}')  # filter_name { ... }
      target.Append('}')  # groups { ... }
      target.Append('apply-groups %s;' % filter_name)
    return str(target) + '\n'


class Error(Exception):
  pass


class JuniperMSMPCFilterError(Error):
  pass


class ConflictingApplicationSetsError(Error):
  pass


class ConflictingTargetOptionsError(Error):
  pass


class UnsupportedHeaderError(Error):
  pass
