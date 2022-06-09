# Copyright 2022 Google Inc. All Rights Reserved.
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

"""Juniper EVO generator.

This is a subclass of Juniper generator. Juniper EVO software (Junos EVO)
uses the same syntax as regular Juniper (Junos) ACLs, with minor differences.
This subclass effects those differences.
"""

from capirca.lib import aclgenerator
from capirca.lib import juniper


class Term(juniper.Term):
  """Single Juniper EVO term representation."""

  _PLATFORM = 'juniperevo'
  _INGRESS = 'ingress'
  _EGRESS = 'egress'
  _INET6 = 'inet6'
  _PROTOCOL = 'protocol'
  _PROTOCOL_EXCEPT = 'protocol-except'
  _NEXT_HEADER = 'next-header'
  _NEXT_HEADER_EXCEPT = 'next-header-except'
  _PAYLOAD_PROTOCOL = 'payload-protocol'
  _PAYLOAD_PROTOCOL_EXCEPT = 'payload-protocol-except'

  def __str__(self):
    self._Ipv6ProtocolMatch()
    term_config = super().__str__()
    # Reset to original syntax.
    self._TERM_TYPE[self._INET6][self._PROTOCOL] = self._NEXT_HEADER
    self._TERM_TYPE[self._INET6][
        self._PROTOCOL_EXCEPT] = self._NEXT_HEADER_EXCEPT
    return term_config

  def _Ipv6ProtocolMatch(self):
    """Use the correct syntax to match protocols after the IPv6 header.

    Refer to juniperevo.md in documentation for matching syntax.

    Returns:
      None

    Raises:
      FilterDirectionError: If a direction is not provided for the filter
        e.g. ingress or egress
    """
    self.extension_headers = ['hop-by-hop', 'fragment']
    # 'hopopt' is renamed to 'hop-by-hop' in juniper base class, add an
    # additional key with the same protocol number to aid renaming.
    self.PROTO_MAP['hop-by-hop'] = 0

    if self.term_type == self._INET6:
      if self.filter_direction != self._INGRESS and self.filter_direction != self._EGRESS:
        raise FilterDirectionError('a direction must be specified for Junos '
                                   'EVO IPv6 filter; this is required to '
                                   'render the correct syntax when matching '
                                   'protocols headers that follow the IPv6 '
                                   'header')

      # Default to rendering filter for physical interfaces.
      if self.interface_type is None:
        self.interface_type = 'physical'

      # Ingress filter.
      if self.filter_direction == self._INGRESS:
        if self.interface_type == 'physical':
          if not any(header in self.term.protocol
                     for header in self.extension_headers):
            self._TERM_TYPE[self._INET6][
                self._PROTOCOL] = self._PAYLOAD_PROTOCOL

          if not any(header in self.term.protocol_except
                     for header in self.extension_headers):
            self._TERM_TYPE[self._INET6][
                self._PROTOCOL_EXCEPT] = self._PAYLOAD_PROTOCOL_EXCEPT

        if self.interface_type == 'loopback':
          self._TERM_TYPE[self._INET6][self._PROTOCOL] = self._PAYLOAD_PROTOCOL
          self._TERM_TYPE[self._INET6][
              self._PROTOCOL_EXCEPT] = self._PAYLOAD_PROTOCOL_EXCEPT

          self.term.protocol = aclgenerator.ProtocolNameToNumber(
              self.term.protocol, self.extension_headers, self.PROTO_MAP)

          self.term.protocol_except = aclgenerator.ProtocolNameToNumber(
              self.term.protocol_except, self.extension_headers, self.PROTO_MAP)

      # Egress filter.
      if self.filter_direction == self._EGRESS:
        self._TERM_TYPE[self._INET6][self._PROTOCOL] = self._PAYLOAD_PROTOCOL
        self._TERM_TYPE[self._INET6][
            self._PROTOCOL_EXCEPT] = self._PAYLOAD_PROTOCOL_EXCEPT

        self.term.protocol = aclgenerator.ProtocolNameToNumber(
            self.term.protocol, self.extension_headers, self.PROTO_MAP)

        self.term.protocol_except = aclgenerator.ProtocolNameToNumber(
            self.term.protocol_except, self.extension_headers, self.PROTO_MAP)


class JuniperEvo(juniper.Juniper):
  """Juniper EVO generator."""

  _PLATFORM = 'juniperevo'
  SUFFIX = '.evojcl'
  _TERM = Term


class Error(Exception):
  pass


class FilterDirectionError(Error):
  pass
