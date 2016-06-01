# Copyright 2015 The Capirca Project Authors All Rights Reserved.
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
"""Nsxv Mock Test terms for nsxv.py"""


INET_TERM="""\
  term permit-mail-services {
    destination-address:: MAIL_SERVERS
    protocol:: tcp
    destination-port:: MAIL_SERVICES
    action:: accept
  }
  """

INET6_TERM="""\
  term test-icmpv6 {
    protocol:: icmpv6
    icmp-type:: echo-request echo-reply
    action:: accept
  }
  """

INET_FILTER= """\
  header {
    comment:: "Sample inet NSXV filter"
    target:: nsxv inet
  }

  term allow-ntp-request {
    comment::"Allow ntp request"
    source-address:: NTP_SERVERS
    source-port:: NTP
    destination-address:: INTERNAL
    destination-port:: NTP
    protocol:: udp
    action:: accept
  }
  """

INET6_FILTER= """\
  header {
    comment:: "Sample inet6 NSXV filter"
    target:: nsxv inet6
  }

  term test-icmpv6 {
    #destination-address:: WEB_SERVERS
    protocol:: icmpv6
    icmp-type:: echo-request echo-reply
    action:: accept
  }
  """

MIXED_FILTER= """\
  header {
    comment:: "Sample mixed NSXV filter"
    target:: nsxv mixed 1009
  }

  term accept-to-honestdns {
    comment:: "Allow name resolution using honestdns."
    destination-address:: GOOGLE_DNS
    destination-port:: DNS
    protocol:: udp
    action:: accept
  }
  """

POLICY= """\
  header {
    comment:: "Sample NSXV filter"
    target:: nsxv inet 1007
  }

  term reject-imap-requests {
    destination-address:: MAIL_SERVERS
    destination-port:: IMAP
    protocol:: tcp
    action:: reject-with-tcp-rst
  }
  """

POLICY_NO_SECTION_ID= """\
  header {
    comment:: "NSXV filter without section id"
    target:: nsxv inet
  }
  term accept-icmp {
    protocol:: icmp
    action:: accept
  }
  """

POLICY_NO_FILTERTYPE= """\
  header {
    comment:: "Sample NSXV filter"
    target:: nsxv
  }
  term accept-icmp {
    protocol:: icmp
    action:: accept
  }
  """

POLICY_INCORRECT_FILTERTYPE= """\
  header {
    comment:: "Sample NSXV filter"
    target:: nsxv inet1
  }
  term accept-icmp {
    protocol:: icmp
    action:: accept
  }
  """

POLICY_OPTION_KYWD= """\
  header {
    comment:: "Sample NSXV filter"
    target:: nsxv inet 1009
  }
  term accept-bgp-replies {
    comment:: "Allow inbound replies to BGP requests."
    source-port:: BGP
    protocol:: tcp
    option:: tcp-established
    action:: accept
  }
  """
